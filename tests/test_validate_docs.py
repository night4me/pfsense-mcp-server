from __future__ import annotations

from validate_docs import _heading_slugs, main, validate_document


def test_repository_documentation_is_consistent():
    assert main() == 0


def test_missing_local_link_is_rejected(tmp_path):
    document = tmp_path / "document.md"
    document.write_text("[missing](not-here.md)\n", encoding="utf-8")

    assert validate_document(document) == ["document.md: missing local link target 'not-here.md'"]


def test_invalid_machine_readable_fence_is_rejected(tmp_path):
    document = tmp_path / "document.md"
    document.write_text('```json\n{"invalid": }\n```\n', encoding="utf-8")

    errors = validate_document(document)

    assert len(errors) == 1
    assert "invalid json fence 1" in errors[0]


def test_missing_cross_file_anchor_is_rejected(tmp_path):
    (tmp_path / "other.md").write_text("# Real Heading\n", encoding="utf-8")
    document = tmp_path / "document.md"
    document.write_text("[link](other.md#does-not-exist)\n", encoding="utf-8")

    assert validate_document(document) == ["document.md: missing anchor 'does-not-exist' in other.md"]


def test_valid_cross_file_anchor_is_accepted(tmp_path):
    (tmp_path / "other.md").write_text("# Real Heading\n", encoding="utf-8")
    document = tmp_path / "document.md"
    document.write_text("[link](other.md#real-heading)\n", encoding="utf-8")

    assert validate_document(document) == []


def test_same_document_anchor_is_validated(tmp_path):
    document = tmp_path / "document.md"
    document.write_text("# Title\n\n[jump](#does-not-exist)\n\n## A Real Section\n", encoding="utf-8")

    assert validate_document(document) == ["document.md: missing anchor 'does-not-exist' in document.md"]

    document.write_text("# Title\n\n[jump](#a-real-section)\n\n## A Real Section\n", encoding="utf-8")

    assert validate_document(document) == []


def test_anchor_inside_fenced_code_block_is_not_treated_as_heading(tmp_path):
    document = tmp_path / "document.md"
    document.write_text(
        "# Title\n\n```python\n# Not a heading\n```\n\n[jump](#not-a-heading)\n",
        encoding="utf-8",
    )

    assert validate_document(document) == ["document.md: missing anchor 'not-a-heading' in document.md"]


def test_duplicate_headings_get_a_numeric_suffix_like_github():
    slugs = _heading_slugs("## Overview\n\n## Overview\n\n## Overview\n")

    assert slugs == {"overview", "overview-1", "overview-2"}


def test_heading_slug_strips_inline_code_and_punctuation_like_github():
    slugs = _heading_slugs("## Configuration (missing/invalid values fail closed)\n\n### `pfsense_get_system_status`\n")

    assert slugs == {"configuration-missinginvalid-values-fail-closed", "pfsense_get_system_status"}
