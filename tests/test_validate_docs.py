from __future__ import annotations

from validate_docs import _heading_slugs, main, readme_portability_errors, validate_document


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


def test_readme_repo_relative_link_is_rejected(tmp_path):
    """README.md is also rendered as the PyPI long_description, outside any
    repository checkout -- a repo-relative link that resolves fine on
    GitHub silently 404s there (see docs/adr for the ADR-026 case this
    caught). Only absolute URLs and same-document anchors are portable."""

    readme = tmp_path / "README.md"
    readme.write_text("[bad](docs/API.md)\n[also bad](LICENSE)\n", encoding="utf-8")

    errors = readme_portability_errors(readme)

    assert len(errors) == 2
    assert "docs/API.md" in errors[0]
    assert "LICENSE" in errors[1]


def test_readme_absolute_url_and_anchor_links_are_accepted(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(
        "[ok](https://example.com/page)\n[ok anchor](#some-section)\n[ok mail](mailto:security@example.com)\n",
        encoding="utf-8",
    )

    assert readme_portability_errors(readme) == []
