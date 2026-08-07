from __future__ import annotations

from validate_docs import main, validate_document


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
