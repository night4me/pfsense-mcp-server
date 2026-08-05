"""Unit tests for scripts/tools_write_check.py, using a synthetic
temporary directory rather than the real repository tree."""

from __future__ import annotations

from tools_write_check import find_forbidden_imports


def test_passes_when_absent(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "registry.py").write_text("from .read import gateways\n")

    assert find_forbidden_imports(tmp_path) == []


def test_flags_from_import_of_tools_write(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "registry.py").write_text("from pfsense_mcp.tools.write import something\n")

    findings = find_forbidden_imports(tmp_path)

    assert len(findings) == 1
    assert "registry.py" in findings[0]


def test_flags_relative_write_import(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "registry.py").write_text("from .write import something\n")

    findings = find_forbidden_imports(tmp_path)

    assert len(findings) == 1


def test_flags_plain_import_statement(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "registry.py").write_text("import pfsense_mcp.tools.write\n")

    findings = find_forbidden_imports(tmp_path)

    assert len(findings) == 1


def test_does_not_flag_the_reserved_packages_own_init_file(tmp_path):
    write_dir = tmp_path / "src" / "pfsense_mcp" / "tools" / "write"
    write_dir.mkdir(parents=True)
    (write_dir / "__init__.py").write_text(
        '"""Reserved for future mutating tools. Must never be imported until tools.write is authorized."""\n'
    )

    assert find_forbidden_imports(tmp_path) == []
