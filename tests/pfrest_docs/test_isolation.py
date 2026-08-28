"""pfREST_LIVE_GUIDANCE_ARC Required tests: the pfrest_docs package
must have zero import path to any existing safety-authority code path,
and must be imported by exactly one reviewed production module -- same
AST-scan discipline as `tests/guidance/test_isolation.py` and
`tests/tier1/test_isolation.py` apply to their own subsystems.

Unlike `pfsense_mcp.guidance`, this package IS allowed to import
network modules (that is its entire purpose) -- so instead of "no
network module", this package is checked for "network I/O confined to
exactly one module" (`fetch.py`), and for NOT depending on
`pfsense_mcp.guidance` at all (the two subsystems stay decoupled; see
`composition.py`'s own module docstring).
"""

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
PFREST_DOCS_PACKAGE = ROOT / "src/pfsense_mcp/pfrest_docs"

#: The one deliberate, reviewed exception (owner-authorized 2026-08-28,
#: pfREST_LIVE_GUIDANCE_ARC). A change to this constant is itself the
#: kind of thing that must be a reviewed diff -- see api_guidance.py's
#: own module docstring for the full rationale.
ALLOWED_PFREST_DOCS_IMPORTER = "src/pfsense_mcp/tools/read/api_guidance.py"

#: Mirrors tests/guidance/test_isolation.py's FORBIDDEN_IMPORT_ROOTS:
#: nothing capable of selecting a capability/endpoint/method or reaching
#: mutation may be imported by this package. `pfsense_mcp.pfsense_client`
#: is deliberately NOT forbidden -- `appliance_schema.py` legitimately
#: reuses it for LIVE_APPLIANCE_SCHEMA evidence, the same READ-only,
#: already-authenticated client every one of the 95 READ tools uses
#: (mirrors `pfsense_mcp.guidance.appliance_identity`'s own precedent).
FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.write_types",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.tools",
}

#: The one module in this package allowed to import a network library.
_ALLOWED_NETWORK_MODULE_IMPORTER = "src/pfsense_mcp/pfrest_docs/fetch.py"
_NETWORK_MODULES = {"socket", "requests", "httpx", "urllib.request"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_pfrest_docs_package_has_no_safety_authority_import():
    offenders: list[str] = []
    for path in PFREST_DOCS_PACKAGE.glob("*.py"):
        imported = _imported_modules(_tree(path))
        for module in imported:
            if any(module == root or module.startswith(f"{root}.") for root in FORBIDDEN_IMPORT_ROOTS):
                offenders.append(f"{path.relative_to(ROOT).as_posix()} imports {module}")
    assert offenders == []


def test_pfrest_docs_package_does_not_import_guidance_package():
    """This package stays fully decoupled from pfsense_mcp.guidance --
    the one reviewed module allowed to import both is the tool file
    itself, never this package (see composition.py's module docstring)."""
    offenders: list[str] = []
    for path in PFREST_DOCS_PACKAGE.glob("*.py"):
        imported = _imported_modules(_tree(path))
        if any(module == "pfsense_mcp.guidance" or module.startswith("pfsense_mcp.guidance.") for module in imported):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_pfrest_docs_package_is_imported_by_exactly_one_reviewed_production_module():
    production = ROOT / "src/pfsense_mcp"
    offenders: list[str] = []
    for path in production.rglob("*.py"):
        if "pfrest_docs" in path.relative_to(production).parts:
            continue
        imported = _imported_modules(_tree(path))
        if any(
            module == "pfsense_mcp.pfrest_docs" or module.startswith("pfsense_mcp.pfrest_docs.") for module in imported
        ):
            relative = path.relative_to(ROOT).as_posix()
            if relative != ALLOWED_PFREST_DOCS_IMPORTER:
                offenders.append(relative)
    assert offenders == []


def test_api_guidance_module_actually_imports_pfrest_docs():
    path = ROOT / ALLOWED_PFREST_DOCS_IMPORTER
    assert path.is_file(), f"{ALLOWED_PFREST_DOCS_IMPORTER} no longer exists -- remove the exception"
    imported = _imported_modules(_tree(path))
    assert any(
        module == "pfsense_mcp.pfrest_docs" or module.startswith("pfsense_mcp.pfrest_docs.") for module in imported
    )


def test_network_io_is_confined_to_the_fetch_module():
    offenders: list[str] = []
    for path in PFREST_DOCS_PACKAGE.glob("*.py"):
        relative = path.relative_to(ROOT).as_posix()
        if relative == _ALLOWED_NETWORK_MODULE_IMPORTER:
            continue
        imported = _imported_modules(_tree(path))
        hit = imported & _NETWORK_MODULES
        if hit:
            offenders.append(f"{relative} imports {hit}")
    assert offenders == []


def test_fetch_module_actually_imports_httpx():
    path = ROOT / _ALLOWED_NETWORK_MODULE_IMPORTER
    assert path.is_file()
    imported = _imported_modules(_tree(path))
    assert "httpx" in imported
