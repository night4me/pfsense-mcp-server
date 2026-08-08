"""ADR-017 G4 / OFFICIAL_GUIDANCE_LAYER.md Required tests: the guidance
package must have zero import path to any existing safety-authority code
path, and no production module may consume it yet -- both directions
proven by AST scan, not by docstring, mirroring
`tests/tier1/test_isolation.py`'s pattern for a different subsystem.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
GUIDANCE_PACKAGE = ROOT / "src/pfsense_mcp/guidance"

#: OFFICIAL_GUIDANCE_LAYER.md's Trust boundaries section, TB-G4 / G4:
#: nothing capable of selecting a capability/endpoint/method or reaching
#: mutation may be imported by the guidance package.
FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.write_types",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.tools",
}


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


def test_guidance_package_has_no_safety_authority_import():
    offenders: list[str] = []
    for path in GUIDANCE_PACKAGE.glob("*.py"):
        imported = _imported_modules(_tree(path))
        for module in imported:
            if any(module == root or module.startswith(f"{root}.") for root in FORBIDDEN_IMPORT_ROOTS):
                offenders.append(f"{path.relative_to(ROOT).as_posix()} imports {module}")
    assert offenders == []


def test_guidance_package_is_not_imported_by_production_yet():
    production = ROOT / "src/pfsense_mcp"
    offenders: list[str] = []
    for path in production.rglob("*.py"):
        if "guidance" in path.relative_to(production).parts:
            continue
        imported = _imported_modules(_tree(path))
        if any(module == "pfsense_mcp.guidance" or module.startswith("pfsense_mcp.guidance.") for module in imported):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_guidance_package_imports_no_network_module():
    forbidden_network_modules = {"socket", "requests", "httpx", "urllib.request"}
    offenders: list[str] = []
    for path in GUIDANCE_PACKAGE.glob("*.py"):
        imported = _imported_modules(_tree(path))
        if imported & forbidden_network_modules:
            offenders.append(f"{path.relative_to(ROOT).as_posix()} imports {imported & forbidden_network_modules}")
    assert offenders == []
