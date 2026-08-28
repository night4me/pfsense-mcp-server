"""ADR-017 G4 / OFFICIAL_GUIDANCE_LAYER.md Required tests: the guidance
package must have zero import path to any existing safety-authority code
path, proven by AST scan, not by docstring, mirroring
`tests/tier1/test_isolation.py`'s pattern for a different subsystem.

**Revised 2026-08-22** for the owner-authorized `pfsense_get_official_guidance`
tool (Candidate A, `reports-ai/GUIDANCE_MCP_EXPOSURE_QUALIFICATION_2026-08-22.md`):
exactly one production module, `src/pfsense_mcp/tools/read/official_guidance.py`,
is now a deliberate, reviewed exception to "no production module imports
the guidance package" -- every other production module still may not,
verified below.

**Revised again 2026-08-28** (pfREST_LIVE_GUIDANCE_ARC): a second
production module, `src/pfsense_mcp/tools/read/api_guidance.py`
(`pfsense_get_api_guidance`), is now also a deliberate, reviewed
exception -- it imports `pfsense_mcp.guidance.tool_guidance` (Slice A)
to surface PROJECT_AUTHORED tool interpretation alongside
`pfsense_mcp.pfrest_docs`'s PFREST_UPSTREAM/LIVE_APPLIANCE_SCHEMA
evidence. Every other production module still may not import either
package, verified below.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
GUIDANCE_PACKAGE = ROOT / "src/pfsense_mcp/guidance"

#: The two deliberate, reviewed exceptions (owner-authorized 2026-08-22
#: and 2026-08-28 respectively). A change to this constant is itself the
#: kind of thing that must be a reviewed diff, not a silent expansion --
#: see official_guidance.py's and api_guidance.py's own module
#: docstrings for the full rationale of each.
ALLOWED_GUIDANCE_IMPORTERS = frozenset(
    {
        "src/pfsense_mcp/tools/read/official_guidance.py",
        "src/pfsense_mcp/tools/read/api_guidance.py",
    }
)

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


def test_guidance_package_is_imported_by_exactly_one_reviewed_production_module():
    production = ROOT / "src/pfsense_mcp"
    offenders: list[str] = []
    for path in production.rglob("*.py"):
        if "guidance" in path.relative_to(production).parts:
            continue
        imported = _imported_modules(_tree(path))
        if any(module == "pfsense_mcp.guidance" or module.startswith("pfsense_mcp.guidance.") for module in imported):
            relative = path.relative_to(ROOT).as_posix()
            if relative not in ALLOWED_GUIDANCE_IMPORTERS:
                offenders.append(relative)
    assert offenders == []


def test_official_guidance_module_actually_imports_the_guidance_package():
    """The flip side of the test above: confirm every entry in
    `ALLOWED_GUIDANCE_IMPORTERS` is not a stale exception for a file that
    no longer imports guidance -- an unused exception would be exactly
    the kind of silent scope creep this isolation test exists to
    catch."""
    for allowed in sorted(ALLOWED_GUIDANCE_IMPORTERS):
        path = ROOT / allowed
        assert path.is_file(), f"{allowed} no longer exists -- remove the exception"
        imported = _imported_modules(_tree(path))
        assert any(
            module == "pfsense_mcp.guidance" or module.startswith("pfsense_mcp.guidance.") for module in imported
        ), f"{allowed} is listed in ALLOWED_GUIDANCE_IMPORTERS but does not import pfsense_mcp.guidance"


def test_guidance_package_imports_no_network_module():
    forbidden_network_modules = {"socket", "requests", "httpx", "urllib.request"}
    offenders: list[str] = []
    for path in GUIDANCE_PACKAGE.glob("*.py"):
        imported = _imported_modules(_tree(path))
        if imported & forbidden_network_modules:
            offenders.append(f"{path.relative_to(ROOT).as_posix()} imports {imported & forbidden_network_modules}")
    assert offenders == []
