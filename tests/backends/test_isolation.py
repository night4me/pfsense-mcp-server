"""ADR-030 (Nexus Phase A): `pfsense_mcp.backends` is a research/design
artifact with zero production wiring. Unlike `tier1` (which has five
narrow, individually-justified exceptions -- see
`tests/tier1/test_isolation.py`), `backends` has none: nothing imports
it, anywhere, for any reason. This test enforces that with no carve-outs.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src" / "pfsense_mcp"


def _is_backends_module(module: str) -> bool:
    return module == "backends" or module.startswith("backends.")


def _imports_backends(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            _is_backends_module(alias.name.removeprefix("pfsense_mcp.")) for alias in node.names
        ):
            return True
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if _is_backends_module(module.removeprefix("pfsense_mcp.")) or (node.level and _is_backends_module(module)):
                return True
    return False


def test_backends_package_is_never_imported_outside_itself():
    offenders = [
        path for path in SRC.rglob("*.py") if not path.is_relative_to(SRC / "backends") and _imports_backends(path)
    ]
    assert offenders == [], f"pfsense_mcp.backends must not be imported by production code: {offenders}"


def test_backends_package_defines_no_write_shaped_members():
    """Every port must be a READ-only capability -- no method name
    suggesting a mutation, and nothing importing write_api_client,
    tier1, or the transport layer."""

    ports_path = SRC / "backends" / "ports.py"
    tree = ast.parse(ports_path.read_text(encoding="utf-8"), filename=str(ports_path))

    forbidden_imports = {"write_api_client", "tier1", "transport"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = (node.module or "").removeprefix("pfsense_mcp.").split(".")[0]
            assert module not in forbidden_imports, f"backends/ports.py must not import {module!r}"

    write_shaped_prefixes = ("set_", "create_", "update_", "delete_", "patch_", "put_", "execute_", "apply_")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert not node.name.startswith(write_shaped_prefixes), f"WRITE-shaped port method found: {node.name}"
