import ast
from pathlib import Path

from pfsense_mcp.profiles import EngineerProfile
from pfsense_mcp.tier1.policy import INACTIVE_TIER1_POLICY
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

ROOT = Path(__file__).parents[2]


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports_tier1(path: Path) -> bool:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import) and any(alias.name.startswith("pfsense_mcp.tier1") for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("pfsense_mcp.tier1") or (node.level and module.startswith("tier1")):
                return True
    return False


def test_tier1_is_not_imported_outside_its_inert_package():
    production = ROOT / "src/pfsense_mcp"
    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in production.rglob("*.py")
        if "tier1" not in path.relative_to(production).parts and _imports_tier1(path)
    ]
    assert offenders == []


def test_tier1_domain_has_no_transport_or_tool_registration_dependency():
    forbidden_import_roots = {
        "pfsense_mcp.rest_api_client",
        "pfsense_mcp.transport",
        "pfsense_mcp.tools",
        "pfsense_mcp.write_api_client",
    }
    forbidden_calls = {"delete", "patch", "post", "put", "request", "tool"}
    for path in (ROOT / "src/pfsense_mcp/tier1").glob("*.py"):
        tree = _tree(path)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }
        assert not any(
            module == root or module.startswith(f"{root}.") for module in imported for root in forbidden_import_roots
        )
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert called_attributes.isdisjoint(forbidden_calls)


def test_all_production_write_surfaces_remain_inactive():
    assert EngineerProfile.capabilities == frozenset()
    assert INACTIVE_TIER1_POLICY.rules == frozenset()
    assert not any(isinstance(value, WriteEndpointInfo) for value in vars(WriteEndpoints).values())
