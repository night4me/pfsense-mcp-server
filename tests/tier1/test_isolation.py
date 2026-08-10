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
    # rest_api_client/transport/tools remain forbidden for every tier1
    # module, including executor.py: the executor reaches pfSense only
    # through WriteApiClient.send_for_tier1()/PfSenseClient's own typed
    # methods, never raw Transport.request() or the READ tool registry.
    universally_forbidden_import_roots = {
        "pfsense_mcp.rest_api_client",
        "pfsense_mcp.transport",
        "pfsense_mcp.tools",
    }
    # executor.py is the one sealed exception (sealed_executor.md
    # Invariant I1): it is the only tier1 module authorized to hold a
    # WriteApiClient/PfSenseClient reference. Every other tier1 module,
    # including any future tier1/adapters/*.py, remains forbidden from
    # importing either.
    executor_only_import_roots = {"pfsense_mcp.write_api_client", "pfsense_mcp.pfsense_client"}
    forbidden_calls = {"delete", "patch", "post", "put", "request", "tool"}
    # anti_rollback_tpm_witness.py is a second, narrow, explicit exception,
    # mirroring executor.py's own pattern above: it is the guest side of the
    # ADR-011 TPM-backed anti-rollback witness service
    # (docs/tier1/specs/anti_rollback_tpm_host_witness.md) -- a system with
    # no relationship to pfSense at all. Its httpx.Client.post() call reaches
    # only the witness daemon's own /anchor/advance endpoint. It remains
    # fully subject to universally_forbidden_import_roots and
    # executor_only_import_roots above (still cannot import
    # rest_api_client/transport/tools/write_api_client/pfsense_client), so
    # it stays structurally incapable of reaching pfSense even with this
    # one call-name check relaxed. No other tier1 module gets this
    # exception, and "post" is the only call name relaxed for it.
    call_name_exceptions = {"anti_rollback_tpm_witness.py": {"post"}}
    for path in (ROOT / "src/pfsense_mcp/tier1").glob("*.py"):
        forbidden_import_roots = universally_forbidden_import_roots | (
            set() if path.name == "executor.py" else executor_only_import_roots
        )
        tree = _tree(path)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }
        assert not any(
            module == root or module.startswith(f"{root}.") for module in imported for root in forbidden_import_roots
        ), f"{path.name} imports a forbidden module"
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        effective_forbidden_calls = forbidden_calls - call_name_exceptions.get(path.name, set())
        assert called_attributes.isdisjoint(effective_forbidden_calls), f"{path.name} calls a forbidden attribute name"


def test_all_production_write_surfaces_remain_inactive():
    assert EngineerProfile.capabilities == frozenset()
    assert INACTIVE_TIER1_POLICY.rules == frozenset()
    assert not any(isinstance(value, WriteEndpointInfo) for value in vars(WriteEndpoints).values())
