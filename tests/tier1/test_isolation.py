import ast
from pathlib import Path

from pfsense_mcp.profiles import EngineerProfile
from pfsense_mcp.tier1.policy import INACTIVE_TIER1_POLICY
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

ROOT = Path(__file__).parents[2]


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _is_tier1_module(module: str) -> bool:
    # Exact-or-dotted-prefix match only -- "tier1_anchor_check" (a
    # genuinely different, sibling top-level module) must not match
    # "tier1" via a bare, boundary-unaware startswith() the way an
    # earlier version of this helper did.
    return module == "tier1" or module.startswith("tier1.")


def _imports_tier1(path: Path) -> bool:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import) and any(
            _is_tier1_module(alias.name.removeprefix("pfsense_mcp.")) for alias in node.names
        ):
            return True
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if _is_tier1_module(module.removeprefix("pfsense_mcp.")) or (node.level and _is_tier1_module(module)):
                return True
    return False


def test_tier1_is_not_imported_outside_its_inert_package():
    # tier1_anchor_check.py is the first, narrow, explicit exception
    # (2026-08-10, owner-authorized read-only runtime wiring): the sole
    # production entrypoint for the read-only, opt-in, log-only
    # anti-rollback anchor startup verification -- see its own module
    # docstring for the full scope. application.py itself does NOT
    # import pfsense_mcp.tier1 at all; it only imports
    # tier1_anchor_check.run_anchor_startup_check(), so this exemption's
    # surface is exactly one file, not application.py or any other
    # production module. See
    # tests/test_tier1_anchor_check_isolation.py for the stronger,
    # dedicated tests proving this file's own access is read-only,
    # opt-in, and cannot reach PREPARE/EXECUTE/WRITE.
    #
    # security_discovery.py is the second such exception (2026-08-10,
    # ADR-021 Phase B: read-only security-posture discovery CLI). Its
    # own module docstring states the same discipline; security_cli.py
    # (the actual `pfsense-mcp-security` entrypoint) does NOT import
    # pfsense_mcp.tier1 at all, only security_discovery.py's public
    # functions -- mirroring tier1_anchor_check.py/application.py's own
    # pattern exactly. See tests/test_security_discovery_isolation.py
    # for the matching stronger, dedicated tests.
    #
    # security_plan_digest.py is the third such exception (2026-08-11,
    # ADR-022 Phase B: canonical PlanDigest computation). Unlike the two
    # above, the only pfsense_mcp.tier1 import here is `canonical` --
    # pure, stateless canonicalization/hashing with zero I/O and zero
    # mutation capability of any kind, not the store/witness/anchor
    # machinery the other two exemptions read. See
    # tests/test_security_plan_digest_isolation.py for the matching
    # stronger, dedicated tests, including that this is the *only*
    # pfsense_mcp.tier1 submodule this file ever imports.
    #
    # security_authorization.py is the fourth such exception (2026-08-11,
    # ADR-022 Phase C: PlanAuthorization/DeprovisionAuthorization data
    # models, canonical signing payloads, and signature construction on
    # the signing/operator side only). Like security_plan_digest.py, the
    # only pfsense_mcp.tier1 import here is `canonical`
    # (`DigestPurpose`/`canonical_json`) -- no store/witness/confirmation/
    # contract access. See tests/test_security_authorization_isolation.py
    # for the matching stronger, dedicated tests.
    #
    # security_authorization_verifier.py is the fifth such exception
    # (2026-08-11, ADR-022 Phase D: pure PlanAuthorization signature/
    # expiry/step-scope verification only). The only pfsense_mcp.tier1
    # import here is `ed25519_authority.PinnedAuthoritySet` -- the same,
    # already-reviewed pinned-authority verification mechanics
    # `confirmation_providers.py`/`reconciliation_providers.py` already
    # reuse, not a new cryptographic primitive. No store/contract/
    # executor/state-machine access. See
    # tests/test_security_authorization_verifier_isolation.py for the
    # matching stronger, dedicated tests, including that this is the
    # *only* pfsense_mcp.tier1 submodule this file ever imports and that
    # no production module ever imports this file.
    #
    # tier1_write_bridge.py is the sixth such exception (2026-08-15, W3
    # Slice 4: the accepted first-WRITE product surface's only connection
    # to pfsense_mcp.tier1). Imports
    # `tier1.alias_description.AliasDescriptionChangeV1` and
    # `tier1.production_runtime.{ProductOutcomeState, build_production_runtime}`
    # only -- constructs no lower-level Tier-1 object of its own, performs
    # no authorization/confirmation/execution logic of its own. Neither
    # `tools/registry.py` nor `tools/write/set_firewall_alias_description.py`
    # import `pfsense_mcp.tier1` at all; they only call this module's own
    # two exposed functions. See
    # tests/test_tier1_write_bridge_isolation.py for the matching
    # stronger, dedicated tests.
    exempt = {
        "tier1_anchor_check.py",
        "security_discovery.py",
        "security_plan_digest.py",
        "security_authorization.py",
        "security_authorization_verifier.py",
        "tier1_write_bridge.py",
    }
    production = ROOT / "src/pfsense_mcp"
    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in production.rglob("*.py")
        if "tier1" not in path.relative_to(production).parts and path.name not in exempt and _imports_tier1(path)
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
    # Through W3 Slice 3, WriteEndpoints was empty. W3 Slice 4 added
    # exactly the one accepted first-WRITE entry, governed by ADR-028's
    # own three-condition activation gate (proved reachable-only-when-
    # all-three-hold by tests/test_tool_registry_write.py) -- this test's
    # own job is narrower: prove no *unreviewed additional* entry exists.
    active = {name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)}
    assert active == {"FIREWALL_ALIAS_DESCRIPTION"}
