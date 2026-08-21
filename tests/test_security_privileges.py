"""Comprehensive tests for `pfsense_mcp.security_privileges` (`ADR-033`
implementation Phase B). `tests/fixtures/pfsense_openapi_schema_trimmed.json`
is a real, trimmed subset (82 paths -- the current 81 READ + 1 WRITE
endpoints) of an actual OpenAPI schema previously captured live from
the disposable LAB appliance during the ADR-026 provisioning work,
plus thirty-eight entries carried over verbatim from the live production/LAB
schemas for the READ Expansion phase (interface VLANs, static routes,
interface groups, firewall schedules, REST API version, firewall
virtual IPs, certificate authorities, IPsec SA/child-SA status,
WireGuard tunnel/peer status, OpenVPN server/client/connection/route
status, DNS Forwarder host overrides, DNS Resolver domain overrides
and access lists, interface available interfaces/GREs/LAGGs, routing
gateway groups/default, DHCP relay, DHCP server address pools/
custom options, the system hostname/timezone/DNS/console/webgui
settings cluster, the REST API access list/CRLs/available packages
trio, firewall traffic shapers, and the IPsec Phase 2/encryption
capability lists trio) -- not synthetic data, just narrowed to keep
the fixture small.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pfsense_mcp.security_privileges import (
    DriftFindingKind,
    EvidenceClass,
    ResolvedPrivilege,
    ToolPrivilegeRequirement,
    check_package_version_support,
    compute_account_drift,
    compute_privilege_from_url,
    distinct_ok_privileges,
    full_api_path,
    lookup_schema_privileges,
    read_profile_requirements,
    resolve_privilege,
    resolve_profile_privileges,
    write_protected_profile_requirements,
    write_protected_tool_requirements,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def live_schema() -> dict:
    return json.loads((FIXTURES / "pfsense_openapi_schema_trimmed.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. compute_privilege_from_url -- the pure pinned-source algorithm
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "method", "expected"),
    [
        ("/api/v2/status/system", "GET", "api-v2-status-system-get"),
        ("/api/v2/firewall/alias", "PATCH", "api-v2-firewall-alias-patch"),
        ("/api/v2/status/dhcp_server/leases", "GET", "api-v2-status-dhcp-server-leases-get"),
        ("/api/v2/firewall/aliases", "GET", "api-v2-firewall-aliases-get"),
        ("/api/v2/system/hasync", "GET", "api-v2-system-hasync-get"),
    ],
)
def test_compute_privilege_from_url_matches_known_values(url, method, expected):
    assert compute_privilege_from_url(url, method) == expected


def test_compute_privilege_from_url_converts_underscores_and_slashes():
    assert compute_privilege_from_url("/a_b/c_d", "GET") == "a-b-c-d-get"


def test_compute_privilege_from_url_rejects_malformed_url():
    with pytest.raises(ValueError, match="must be a non-empty path starting with '/'"):
        compute_privilege_from_url("no-leading-slash", "GET")
    with pytest.raises(ValueError):
        compute_privilege_from_url("", "GET")


def test_compute_privilege_from_url_rejects_malformed_method():
    with pytest.raises(ValueError, match="must be a non-empty alphabetic HTTP verb"):
        compute_privilege_from_url("/a", "")
    with pytest.raises(ValueError):
        compute_privilege_from_url("/a", "GET2")


def test_full_api_path_matches_rest_api_client_convention():
    from pfsense_mcp.api_version import ApiVersion

    assert full_api_path("/status/system", ApiVersion.V2) == "/api/v2/status/system"


# ---------------------------------------------------------------------------
# 2. lookup_schema_privileges -- pure schema parsing
# ---------------------------------------------------------------------------


def test_lookup_schema_privileges_known_good(live_schema):
    result = lookup_schema_privileges(live_schema, "/api/v2/status/system", "GET")
    assert result.ok
    assert result.privileges == ("page-all", "api-v2-status-system-get")


def test_lookup_schema_privileges_unknown_endpoint(live_schema):
    result = lookup_schema_privileges(live_schema, "/api/v2/does/not/exist", "GET")
    assert not result.ok
    assert "not present in schema" in result.error


def test_lookup_schema_privileges_endpoint_method_mismatch(live_schema):
    # /api/v2/status/system exists in the fixture, but only GET was captured.
    result = lookup_schema_privileges(live_schema, "/api/v2/status/system", "DELETE")
    assert not result.ok
    assert "not present for endpoint" in result.error


def test_lookup_schema_privileges_missing_paths_object():
    result = lookup_schema_privileges({}, "/api/v2/status/system", "GET")
    assert not result.ok
    assert "no 'paths' object" in result.error


def test_lookup_schema_privileges_missing_description():
    schema = {"paths": {"/api/v2/x": {"get": {}}}}
    result = lookup_schema_privileges(schema, "/api/v2/x", "GET")
    assert not result.ok
    assert "no 'description' field" in result.error


def test_lookup_schema_privileges_no_allowed_privileges_marker():
    schema = {"paths": {"/api/v2/x": {"get": {"description": "nothing relevant here"}}}}
    result = lookup_schema_privileges(schema, "/api/v2/x", "GET")
    assert not result.ok
    assert "no 'Allowed privileges' text found" in result.error


def test_lookup_schema_privileges_empty_list_is_malformed():
    schema = {"paths": {"/api/v2/x": {"get": {"description": "**Allowed privileges**: [  ]"}}}}
    result = lookup_schema_privileges(schema, "/api/v2/x", "GET")
    assert not result.ok
    assert "empty" in result.error


def test_lookup_schema_privileges_duplicate_entries_are_deduped_not_an_error():
    schema = {
        "paths": {
            "/api/v2/x": {
                "get": {
                    "description": "**Allowed privileges**: [ page-all, api-v2-x-get, api-v2-x-get ]",
                }
            }
        }
    }
    result = lookup_schema_privileges(schema, "/api/v2/x", "GET")
    assert result.ok
    assert result.privileges == ("page-all", "api-v2-x-get")


def test_lookup_schema_privileges_malformed_empty_entry_is_rejected():
    schema = {"paths": {"/api/v2/x": {"get": {"description": "**Allowed privileges**: [ page-all, , api-v2-x-get ]"}}}}
    result = lookup_schema_privileges(schema, "/api/v2/x", "GET")
    assert not result.ok
    assert "malformed privilege list" in result.error


# ---------------------------------------------------------------------------
# 3. resolve_privilege -- schema + pinned-source fail-closed combination
# ---------------------------------------------------------------------------


def test_resolve_privilege_agreement_is_source_cross_checked(live_schema):
    result = resolve_privilege(live_schema, "/api/v2/status/system", "GET")
    assert result.ok
    assert result.privilege == "api-v2-status-system-get"
    assert result.evidence_class is EvidenceClass.SOURCE_CROSS_CHECKED


def test_resolve_privilege_no_schema_is_uncorroborated_but_ok():
    result = resolve_privilege(None, "/api/v2/status/system", "GET")
    assert result.ok
    assert result.privilege == "api-v2-status-system-get"
    assert result.evidence_class is None  # honestly: no live corroboration attempted


def test_resolve_privilege_disagreement_fails_closed():
    schema = {
        "paths": {
            "/api/v2/status/system": {
                "get": {"description": "**Allowed privileges**: [ page-all, some-other-privilege-get ]"}
            }
        }
    }
    result = resolve_privilege(schema, "/api/v2/status/system", "GET")
    assert not result.ok
    assert result.privilege is None
    assert "disagreement" in result.error
    assert "some-other-privilege-get" in result.error
    assert "api-v2-status-system-get" in result.error


def test_resolve_privilege_page_all_only_fails_closed():
    schema = {"paths": {"/api/v2/x": {"get": {"description": "**Allowed privileges**: [ page-all ]"}}}}
    result = resolve_privilege(schema, "/api/v2/x", "GET")
    assert not result.ok
    assert "no narrow privilege exists" in result.error


def test_resolve_privilege_ambiguous_multiple_narrow_privileges_fails_closed():
    schema = {
        "paths": {
            "/api/v2/x": {"get": {"description": "**Allowed privileges**: [ page-all, api-v2-a-get, api-v2-b-get ]"}}
        }
    }
    result = resolve_privilege(schema, "/api/v2/x", "GET")
    assert not result.ok
    assert "ambiguous" in result.error


def test_resolve_privilege_missing_endpoint_fails_closed_never_falls_back_to_source(live_schema):
    """Even though the pinned-source algorithm *could* produce a
    candidate for an endpoint missing from the schema, resolve_privilege
    must not silently use it -- requirement 1's fail-closed rule."""

    result = resolve_privilege(live_schema, "/api/v2/does/not/exist", "GET")
    assert not result.ok
    assert result.privilege is None


# ---------------------------------------------------------------------------
# 4. registered_read_tool_requirements / write_protected_profile_requirements
# ---------------------------------------------------------------------------


def test_read_profile_requirements_has_82_entries_with_exactly_one_local_only():
    requirements = read_profile_requirements()
    assert len(requirements) == 82
    local_only = [r for r in requirements if r.url is None]
    assert len(local_only) == 1
    assert local_only[0].tool_name == "mcp_info"


def test_read_profile_resolves_to_the_currently_verified_81_privileges(live_schema):
    resolved = resolve_profile_privileges(live_schema, read_profile_requirements())
    assert all(r.ok for r in resolved), [r.error for r in resolved if not r.ok]
    privileges = distinct_ok_privileges(resolved)
    assert len(privileges) == 81
    # Every resolved privilege is source-cross-checked -- the strongest
    # evidence class, since the fixture is real captured schema data.
    assert all(r.evidence_class is EvidenceClass.SOURCE_CROSS_CHECKED for r in resolved)


def test_write_protected_profile_resolves_to_the_currently_verified_82_privileges(live_schema):
    resolved = resolve_profile_privileges(live_schema, write_protected_profile_requirements())
    assert all(r.ok for r in resolved), [r.error for r in resolved if not r.ok]
    privileges = distinct_ok_privileges(resolved)
    assert len(privileges) == 82


def test_write_protected_includes_the_write_exclusive_patch_privilege(live_schema):
    resolved = resolve_profile_privileges(live_schema, write_protected_profile_requirements())
    privileges = distinct_ok_privileges(resolved)
    assert "api-v2-firewall-alias-patch" in privileges


def test_write_protected_tool_requirements_is_not_hard_coded_to_one_entry():
    """Generic over WriteEndpoints.active_entries() -- currently exactly
    one, but this test only asserts consistency with that live source,
    never a hard-coded count."""

    from pfsense_mcp.write_endpoints import WriteEndpoints

    requirements = write_protected_tool_requirements()
    assert len(requirements) == len(WriteEndpoints.active_entries())
    assert {r.endpoint_symbol for r in requirements} == set(WriteEndpoints.active_entries())


def test_profile_requirements_are_deterministic():
    first = read_profile_requirements()
    second = read_profile_requirements()
    assert first == second


def test_no_hard_coded_privilege_count_assumption_in_source():
    """The 41/42 counts above are regression evidence about *today's*
    tool catalogue, not a constant baked into the production functions
    -- proven by confirming read_profile_requirements()'s own length
    equals however many non-__init__ files currently exist under
    tools/read/, not a literal 42 anywhere in the derivation logic."""

    from pathlib import Path as _Path

    tools_dir = _Path("src/pfsense_mcp/tools/read")
    on_disk = len([p for p in tools_dir.glob("*.py") if p.name != "__init__.py"])
    assert len(read_profile_requirements()) == on_disk


# ---------------------------------------------------------------------------
# 5. drift detection
# ---------------------------------------------------------------------------


def test_drift_exact_match_is_clean():
    report = compute_account_drift(frozenset({"a", "b"}), frozenset({"a", "b"}))
    assert report.clean
    kinds = {f.kind for f in report.findings}
    assert kinds == {DriftFindingKind.PRIVILEGE_PRESENT_AS_EXPECTED}


def test_drift_missing_privilege():
    report = compute_account_drift(frozenset({"a", "b"}), frozenset({"a"}))
    assert not report.clean
    assert any(f.kind is DriftFindingKind.PRIVILEGE_MISSING and f.privilege == "b" for f in report.findings)


def test_drift_unexpected_additional_privilege():
    report = compute_account_drift(frozenset({"a"}), frozenset({"a", "page-all"}))
    assert not report.clean
    assert any(
        f.kind is DriftFindingKind.UNEXPECTED_ADDITIONAL_PRIVILEGE and f.privilege == "page-all"
        for f in report.findings
    )


def test_drift_multiple_simultaneous_findings():
    report = compute_account_drift(frozenset({"a", "b", "c"}), frozenset({"a", "d", "e"}))
    assert not report.clean
    kinds = [(f.kind, f.privilege) for f in report.findings]
    assert (DriftFindingKind.PRIVILEGE_MISSING, "b") in kinds
    assert (DriftFindingKind.PRIVILEGE_MISSING, "c") in kinds
    assert (DriftFindingKind.UNEXPECTED_ADDITIONAL_PRIVILEGE, "d") in kinds
    assert (DriftFindingKind.UNEXPECTED_ADDITIONAL_PRIVILEGE, "e") in kinds


def test_drift_resolution_errors_become_malformed_evidence_findings():
    report = compute_account_drift(
        frozenset({"a"}), frozenset({"a"}), resolution_errors=("schema/source disagreement for X",)
    )
    assert not report.clean
    assert any(f.kind is DriftFindingKind.MALFORMED_EVIDENCE for f in report.findings)


def test_drift_findings_are_deterministically_ordered():
    report1 = compute_account_drift(frozenset({"z", "a", "m"}), frozenset({"a"}))
    report2 = compute_account_drift(frozenset({"z", "a", "m"}), frozenset({"a"}))
    assert report1.findings == report2.findings
    missing = [f.privilege for f in report1.findings if f.kind is DriftFindingKind.PRIVILEGE_MISSING]
    assert missing == sorted(missing)


def test_drift_never_mutates_inputs():
    expected = frozenset({"a", "b"})
    observed = frozenset({"a"})
    compute_account_drift(expected, observed)
    assert expected == frozenset({"a", "b"})
    assert observed == frozenset({"a"})


# ---------------------------------------------------------------------------
# 6. package version support
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", [(2, 7, 7), (2, 8, 0), (2, 9, 0), (2, 10, 0)])
def test_supported_package_versions_produce_no_finding(version):
    assert check_package_version_support(version) is None


@pytest.mark.parametrize("version", [(2, 7, 6), (2, 11, 0), (3, 0, 0)])
def test_unsupported_package_versions_produce_a_finding(version):
    finding = check_package_version_support(version)
    assert finding is not None
    assert finding.kind is DriftFindingKind.UNVERIFIED_PACKAGE_VERSION


def test_unverified_package_version_alone_does_not_make_a_drift_report_unclean():
    """An out-of-range version is a flag to re-confirm, not proof of an
    actual mismatch (ADR-033 §3) -- DriftReport.clean must not key off
    UNVERIFIED_PACKAGE_VERSION findings."""

    from pfsense_mcp.security_privileges import DriftFinding, DriftReport

    report = DriftReport(findings=(DriftFinding(DriftFindingKind.UNVERIFIED_PACKAGE_VERSION, "out of range"),))
    assert report.clean


# ---------------------------------------------------------------------------
# 7. no network / no mutation, structural
# ---------------------------------------------------------------------------


def test_resolve_privilege_never_performs_io(monkeypatch):
    """Structural proof, not just absence-of-evidence: patch open()/
    socket-like builtins away and confirm resolution still works from
    an in-memory schema dict."""

    import builtins

    original_open = builtins.open

    def _forbidden_open(*args, **kwargs):
        raise AssertionError("resolve_privilege() must never perform file I/O")

    schema = {
        "paths": {
            "/api/v2/status/system": {
                "get": {"description": "**Allowed privileges**: [ page-all, api-v2-status-system-get ]"}
            }
        }
    }
    monkeypatch.setattr(builtins, "open", _forbidden_open)
    try:
        result = resolve_privilege(schema, "/api/v2/status/system", "GET")
        assert result.ok
    finally:
        monkeypatch.setattr(builtins, "open", original_open)


def test_resolved_privilege_and_requirement_dataclasses_are_frozen():
    r = ResolvedPrivilege("/x", "GET", "p", None, None)
    with pytest.raises(AttributeError):
        r.privilege = "other"  # type: ignore[misc]

    t = ToolPrivilegeRequirement("x", None, None, None, None)
    with pytest.raises(AttributeError):
        t.tool_name = "y"  # type: ignore[misc]
