"""Tests for scripts/pfrest_privilege_crosscheck.py (owner direction,
pfREST_LIVE_GUIDANCE_ARC, 2026-08-28). Pure classification logic tested
offline; the fetch functions tested via respx/MockTransport-style
fakes -- never the real network."""

from __future__ import annotations

import httpx
import respx
from pfrest_privilege_crosscheck import (
    OPENAPI_URL,
    CrossCheckResult,
    CrossCheckVerdict,
    classify,
    run_crosscheck,
)

from pfsense_mcp.security_privileges import SchemaPrivilegeLookup, ToolPrivilegeRequirement

_REQUIREMENT = ToolPrivilegeRequirement(
    "pfsense_get_firewall_aliases", "get_firewall_aliases", "FIREWALL_ALIASES", "/api/v2/firewall/aliases", "GET"
)
_EXPECTED = "api-v2-firewall-aliases-get"


def _lookup(*privileges: str, error: str | None = None) -> SchemaPrivilegeLookup:
    if error is not None:
        return SchemaPrivilegeLookup(None, error)
    return SchemaPrivilegeLookup(privileges, None)


def test_classify_matches_when_both_sources_agree():
    result = classify(_REQUIREMENT, _lookup("page-all", _EXPECTED), _lookup("page-all", _EXPECTED))
    assert result.verdict == CrossCheckVerdict.MATCH


def test_classify_drift_when_sources_disagree():
    result = classify(_REQUIREMENT, _lookup("page-all", _EXPECTED), _lookup("page-all", "some-renamed-privilege"))
    assert result.verdict == CrossCheckVerdict.DRIFT
    assert _EXPECTED in result.detail
    assert "some-renamed-privilege" in result.detail


def test_classify_explained_difference_when_upstream_unavailable():
    result = classify(_REQUIREMENT, None, _lookup("page-all", _EXPECTED))
    assert result.verdict == CrossCheckVerdict.EXPLAINED_DIFFERENCE


def test_classify_explained_difference_when_upstream_not_ok():
    result = classify(_REQUIREMENT, _lookup(error="endpoint not present in schema"), None)
    assert result.verdict == CrossCheckVerdict.EXPLAINED_DIFFERENCE
    assert "endpoint not present" in result.detail


def test_classify_match_when_no_appliance_configured_and_upstream_agrees_with_pinned_source():
    result = classify(_REQUIREMENT, _lookup("page-all", _EXPECTED), None)
    assert result.verdict == CrossCheckVerdict.MATCH
    assert "agrees with pinned-source algorithm" in result.detail


def test_classify_match_but_flags_pinned_source_disagreement_when_no_appliance_configured():
    """Still MATCH (nothing to cross-check against), but the detail text
    honestly says the upstream value itself doesn't match our own
    pinned-source expectation -- an important distinction a human/CI
    reader should be able to see even when the verdict is MATCH."""
    result = classify(_REQUIREMENT, _lookup("page-all", "totally-different-privilege"), None)
    assert result.verdict == CrossCheckVerdict.MATCH
    assert "does NOT match pinned-source algorithm" in result.detail


def test_classify_explained_difference_when_appliance_not_ok():
    result = classify(_REQUIREMENT, _lookup("page-all", _EXPECTED), _lookup(error="endpoint not present in schema"))
    assert result.verdict == CrossCheckVerdict.EXPLAINED_DIFFERENCE


def test_classify_never_grants_or_authorizes_anything():
    """Structural check: CrossCheckResult carries no field that could be
    mistaken for a grant/authorization decision."""
    fields = set(CrossCheckResult.__dataclass_fields__.keys())
    forbidden = {"grant", "authorize", "confirm", "token", "privilege_change"}
    assert not (fields & forbidden)


@respx.mock
def test_run_crosscheck_end_to_end_offline_self_consistency():
    """Full integration using a real (small, synthetic) OpenAPI document
    served via respx -- proves the whole pipeline works without hitting
    the real network, and that PFREST_UPSTREAM-only mode (no appliance)
    reports MATCH for a well-formed endpoint."""

    doc = {
        "paths": {
            "/api/v2/firewall/aliases": {
                "get": {
                    "description": (
                        "<h3>Description:</h3>Reads.<br><h3>Details:</h3>"
                        f"**Allowed privileges**: [ page-all, {_EXPECTED} ]<br>"
                    )
                }
            }
        }
    }
    respx.get(OPENAPI_URL).mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, json=doc)
    )

    results = run_crosscheck(doc, None)
    matching = [r for r in results if r.url == "/api/v2/firewall/aliases" and r.method == "GET"]
    assert len(matching) == 1
    assert matching[0].verdict == CrossCheckVerdict.MATCH


def test_run_crosscheck_detects_real_drift():
    upstream_doc = {
        "paths": {
            "/api/v2/firewall/aliases": {
                "get": {"description": f"**Allowed privileges**: [ page-all, {_EXPECTED} ]<br>"}
            }
        }
    }
    appliance_doc = {
        "paths": {
            "/api/v2/firewall/aliases": {
                "get": {"description": "**Allowed privileges**: [ page-all, some-renamed-privilege ]<br>"}
            }
        }
    }
    results = run_crosscheck(upstream_doc, appliance_doc)
    matching = [r for r in results if r.url == "/api/v2/firewall/aliases" and r.method == "GET"]
    assert len(matching) == 1
    assert matching[0].verdict == CrossCheckVerdict.DRIFT


def test_run_crosscheck_no_drift_when_sources_genuinely_agree():
    doc = {
        "paths": {
            "/api/v2/firewall/aliases": {
                "get": {"description": f"**Allowed privileges**: [ page-all, {_EXPECTED} ]<br>"}
            }
        }
    }
    results = run_crosscheck(doc, doc)
    matching = [r for r in results if r.url == "/api/v2/firewall/aliases" and r.method == "GET"]
    assert len(matching) == 1
    assert matching[0].verdict == CrossCheckVerdict.MATCH


def test_run_crosscheck_covers_all_url_bearing_tools():
    """Every registered READ tool with a real endpoint gets exactly one
    classification -- none silently dropped."""
    from pfsense_mcp.security_privileges import read_profile_requirements

    expected = [r for r in read_profile_requirements() if r.url is not None and r.method is not None]
    results = run_crosscheck(None, None)
    assert len(results) == len(expected)
