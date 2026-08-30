"""Qualification-only tests for `POST_V1_1_BIND_READ_QUALIFICATION.md`.

BIND (`pfSense-pkg-bind`) is not installed on LAB, and this mission's owner
authorization explicitly prohibits implementing production BIND tools or
installing the package before an explicit owner GO. These tests exist solely
to make the qualification's own evidence -- the complete BIND operation
matrix and its privilege-alias-freedom proof -- durable, executable, and
regression-checked against `tests/fixtures/bind_openapi_subset.json` (a
pinned, self-contained subset of the live pfrest.org OpenAPI document
fetched 2026-08-30, scoped to the 13 `/services/bind/*` paths and their
21 referenced schemas). They do not touch, import, or assert anything about
production `src/pfsense_mcp` runtime code -- there is none to test yet.

If a future mission installs BIND on LAB and implements production tools,
this file's fixture should be refreshed from a live fetch and these tests
extended (not replaced) with the usual per-tool client/registry/endpoint
tests those tools would need.
"""

from __future__ import annotations

import json
from pathlib import Path

from pfsense_mcp.security_privileges import resolve_privilege

BIND_FIXTURE = Path(__file__).parent / "fixtures" / "bind_openapi_subset.json"

#: The complete BIND operation matrix as of this qualification (pfREST
#: 2.10.2, fetched live from pfrest.org 2026-08-30). 13 paths, each with
#: the exact HTTP methods pfREST declares for it. This is the corrected,
#: independently re-derived count -- the earlier POST_V1_1_FINAL_READ_
#: COVERAGE_AUDIT.md pass had missed `/services/bind/settings` entirely
#: and undercounted the surface as 9 GET-capable paths.
EXPECTED_BIND_OPERATION_MATRIX: dict[str, tuple[str, ...]] = {
    "/api/v2/services/bind/access_list": ("DELETE", "GET", "PATCH", "POST"),
    "/api/v2/services/bind/access_list/entries": ("DELETE", "GET"),
    "/api/v2/services/bind/access_list/entry": ("DELETE", "GET", "PATCH", "POST"),
    "/api/v2/services/bind/access_lists": ("DELETE", "GET", "PUT"),
    "/api/v2/services/bind/settings": ("GET", "PATCH"),
    "/api/v2/services/bind/sync/remote_host": ("DELETE", "GET", "PATCH", "POST"),
    "/api/v2/services/bind/sync/remote_hosts": ("DELETE", "GET", "PUT"),
    "/api/v2/services/bind/sync/settings": ("GET", "PATCH"),
    "/api/v2/services/bind/view": ("DELETE", "GET", "PATCH", "POST"),
    "/api/v2/services/bind/views": ("DELETE", "GET", "PUT"),
    "/api/v2/services/bind/zone": ("DELETE", "GET", "PATCH", "POST"),
    "/api/v2/services/bind/zone/record": ("DELETE", "GET", "PATCH", "POST"),
    "/api/v2/services/bind/zones": ("DELETE", "GET", "PUT"),
}


def _load_fixture() -> dict:
    return json.loads(BIND_FIXTURE.read_text(encoding="utf-8"))


def test_bind_fixture_paths_match_the_expected_operation_matrix():
    doc = _load_fixture()
    bind_paths = {p for p in doc["paths"] if "/bind" in p.lower()}
    assert bind_paths == set(EXPECTED_BIND_OPERATION_MATRIX)
    for path, expected_methods in EXPECTED_BIND_OPERATION_MATRIX.items():
        actual_methods = tuple(sorted(m.upper() for m in doc["paths"][path]))
        assert actual_methods == tuple(sorted(expected_methods)), path


def test_bind_surface_is_13_paths_not_9():
    """Q1's answer, made a regression check: the earlier 9-path BIND
    tally in POST_V1_1_FINAL_READ_COVERAGE_AUDIT.md was incomplete."""
    doc = _load_fixture()
    bind_paths = {p for p in doc["paths"] if "/bind" in p.lower()}
    assert len(bind_paths) == 13


def test_every_bind_get_privilege_resolves_source_cross_checked():
    doc = _load_fixture()
    for path, methods in EXPECTED_BIND_OPERATION_MATRIX.items():
        if "GET" not in methods:
            continue
        result = resolve_privilege(doc, path, "GET")
        assert result.ok, result.error
        assert result.evidence_class is not None
        assert result.evidence_class.value == "source_cross_checked"


def test_no_bind_get_privilege_is_aliased_with_any_mutating_bind_privilege():
    """Phase 4's hard security gate, as an executable proof: every BIND
    GET privilege must be a structurally distinct string from every BIND
    POST/PATCH/PUT/DELETE privilege, both on its own path and across all
    13 BIND paths."""
    doc = _load_fixture()
    get_privileges: set[str] = set()
    mutating_privileges: set[str] = set()
    for path, methods in EXPECTED_BIND_OPERATION_MATRIX.items():
        for method in methods:
            result = resolve_privilege(doc, path, method)
            assert result.ok, (path, method, result.error)
            if method == "GET":
                get_privileges.add(result.privilege)
            else:
                mutating_privileges.add(result.privilege)

    assert len(get_privileges) == 13
    assert len(mutating_privileges) == 29
    assert get_privileges.isdisjoint(mutating_privileges)


def test_bind_sync_remote_host_schemas_carry_a_plaintext_password_field():
    """Regression coverage for the REJECT_SECRET classification: proves
    the finding was schema-derived, not assumed from the resource name."""
    doc = _load_fixture()
    schema = doc["components"]["schemas"]["BINDSyncRemoteHost"]
    assert "password" in schema["properties"]


def test_bind_zone_schema_has_no_tsig_or_dnssec_private_key_field():
    """Regression coverage for the Phase 3.A/3.B finding: no field name
    across any of the 21 pinned BIND-related schemas suggests TSIG or
    DNSSEC private key material is returned by any BIND GET endpoint."""
    doc = _load_fixture()
    sensitive_terms = ("tsig", "hmac", "privatekey", "keydata")
    for schema_name, schema in doc["components"]["schemas"].items():
        if not schema_name.startswith("BIND"):
            continue
        for field_name in schema.get("properties", {}):
            lowered = field_name.lower()
            assert not any(term in lowered for term in sensitive_terms), (schema_name, field_name)


def test_bind_zone_records_field_is_schema_bounded_but_large():
    """Documents the Class F finding driving the SAFE_READ_WITH_BOUNDS
    recommendation for `zones`/`zone`: the schema itself caps `records`
    at 65535 items, which is a real bound but still large enough that a
    future implementation should exclude or paginate it rather than
    return it inline by default."""
    doc = _load_fixture()
    records_field = doc["components"]["schemas"]["BINDZone"]["properties"]["records"]
    assert records_field["type"] == "array"
    assert records_field["maxItems"] == 65535
