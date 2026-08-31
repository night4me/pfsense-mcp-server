"""Tests for the 14 HAProxy READ tools implemented from
`POST_V1_1_HAPROXY_READ_QUALIFICATION.md`'s already-qualified,
already-live-verified candidate set (source qualification +
2026-08-30 LAB read-only ceremony). See
`reports-ai/POST_V1_1_BIND_HAPROXY_READ_IMPLEMENTATION.md` for the
implementation manifest this file proves.

Three test classes per model-with-exclusions:

1. field-mapping / endpoint-call tests (proves the tool calls exactly
   its one reviewed GET endpoint, and maps included fields correctly);
2. limit-validation tests (plural endpoints only);
3. adversarial structural-exclusion tests -- proves every
   qualification-excluded field can never reach `model_dump_json()`,
   even if a hostile/malformed raw response includes it. This is the
   security-critical set: qualification established these are
   plaintext-credential/raw-config-injection/nested-back-door risks,
   not merely stylistic exclusions.

Plus one permanent regression test proving, via a pinned live-fetched
OpenAPI subset (`tests/fixtures/haproxy_openapi_subset.json`), that
none of the 14 approved GET privileges aliases any of the 61 distinct
HAProxy mutating privileges -- the hard security gate Phase 7 of the
implementation mission required before any tool could be registered.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.security_privileges import resolve_privilege
from pfsense_mcp.transport.mock import MockTransport

HAPROXY_OPENAPI_SUBSET = Path(__file__).parent / "fixtures" / "haproxy_openapi_subset.json"


def _client(path: str, body: dict) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    transport.register("GET", path, status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="test", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


# ---------------------------------------------------------------------------
# 1. HAProxyApplyStatus -- singleton, no exclusions (single safe boolean field)
# ---------------------------------------------------------------------------


def test_get_haproxy_apply_status_maps_field():
    client, transport = _client("/api/v2/services/haproxy/apply", {"data": {"applied": True}})
    status = client.get_haproxy_apply_status()
    assert status.applied is True
    assert transport.calls == [("GET", "/api/v2/services/haproxy/apply")]


def test_get_haproxy_apply_status_tolerates_null():
    client, _ = _client("/api/v2/services/haproxy/apply", {"data": {"applied": None}})
    status = client.get_haproxy_apply_status()
    assert status.applied is None


def test_get_haproxy_apply_status_missing_data_key_raises_shape_error():
    client, _ = _client("/api/v2/services/haproxy/apply", {})
    with pytest.raises(PfSenseResponseShapeError):
        client.get_haproxy_apply_status()


# ---------------------------------------------------------------------------
# 2. HAProxyBackend -- plural, heaviest exclusion set
# ---------------------------------------------------------------------------

_BACKEND_SAFE_FIELDS = {
    "id": 1,
    "name": "lb-backend",
    "balance": "roundrobin",
    "check_type": "none",
    "stats_enabled": True,
    "stats_uri": "/haproxy?stats",
    "stats_realm": "HAProxy Statistics",
    "stats_username": "statsuser",
    "stats_admin": "false",
    "stats_node": "node1",
    "stats_desc": "primary",
    "stats_refresh": 10,
    "persist_cookie_enabled": False,
    "email_to": "ops@example.test",
}

_BACKEND_EXCLUDED_FIELDS = {
    "stats_password": "SENTINEL-STATS-PASSWORD",
    "haproxy_cookie_dynamic_cookie_key": "SENTINEL-COOKIE-KEY",
    "advanced": "SENTINEL-ADVANCED-CONFIG",
    "advanced_backend": "SENTINEL-ADVANCED-BACKEND-CONFIG",
    "servers": [{"name": "SENTINEL-NESTED-SERVER"}],
    "acls": [{"name": "SENTINEL-NESTED-ACL"}],
    "actions": [{"name": "SENTINEL-NESTED-ACTION", "fmt": "SENTINEL-HEADER-VALUE"}],
    "errorfiles": [{"errorfile": "SENTINEL-NESTED-ERRORFILE"}],
}


def _backends_body(extra: dict | None = None) -> dict:
    item = dict(_BACKEND_SAFE_FIELDS)
    if extra:
        item.update(extra)
    return {"data": [item]}


def test_get_haproxy_backends_maps_safe_fields():
    client, transport = _client("/api/v2/services/haproxy/backends?limit=100", _backends_body())
    backends = client.get_haproxy_backends()
    assert len(backends) == 1
    assert backends[0].id == 1
    assert backends[0].name == "lb-backend"
    assert backends[0].balance == "roundrobin"
    assert backends[0].stats_username == "statsuser"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/backends?limit=100")]


def test_get_haproxy_backends_rejects_zero_limit():
    client, _ = _client("/api/v2/services/haproxy/backends?limit=100", _backends_body())
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_backends(limit=0)


def test_get_haproxy_backends_rejects_limit_above_max():
    client, _ = _client("/api/v2/services/haproxy/backends?limit=100", _backends_body())
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_backends(limit=101)


def test_get_haproxy_backends_passes_custom_limit():
    client, transport = _client("/api/v2/services/haproxy/backends?limit=5", _backends_body())
    client.get_haproxy_backends(limit=5)
    assert transport.calls == [("GET", "/api/v2/services/haproxy/backends?limit=5")]


def test_get_haproxy_backends_missing_data_key_raises_shape_error():
    client, _ = _client("/api/v2/services/haproxy/backends?limit=100", {})
    with pytest.raises(PfSenseResponseShapeError):
        client.get_haproxy_backends()


def test_get_haproxy_backends_never_exposes_stats_password_even_if_present_in_raw_response():
    """The single most severe finding of the qualification: `stats_password`
    is `sensitive: true` but NOT `write_only: true` upstream -- a genuine
    plaintext-credential-in-GET-response risk if not structurally excluded."""
    body = _backends_body({"stats_password": "SENTINEL-STATS-PASSWORD"})
    client, _ = _client("/api/v2/services/haproxy/backends?limit=100", body)
    backends = client.get_haproxy_backends()
    dumped = backends[0].model_dump_json()
    assert "SENTINEL-STATS-PASSWORD" not in dumped
    assert not hasattr(backends[0], "stats_password")


def test_get_haproxy_backends_never_exposes_any_excluded_field_even_if_present_in_raw_response():
    body = _backends_body(_BACKEND_EXCLUDED_FIELDS)
    client, _ = _client("/api/v2/services/haproxy/backends?limit=100", body)
    backends = client.get_haproxy_backends()
    dumped = backends[0].model_dump_json()
    for field, value in _BACKEND_EXCLUDED_FIELDS.items():
        assert not hasattr(backends[0], field), f"{field} must not exist on the model at all"
        if isinstance(value, str):
            assert value not in dumped
    for sentinel in (
        "SENTINEL-NESTED-SERVER",
        "SENTINEL-NESTED-ACL",
        "SENTINEL-NESTED-ACTION",
        "SENTINEL-HEADER-VALUE",
    ):
        assert sentinel not in dumped


# ---------------------------------------------------------------------------
# 3. HAProxyBackendAcl -- plural nested, all fields safe (value residual-risk documented)
# ---------------------------------------------------------------------------


def test_get_haproxy_backend_acls_maps_fields_including_reserved_word_not():
    body = {
        "data": [
            {
                "id": 1,
                "parent_id": 0,
                "name": "block-admin",
                "expression": "host_starts_with",
                "value": "admin.",
                "casesensitive": False,
                "not": True,
            }
        ]
    }
    client, transport = _client("/api/v2/services/haproxy/backend/acls?limit=100", body)
    acls = client.get_haproxy_backend_acls()
    assert len(acls) == 1
    assert acls[0].id == 1
    assert acls[0].parent_id == 0
    assert acls[0].expression == "host_starts_with"
    assert acls[0].value == "admin."
    assert acls[0].not_field is True
    assert transport.calls == [("GET", "/api/v2/services/haproxy/backend/acls?limit=100")]


def test_get_haproxy_backend_acls_rejects_limit_above_max():
    client, _ = _client("/api/v2/services/haproxy/backend/acls?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_backend_acls(limit=101)


# ---------------------------------------------------------------------------
# 4. HAProxyBackendErrorFile -- plural nested, metadata-only
# ---------------------------------------------------------------------------


def test_get_haproxy_backend_errorfiles_maps_fields():
    body = {"data": [{"id": 1, "parent_id": 0, "errorcode": 503, "errorfile": "custom_503.http"}]}
    client, transport = _client("/api/v2/services/haproxy/backend/errorfiles?limit=100", body)
    files = client.get_haproxy_backend_errorfiles()
    assert files[0].errorcode == 503
    assert files[0].errorfile == "custom_503.http"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/backend/errorfiles?limit=100")]


def test_get_haproxy_backend_errorfiles_rejects_zero_limit():
    client, _ = _client("/api/v2/services/haproxy/backend/errorfiles?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_backend_errorfiles(limit=0)


# ---------------------------------------------------------------------------
# 5. HAProxyBackendServer -- plural nested, excludes `advanced`
# ---------------------------------------------------------------------------


def test_get_haproxy_backend_servers_maps_safe_fields():
    body = {
        "data": [
            {
                "id": 1,
                "parent_id": 0,
                "name": "srv1",
                "status": "active",
                "address": "192.0.2.10",
                "port": "80",
                "weight": 10,
                "ssl": False,
                "sslserververify": False,
                "serverid": 1,
            }
        ]
    }
    client, transport = _client("/api/v2/services/haproxy/backend/servers?limit=100", body)
    servers = client.get_haproxy_backend_servers()
    assert servers[0].address == "192.0.2.10"
    assert servers[0].weight == 10
    assert transport.calls == [("GET", "/api/v2/services/haproxy/backend/servers?limit=100")]


def test_get_haproxy_backend_servers_never_exposes_advanced_even_if_present():
    body = {
        "data": [
            {
                "id": 1,
                "parent_id": 0,
                "name": "srv1",
                "advanced": "SENTINEL-SERVER-ADVANCED-CONFIG",
            }
        ]
    }
    client, _ = _client("/api/v2/services/haproxy/backend/servers?limit=100", body)
    servers = client.get_haproxy_backend_servers()
    assert not hasattr(servers[0], "advanced")
    assert "SENTINEL-SERVER-ADVANCED-CONFIG" not in servers[0].model_dump_json()


def test_get_haproxy_backend_servers_rejects_limit_above_max():
    client, _ = _client("/api/v2/services/haproxy/backend/servers?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_backend_servers(limit=101)


# ---------------------------------------------------------------------------
# 6. HAProxyFile -- plural, excludes `content`
# ---------------------------------------------------------------------------


def test_get_haproxy_files_maps_safe_fields():
    body = {"data": [{"id": 1, "name": "block.lua", "type": "luascript"}]}
    client, transport = _client("/api/v2/services/haproxy/files?limit=100", body)
    files = client.get_haproxy_files()
    assert files[0].name == "block.lua"
    assert files[0].type == "luascript"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/files?limit=100")]


def test_get_haproxy_files_never_exposes_content_even_if_present():
    body = {"data": [{"id": 1, "name": "block.lua", "type": "luascript", "content": "SENTINEL-FILE-CONTENT"}]}
    client, _ = _client("/api/v2/services/haproxy/files?limit=100", body)
    files = client.get_haproxy_files()
    assert not hasattr(files[0], "content")
    assert "SENTINEL-FILE-CONTENT" not in files[0].model_dump_json()


def test_get_haproxy_files_rejects_zero_limit():
    client, _ = _client("/api/v2/services/haproxy/files?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_files(limit=0)


# ---------------------------------------------------------------------------
# 7. HAProxyFrontend -- plural, excludes advanced_bind/advanced + 5 nested arrays
#    (ha_certificates was an implementation-time correction -- see haproxy_frontend.py)
# ---------------------------------------------------------------------------

_FRONTEND_SAFE_FIELDS = {
    "id": 1,
    "name": "web-frontend",
    "descr": "public web",
    "status": "active",
    "max_connections": 1000,
    "type": "http",
    "backend_serverpool": "lb-backend",
    "socket_stats": False,
    "client_timeout": 30,
    "forwardfor": True,
    "httpclose": "default",
    "ssloffloadcert": "abc123refid",
}

_FRONTEND_EXCLUDED_FIELDS = {
    "advanced_bind": "SENTINEL-ADVANCED-BIND",
    "advanced": "SENTINEL-FRONTEND-ADVANCED",
    "a_extaddr": [{"extaddr": "SENTINEL-NESTED-ADDRESS"}],
    "ha_acls": [{"name": "SENTINEL-NESTED-FRONTEND-ACL"}],
    "a_actionitems": [{"name": "SENTINEL-NESTED-FRONTEND-ACTION", "fmt": "SENTINEL-FRONTEND-HEADER-VALUE"}],
    "a_errorfiles": [{"errorfile": "SENTINEL-NESTED-FRONTEND-ERRORFILE"}],
    "ha_certificates": [{"ssl_certificate": "SENTINEL-NESTED-CERT"}],
}


def _frontends_body(extra: dict | None = None) -> dict:
    item = dict(_FRONTEND_SAFE_FIELDS)
    if extra:
        item.update(extra)
    return {"data": [item]}


def test_get_haproxy_frontends_maps_safe_fields():
    client, transport = _client("/api/v2/services/haproxy/frontends?limit=100", _frontends_body())
    frontends = client.get_haproxy_frontends()
    assert frontends[0].name == "web-frontend"
    assert frontends[0].ssloffloadcert == "abc123refid"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/frontends?limit=100")]


def test_get_haproxy_frontends_never_exposes_any_excluded_field_even_if_present():
    body = _frontends_body(_FRONTEND_EXCLUDED_FIELDS)
    client, _ = _client("/api/v2/services/haproxy/frontends?limit=100", body)
    frontends = client.get_haproxy_frontends()
    dumped = frontends[0].model_dump_json()
    for field, value in _FRONTEND_EXCLUDED_FIELDS.items():
        assert not hasattr(frontends[0], field), f"{field} must not exist on the model at all"
        if isinstance(value, str):
            assert value not in dumped
    for sentinel in (
        "SENTINEL-NESTED-ADDRESS",
        "SENTINEL-NESTED-FRONTEND-ACL",
        "SENTINEL-NESTED-FRONTEND-ACTION",
        "SENTINEL-FRONTEND-HEADER-VALUE",
        "SENTINEL-NESTED-FRONTEND-ERRORFILE",
        "SENTINEL-NESTED-CERT",
    ):
        assert sentinel not in dumped


def test_get_haproxy_frontends_rejects_limit_above_max():
    client, _ = _client("/api/v2/services/haproxy/frontends?limit=100", _frontends_body())
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_frontends(limit=101)


# ---------------------------------------------------------------------------
# 8. HAProxyFrontendAcl -- same shape/risk as HAProxyBackendAcl
# ---------------------------------------------------------------------------


def test_get_haproxy_frontend_acls_maps_fields_including_reserved_word_not():
    body = {
        "data": [
            {
                "id": 1,
                "parent_id": 0,
                "name": "allow-local",
                "expression": "source_ip",
                "value": "192.0.2.0/24",
                "casesensitive": False,
                "not": False,
            }
        ]
    }
    client, transport = _client("/api/v2/services/haproxy/frontend/acls?limit=100", body)
    acls = client.get_haproxy_frontend_acls()
    assert acls[0].value == "192.0.2.0/24"
    assert acls[0].not_field is False
    assert transport.calls == [("GET", "/api/v2/services/haproxy/frontend/acls?limit=100")]


def test_get_haproxy_frontend_acls_rejects_zero_limit():
    client, _ = _client("/api/v2/services/haproxy/frontend/acls?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_frontend_acls(limit=0)


# ---------------------------------------------------------------------------
# 9. HAProxyFrontendAddress -- plural nested, excludes `exaddr_advanced`
# ---------------------------------------------------------------------------


def test_get_haproxy_frontend_addresses_maps_safe_fields():
    body = {
        "data": [
            {
                "id": 1,
                "parent_id": 0,
                "extaddr": "wan_ipv4",
                "extaddr_custom": "",
                "extaddr_port": "443",
                "extaddr_ssl": True,
            }
        ]
    }
    client, transport = _client("/api/v2/services/haproxy/frontend/addresses?limit=100", body)
    addrs = client.get_haproxy_frontend_addresses()
    assert addrs[0].extaddr == "wan_ipv4"
    assert addrs[0].extaddr_ssl is True
    assert transport.calls == [("GET", "/api/v2/services/haproxy/frontend/addresses?limit=100")]


def test_get_haproxy_frontend_addresses_never_exposes_exaddr_advanced_even_if_present():
    body = {"data": [{"id": 1, "parent_id": 0, "extaddr": "wan_ipv4", "exaddr_advanced": "SENTINEL-ADDR-ADVANCED"}]}
    client, _ = _client("/api/v2/services/haproxy/frontend/addresses?limit=100", body)
    addrs = client.get_haproxy_frontend_addresses()
    assert not hasattr(addrs[0], "exaddr_advanced")
    assert "SENTINEL-ADDR-ADVANCED" not in addrs[0].model_dump_json()


def test_get_haproxy_frontend_addresses_rejects_limit_above_max():
    client, _ = _client("/api/v2/services/haproxy/frontend/addresses?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_frontend_addresses(limit=101)


# ---------------------------------------------------------------------------
# 10. HAProxyFrontendCertificate -- plural nested, safe FK reference only
# ---------------------------------------------------------------------------


def test_get_haproxy_frontend_certificates_maps_fields():
    body = {"data": [{"id": 1, "parent_id": 0, "ssl_certificate": "abc123refid"}]}
    client, transport = _client("/api/v2/services/haproxy/frontend/certificates?limit=100", body)
    certs = client.get_haproxy_frontend_certificates()
    assert certs[0].ssl_certificate == "abc123refid"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/frontend/certificates?limit=100")]


def test_get_haproxy_frontend_certificates_rejects_zero_limit():
    client, _ = _client("/api/v2/services/haproxy/frontend/certificates?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_frontend_certificates(limit=0)


# ---------------------------------------------------------------------------
# 11. HAProxyFrontendErrorFile -- plural nested, metadata-only
# ---------------------------------------------------------------------------


def test_get_haproxy_frontend_error_files_maps_fields():
    body = {"data": [{"id": 1, "parent_id": 0, "errorcode": 404, "errorfile": "custom_404.http"}]}
    client, transport = _client("/api/v2/services/haproxy/frontend/error_files?limit=100", body)
    files = client.get_haproxy_frontend_error_files()
    assert files[0].errorcode == 404
    assert transport.calls == [("GET", "/api/v2/services/haproxy/frontend/error_files?limit=100")]


def test_get_haproxy_frontend_error_files_rejects_limit_above_max():
    client, _ = _client("/api/v2/services/haproxy/frontend/error_files?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_frontend_error_files(limit=101)


# ---------------------------------------------------------------------------
# 12. HAProxySettings -- singleton, excludes advanced + dns_resolvers/email_mailers
# ---------------------------------------------------------------------------

_SETTINGS_SAFE_BODY = {
    "enable": False,
    "maxconn": None,
    "nbthread": 1,
    "hard_stop_after": "15m",
    "logfacility": "syslog",
    "loglevel": "warning",
    "resolver_retries": 3,
    "sslcompatibilitymode": "auto",
    "ssldefaultdhparam": 1024,
    "enablesync": False,
}


def test_get_haproxy_settings_maps_safe_fields():
    client, transport = _client("/api/v2/services/haproxy/settings", {"data": _SETTINGS_SAFE_BODY})
    settings = client.get_haproxy_settings()
    assert settings.enable is False
    assert settings.nbthread == 1
    assert settings.sslcompatibilitymode == "auto"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/settings")]


def test_get_haproxy_settings_never_exposes_advanced_or_nested_resolvers_mailers_even_if_present():
    body = dict(_SETTINGS_SAFE_BODY)
    body["advanced"] = "SENTINEL-SETTINGS-ADVANCED"
    body["dns_resolvers"] = [{"name": "SENTINEL-NESTED-RESOLVER"}]
    body["email_mailers"] = [{"name": "SENTINEL-NESTED-MAILER"}]
    client, _ = _client("/api/v2/services/haproxy/settings", {"data": body})
    settings = client.get_haproxy_settings()
    dumped = settings.model_dump_json()
    for field in ("advanced", "dns_resolvers", "email_mailers"):
        assert not hasattr(settings, field)
    for sentinel in ("SENTINEL-SETTINGS-ADVANCED", "SENTINEL-NESTED-RESOLVER", "SENTINEL-NESTED-MAILER"):
        assert sentinel not in dumped


def test_get_haproxy_settings_missing_data_key_raises_shape_error():
    client, _ = _client("/api/v2/services/haproxy/settings", {})
    with pytest.raises(PfSenseResponseShapeError):
        client.get_haproxy_settings()


# ---------------------------------------------------------------------------
# 13. HAProxyDnsResolver -- plural nested, no credential fields exist at all
# ---------------------------------------------------------------------------


def test_get_haproxy_dns_resolvers_maps_fields():
    body = {"data": [{"id": 1, "parent_id": 0, "name": "resolver1", "server": "192.0.2.53", "port": "53"}]}
    client, transport = _client("/api/v2/services/haproxy/settings/dns_resolvers?limit=100", body)
    resolvers = client.get_haproxy_dns_resolvers()
    assert resolvers[0].server == "192.0.2.53"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/settings/dns_resolvers?limit=100")]


def test_get_haproxy_dns_resolvers_rejects_zero_limit():
    client, _ = _client("/api/v2/services/haproxy/settings/dns_resolvers?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_dns_resolvers(limit=0)


# ---------------------------------------------------------------------------
# 14. HAProxyEmailMailer -- plural nested, no SMTP-auth fields exist at all
# ---------------------------------------------------------------------------


def test_get_haproxy_email_mailers_maps_fields():
    body = {
        "data": [
            {"id": 1, "parent_id": 0, "name": "mailer1", "mailserver": "mail.example.test", "mailserverport": "25"}
        ]
    }
    client, transport = _client("/api/v2/services/haproxy/settings/email_mailers?limit=100", body)
    mailers = client.get_haproxy_email_mailers()
    assert mailers[0].mailserver == "mail.example.test"
    assert transport.calls == [("GET", "/api/v2/services/haproxy/settings/email_mailers?limit=100")]


def test_get_haproxy_email_mailers_rejects_limit_above_max():
    client, _ = _client("/api/v2/services/haproxy/settings/email_mailers?limit=100", {"data": []})
    with pytest.raises(PfSenseRequestValidationError):
        client.get_haproxy_email_mailers(limit=101)


# ---------------------------------------------------------------------------
# Permanent regression: none of the 14 approved GET privileges aliases any
# HAProxy mutating privilege. Pinned against a live-fetched OpenAPI subset
# captured during the 2026-08-30 LAB read-only qualification ceremony.
# ---------------------------------------------------------------------------

_APPROVED_14 = (
    ("/api/v2/services/haproxy/apply", "GET"),
    ("/api/v2/services/haproxy/backends", "GET"),
    ("/api/v2/services/haproxy/backend/acls", "GET"),
    ("/api/v2/services/haproxy/backend/errorfiles", "GET"),
    ("/api/v2/services/haproxy/backend/servers", "GET"),
    ("/api/v2/services/haproxy/files", "GET"),
    ("/api/v2/services/haproxy/frontends", "GET"),
    ("/api/v2/services/haproxy/frontend/acls", "GET"),
    ("/api/v2/services/haproxy/frontend/addresses", "GET"),
    ("/api/v2/services/haproxy/frontend/certificates", "GET"),
    ("/api/v2/services/haproxy/frontend/error_files", "GET"),
    ("/api/v2/services/haproxy/settings", "GET"),
    ("/api/v2/services/haproxy/settings/dns_resolvers", "GET"),
    ("/api/v2/services/haproxy/settings/email_mailers", "GET"),
)

# The 4 rejected header-secret-channel endpoints must never be registered
# as tools -- proven separately by KNOWN_READ_TOOL_NAMES not containing
# their tool names (see test_no_rejected_or_deferred_haproxy_tool_name_is_registered
# below); this list exists only to exclude them from the "every other GET
# op is a mutating op" enumeration below.
_REJECTED_ACTION_GETS = (
    ("/api/v2/services/haproxy/backend/action", "GET"),
    ("/api/v2/services/haproxy/backend/actions", "GET"),
    ("/api/v2/services/haproxy/frontend/action", "GET"),
    ("/api/v2/services/haproxy/frontend/actions", "GET"),
)


def _load_haproxy_openapi_subset() -> dict:
    with HAPROXY_OPENAPI_SUBSET.open(encoding="utf-8") as f:
        return json.load(f)


def test_haproxy_openapi_subset_fixture_has_all_30_paths():
    schema = _load_haproxy_openapi_subset()
    assert len(schema["paths"]) == 30


def test_all_14_approved_privileges_are_source_cross_checked():
    schema = _load_haproxy_openapi_subset()
    for url, method in _APPROVED_14:
        resolved = resolve_privilege(schema, url, method)
        assert resolved.ok, f"{method} {url}: {resolved.error}"
        assert resolved.privilege is not None


def test_no_approved_haproxy_get_privilege_is_aliased_with_any_mutating_haproxy_privilege():
    schema = _load_haproxy_openapi_subset()
    approved_privileges = set()
    for url, method in _APPROVED_14:
        resolved = resolve_privilege(schema, url, method)
        assert resolved.ok
        approved_privileges.add(resolved.privilege)
    assert len(approved_privileges) == 14

    mutating_privileges = set()
    for path, methods in schema["paths"].items():
        for method in methods:
            if method.lower() == "get":
                continue
            resolved = resolve_privilege(schema, path, method.upper())
            assert resolved.ok, f"{method.upper()} {path}: {resolved.error}"
            mutating_privileges.add(resolved.privilege)

    assert len(mutating_privileges) == 61
    assert approved_privileges.isdisjoint(mutating_privileges)


def test_rejected_action_endpoints_have_their_own_distinct_privileges_not_in_approved_14():
    schema = _load_haproxy_openapi_subset()
    approved_privileges = {resolve_privilege(schema, url, method).privilege for url, method in _APPROVED_14}
    rejected_privileges = {resolve_privilege(schema, url, method).privilege for url, method in _REJECTED_ACTION_GETS}
    assert len(rejected_privileges) == 4
    assert approved_privileges.isdisjoint(rejected_privileges)


def test_no_rejected_or_deferred_haproxy_tool_name_is_registered():
    from pfsense_mcp.tools.registry import KNOWN_READ_TOOL_NAMES

    # The 4 rejected REJECT_HEADER_SECRET_CHANNEL endpoints and the 12
    # DEFER_LOW_VALUE redundant singular forms must never appear as a
    # registered tool name -- the frozen candidate set is exactly the 14
    # approved names, no more.
    never_registered = {
        "pfsense_get_haproxy_backend_action",
        "pfsense_get_haproxy_backend_actions",
        "pfsense_get_haproxy_frontend_action",
        "pfsense_get_haproxy_frontend_actions",
        "pfsense_get_haproxy_backend",
        "pfsense_get_haproxy_backend_acl",
        "pfsense_get_haproxy_backend_error_file",
        "pfsense_get_haproxy_backend_server",
        "pfsense_get_haproxy_file",
        "pfsense_get_haproxy_frontend",
        "pfsense_get_haproxy_frontend_acl",
        "pfsense_get_haproxy_frontend_address",
        "pfsense_get_haproxy_frontend_certificate",
        "pfsense_get_haproxy_frontend_error_file",
        "pfsense_get_haproxy_settings_dns_resolver",
        "pfsense_get_haproxy_settings_email_mailer",
    }
    assert never_registered.isdisjoint(KNOWN_READ_TOOL_NAMES)


def test_exactly_14_haproxy_tool_names_are_registered():
    from pfsense_mcp.tools.registry import KNOWN_READ_TOOL_NAMES

    approved_names = {
        "pfsense_get_haproxy_apply_status",
        "pfsense_get_haproxy_backends",
        "pfsense_get_haproxy_backend_acls",
        "pfsense_get_haproxy_backend_errorfiles",
        "pfsense_get_haproxy_backend_servers",
        "pfsense_get_haproxy_files",
        "pfsense_get_haproxy_frontends",
        "pfsense_get_haproxy_frontend_acls",
        "pfsense_get_haproxy_frontend_addresses",
        "pfsense_get_haproxy_frontend_certificates",
        "pfsense_get_haproxy_frontend_error_files",
        "pfsense_get_haproxy_settings",
        "pfsense_get_haproxy_dns_resolvers",
        "pfsense_get_haproxy_email_mailers",
    }
    assert approved_names.issubset(KNOWN_READ_TOOL_NAMES)
    haproxy_tool_names = {n for n in KNOWN_READ_TOOL_NAMES if "haproxy" in n}
    assert haproxy_tool_names == approved_names
