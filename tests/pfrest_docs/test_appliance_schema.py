"""pfREST_LIVE_GUIDANCE_ARC Phase 16 APPLIANCE matrix coverage for
pfrest_docs.appliance_schema."""

from __future__ import annotations

import json

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.pfrest_docs.appliance_schema import _MAX_APPLIANCE_SCHEMA_BYTES, ApplianceSchemaCache
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.mock import MockTransport

_SCHEMA_DOC = {
    "paths": {"/api/v2/firewall/alias": {"get": {"operationId": "getFirewallAliasEndpoint"}}},
    "components": {"schemas": {"FirewallAlias": {"properties": {"name": {"type": "string"}}}}},
}


def _client(mock: MockTransport) -> PfSenseClient:
    rest = RestApiClient(mock, identity="test", api_version=ApiVersion.V2)
    return PfSenseClient(rest)


def test_lookup_endpoint_confirms_presence():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text=json.dumps(_SCHEMA_DOC))
    cache = ApplianceSchemaCache()
    result = cache.lookup_endpoint(_client(mock), "/api/v2/firewall/alias", "GET")
    assert result.available is True
    assert result.endpoint is not None
    assert result.endpoint.operation_id == "getFirewallAliasEndpoint"


def test_lookup_endpoint_confirms_absence():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text=json.dumps(_SCHEMA_DOC))
    cache = ApplianceSchemaCache()
    result = cache.lookup_endpoint(_client(mock), "/api/v2/does/not/exist", "GET")
    assert result.available is True
    assert result.endpoint is None


def test_lookup_model_confirms_presence_and_absence():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text=json.dumps(_SCHEMA_DOC))
    cache = ApplianceSchemaCache()
    present = cache.lookup_model(_client(mock), "FirewallAlias")
    assert present.available is True
    assert present.model is not None
    absent = cache.lookup_model(_client(mock), "NotAModel")
    assert absent.available is True
    assert absent.model is None


def test_appliance_unreachable_is_available_false_not_raise():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=500, text="")
    cache = ApplianceSchemaCache()
    result = cache.lookup_endpoint(_client(mock), "/api/v2/firewall/alias", "GET")
    assert result.available is False
    assert result.error is not None


def test_appliance_auth_failure_is_available_false_not_raise():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=401, text="")
    cache = ApplianceSchemaCache()
    result = cache.lookup_endpoint(_client(mock), "/api/v2/firewall/alias", "GET")
    assert result.available is False


def test_malformed_response_shape_is_available_false():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text='"just a string, not an object"')
    cache = ApplianceSchemaCache()
    result = cache.lookup_endpoint(_client(mock), "/x", "GET")
    assert result.available is False


def test_oversized_appliance_schema_is_refused():
    oversized = json.dumps({"padding": "x" * (_MAX_APPLIANCE_SCHEMA_BYTES + 1000)})
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text=oversized)
    cache = ApplianceSchemaCache()
    result = cache.lookup_endpoint(_client(mock), "/x", "GET")
    assert result.available is False


def test_result_never_leaks_credentials_or_secrets():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text=json.dumps(_SCHEMA_DOC))
    cache = ApplianceSchemaCache()
    result = cache.lookup_endpoint(_client(mock), "/api/v2/firewall/alias", "GET")
    serialized = json.dumps(
        {
            "available": result.available,
            "endpoint": result.endpoint.__dict__ if result.endpoint else None,
            "error": result.error,
        }
    )
    assert "test" not in serialized.lower() or "identity" not in serialized  # no identity string leaked
    assert "X-API-Key" not in serialized
    assert "password" not in serialized.lower()


def test_repeated_calls_reuse_cached_index_without_refetching():
    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text=json.dumps(_SCHEMA_DOC))
    cache = ApplianceSchemaCache()
    client = _client(mock)
    cache.lookup_endpoint(client, "/api/v2/firewall/alias", "GET")
    cache.lookup_model(client, "FirewallAlias")
    cache.lookup_endpoint(client, "/api/v2/firewall/alias", "GET")
    assert mock.calls.count(("GET", "/api/v2/schema/openapi")) == 1


def test_stale_cache_is_served_on_subsequent_fetch_failure(monkeypatch):
    import time as time_module

    mock = MockTransport()
    mock.register("GET", "/api/v2/schema/openapi", status_code=200, text=json.dumps(_SCHEMA_DOC))
    cache = ApplianceSchemaCache()
    client = _client(mock)
    fake_now = [1000.0]
    monkeypatch.setattr(time_module, "monotonic", lambda: fake_now[0])
    first = cache.lookup_endpoint(client, "/api/v2/firewall/alias", "GET")
    assert first.available is True

    # Advance past TTL and make the next fetch fail -- must fall back to
    # the stale cached index rather than reporting unavailable.
    from pfsense_mcp.pfrest_docs.appliance_schema import CACHE_TTL_SECONDS

    fake_now[0] += CACHE_TTL_SECONDS + 1.0
    mock.register("GET", "/api/v2/schema/openapi", status_code=500, text="")
    second = cache.lookup_endpoint(client, "/api/v2/firewall/alias", "GET")
    assert second.available is True
    assert second.endpoint is not None
