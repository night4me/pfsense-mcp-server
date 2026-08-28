"""Integration coverage for PfRestDocumentationProvider, via respx --
never touches the real network."""

from __future__ import annotations

import httpx
import respx

from pfsense_mcp.pfrest_docs.guide_topics import GuideTopic
from pfsense_mcp.pfrest_docs.models import FreshnessState
from pfsense_mcp.pfrest_docs.provider import OPENAPI_URL, PfRestDocumentationProvider

_DOC = {
    "paths": {"/api/v2/firewall/alias": {"get": {"operationId": "getFirewallAliasEndpoint"}}},
    "components": {"schemas": {"FirewallAlias": {"properties": {"name": {"type": "string"}}}}},
}


@respx.mock
def test_lookup_endpoint_fetches_and_caches():
    route = respx.get(OPENAPI_URL).mock(
        return_value=httpx.Response(
            200, headers={"content-type": "application/json", "cache-control": "max-age=600"}, json=_DOC
        )
    )
    provider = PfRestDocumentationProvider()
    first = provider.lookup_endpoint("/api/v2/firewall/alias", "GET")
    assert first.value is not None
    assert first.freshness == FreshnessState.FRESH
    second = provider.lookup_endpoint("/api/v2/firewall/alias", "GET")
    assert second.value is not None
    assert route.call_count == 1  # cached, not refetched


@respx.mock
def test_lookup_model_uses_same_cached_document():
    respx.get(OPENAPI_URL).mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, json=_DOC)
    )
    provider = PfRestDocumentationProvider()
    provider.lookup_endpoint("/api/v2/firewall/alias", "GET")
    model = provider.lookup_model("FirewallAlias")
    assert model.value is not None
    assert model.value.name == "FirewallAlias"


@respx.mock
def test_lookup_endpoint_unknown_path_returns_none_value_but_fresh():
    respx.get(OPENAPI_URL).mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, json=_DOC)
    )
    provider = PfRestDocumentationProvider()
    result = provider.lookup_endpoint("/api/v2/does/not/exist", "GET")
    assert result.value is None
    assert result.freshness == FreshnessState.FRESH


@respx.mock
def test_upstream_unavailable_returns_none_with_correct_state():
    respx.get(OPENAPI_URL).mock(return_value=httpx.Response(500))
    provider = PfRestDocumentationProvider()
    result = provider.lookup_endpoint("/x", "GET")
    assert result.value is None
    assert result.freshness == FreshnessState.UPSTREAM_UNAVAILABLE


@respx.mock
def test_malformed_json_document_is_corrupt_not_a_crash():
    respx.get(OPENAPI_URL).mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, text="not json")
    )
    provider = PfRestDocumentationProvider()
    result = provider.lookup_endpoint("/x", "GET")
    assert result.value is None
    assert result.freshness == FreshnessState.CORRUPT


@respx.mock
def test_lookup_guide_topic_fetches_and_extracts_excerpt():
    html = '<div role="main" class="document">Auth guide content here.</div><div class="rst-footer-buttons"></div>'
    respx.get("https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html)
    )
    provider = PfRestDocumentationProvider()
    result = provider.lookup_guide_topic(GuideTopic.AUTHENTICATION_AND_AUTHORIZATION)
    assert result.value is not None
    assert "Auth guide content here." in result.value


@respx.mock
def test_lookup_guide_topic_serves_stale_on_refetch_failure(monkeypatch):
    """v0.9.0 RC audit: coverage gap found -- lookup_guide_topic() has
    its own inline stale-fallback block (distinct from _get_index()'s,
    which test_stale_but_usable_served_when_refetch_fails below already
    covers for lookup_endpoint/lookup_model) that was untested. Closes
    it, plus the fully-unavailable-with-no-stale-entry branch."""

    import time as time_module

    url = "https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/"
    html = '<div role="main" class="document">Auth guide content here.</div><div class="rst-footer-buttons"></div>'
    route = respx.get(url).mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html", "cache-control": "max-age=1"}, text=html)
    )
    provider = PfRestDocumentationProvider()
    fake_now = [1000.0]
    monkeypatch.setattr(time_module, "monotonic", lambda: fake_now[0])

    first = provider.lookup_guide_topic(GuideTopic.AUTHENTICATION_AND_AUTHORIZATION)
    assert first.freshness == FreshnessState.FRESH

    fake_now[0] += 2.0  # past the 1s TTL
    route.mock(return_value=httpx.Response(500))
    second = provider.lookup_guide_topic(GuideTopic.AUTHENTICATION_AND_AUTHORIZATION)
    assert second.value is not None
    assert "Auth guide content here." in second.value
    assert second.freshness == FreshnessState.STALE_BUT_USABLE


@respx.mock
def test_lookup_guide_topic_unavailable_with_no_prior_cache_entry():
    respx.get("https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/").mock(return_value=httpx.Response(500))
    provider = PfRestDocumentationProvider()
    result = provider.lookup_guide_topic(GuideTopic.AUTHENTICATION_AND_AUTHORIZATION)
    assert result.value is None
    assert result.freshness == FreshnessState.UPSTREAM_UNAVAILABLE


@respx.mock
def test_stale_but_usable_served_when_refetch_fails(monkeypatch):
    import time as time_module

    route = respx.get(OPENAPI_URL).mock(
        return_value=httpx.Response(
            200, headers={"content-type": "application/json", "cache-control": "max-age=1"}, json=_DOC
        )
    )
    provider = PfRestDocumentationProvider()
    fake_now = [1000.0]
    monkeypatch.setattr(time_module, "monotonic", lambda: fake_now[0])
    first = provider.lookup_endpoint("/api/v2/firewall/alias", "GET")
    assert first.freshness == FreshnessState.FRESH

    fake_now[0] += 2.0  # past the 1s TTL
    route.mock(return_value=httpx.Response(500))
    second = provider.lookup_endpoint("/api/v2/firewall/alias", "GET")
    assert second.value is not None
    assert second.freshness == FreshnessState.STALE_BUT_USABLE
