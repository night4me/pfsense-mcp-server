"""Adversarial coverage for pfrest_docs.fetch (pfREST_LIVE_GUIDANCE_ARC
Phase 16 NETWORK matrix). Every scenario is simulated via respx --
never touches the real network."""

from __future__ import annotations

import httpx
import pytest
import respx

from pfsense_mcp.pfrest_docs import fetch


@respx.mock
def test_fetch_succeeds_for_allowlisted_https_host():
    respx.get("https://pfrest.org/api-docs/openapi.json").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, text='{"openapi":"3.0.0"}')
    )
    result = fetch.fetch("https://pfrest.org/api-docs/openapi.json", accept="application/json")
    assert result.status_code == 200
    assert result.body == '{"openapi":"3.0.0"}'
    assert result.content_hash


def test_fetch_rejects_non_https_scheme():
    with pytest.raises(fetch.FetchDisallowedURLError):
        fetch.fetch("http://pfrest.org/api-docs/openapi.json", accept="application/json")


def test_fetch_rejects_disallowed_host():
    with pytest.raises(fetch.FetchDisallowedURLError):
        fetch.fetch("https://evil.example/api-docs/openapi.json", accept="application/json")


def test_fetch_rejects_host_similar_to_allowlist():
    """Suffix/prefix confusion: neither a subdomain nor a lookalike
    domain is in the allowlist -- exact match only."""
    for url in (
        "https://pfrest.org.evil.example/x",
        "https://evil-pfrest.org/x",
        "https://notpfrest.org/x",
        "https://pfrest.org.evil.com/x",
    ):
        with pytest.raises(fetch.FetchDisallowedURLError):
            fetch.fetch(url, accept="application/json")


@respx.mock
def test_fetch_follows_one_same_host_redirect():
    respx.get("https://pfrest.org/old-path").mock(
        return_value=httpx.Response(301, headers={"location": "https://pfrest.org/new-path"})
    )
    respx.get("https://pfrest.org/new-path").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text="<html>ok</html>")
    )
    result = fetch.fetch("https://pfrest.org/old-path", accept="text/html")
    assert result.url == "https://pfrest.org/new-path"
    assert result.body == "<html>ok</html>"


@respx.mock
def test_fetch_rejects_redirect_to_disallowed_host():
    respx.get("https://pfrest.org/old-path").mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.example/steal"})
    )
    with pytest.raises(fetch.FetchDisallowedURLError):
        fetch.fetch("https://pfrest.org/old-path", accept="text/html")


@respx.mock
def test_fetch_rejects_redirect_to_http_downgrade():
    respx.get("https://pfrest.org/old-path").mock(
        return_value=httpx.Response(302, headers={"location": "http://pfrest.org/new-path"})
    )
    with pytest.raises(fetch.FetchDisallowedURLError):
        fetch.fetch("https://pfrest.org/old-path", accept="text/html")


@respx.mock
def test_fetch_rejects_more_than_one_redirect():
    respx.get("https://pfrest.org/a").mock(
        return_value=httpx.Response(301, headers={"location": "https://pfrest.org/b"})
    )
    respx.get("https://pfrest.org/b").mock(
        return_value=httpx.Response(301, headers={"location": "https://pfrest.org/c"})
    )
    with pytest.raises(fetch.FetchTooManyRedirectsError):
        fetch.fetch("https://pfrest.org/a", accept="text/html")


@respx.mock
def test_fetch_rejects_redirect_with_no_location_header():
    respx.get("https://pfrest.org/a").mock(return_value=httpx.Response(301))
    with pytest.raises(fetch.FetchDisallowedURLError):
        fetch.fetch("https://pfrest.org/a", accept="text/html")


@respx.mock
def test_fetch_rejects_oversized_response():
    huge_body = "x" * (fetch.MAX_RESPONSE_BYTES + 1)
    respx.get("https://pfrest.org/big").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, text=huge_body)
    )
    with pytest.raises(fetch.FetchOversizedResponseError):
        fetch.fetch("https://pfrest.org/big", accept="application/json")


@respx.mock
def test_fetch_accepts_response_at_exactly_the_boundary():
    body = "x" * fetch.MAX_RESPONSE_BYTES
    respx.get("https://pfrest.org/exact").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, text=body)
    )
    result = fetch.fetch("https://pfrest.org/exact", accept="application/json")
    assert len(result.body) == fetch.MAX_RESPONSE_BYTES


@respx.mock
def test_fetch_rejects_unexpected_content_type():
    respx.get("https://pfrest.org/image").mock(
        return_value=httpx.Response(200, headers={"content-type": "image/png"}, content=b"\x89PNG")
    )
    with pytest.raises(fetch.FetchContentTypeError):
        fetch.fetch("https://pfrest.org/image", accept="application/json")


@respx.mock
def test_fetch_rejects_content_type_with_charset_suffix_only_if_base_type_wrong():
    respx.get("https://pfrest.org/ok").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json; charset=utf-8"}, text="{}")
    )
    result = fetch.fetch("https://pfrest.org/ok", accept="application/json")
    assert result.content_type == "application/json"


@respx.mock
def test_fetch_rejects_non_200_status():
    respx.get("https://pfrest.org/missing").mock(
        return_value=httpx.Response(404, headers={"content-type": "text/html"}, text="not found")
    )
    with pytest.raises(fetch.FetchStatusError) as exc_info:
        fetch.fetch("https://pfrest.org/missing", accept="text/html")
    assert exc_info.value.status_code == 404


@respx.mock
def test_fetch_rejects_server_error_status():
    respx.get("https://pfrest.org/broken").mock(return_value=httpx.Response(500))
    with pytest.raises(fetch.FetchStatusError):
        fetch.fetch("https://pfrest.org/broken", accept="text/html")


@respx.mock
def test_fetch_maps_timeout_to_fetch_network_error():
    respx.get("https://pfrest.org/slow").mock(side_effect=httpx.ConnectTimeout("timed out"))
    with pytest.raises(fetch.FetchNetworkError):
        fetch.fetch("https://pfrest.org/slow", accept="application/json")


@respx.mock
def test_fetch_maps_transport_error_to_fetch_network_error():
    respx.get("https://pfrest.org/down").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(fetch.FetchNetworkError):
        fetch.fetch("https://pfrest.org/down", accept="application/json")


@respx.mock
def test_fetch_rejects_non_utf8_body():
    respx.get("https://pfrest.org/binary").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, content=b"\xff\xfe\x00\x01")
    )
    with pytest.raises(fetch.FetchContentTypeError):
        fetch.fetch("https://pfrest.org/binary", accept="application/json")


@respx.mock
def test_fetch_never_sends_cookies_or_caller_headers():
    route = respx.get("https://pfrest.org/api-docs/openapi.json").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, text="{}")
    )
    fetch.fetch("https://pfrest.org/api-docs/openapi.json", accept="application/json")
    sent = route.calls.last.request
    assert "cookie" not in {k.lower() for k in sent.headers}
    assert "authorization" not in {k.lower() for k in sent.headers}
    assert sent.headers["User-Agent"] == fetch._USER_AGENT


@respx.mock
def test_fetch_preserves_cache_headers_for_the_caller():
    respx.get("https://pfrest.org/api-docs/openapi.json").mock(
        return_value=httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "cache-control": "max-age=600",
                "etag": '"abc123"',
                "last-modified": "Sun, 23 Aug 2026 15:59:54 GMT",
            },
            text="{}",
        )
    )
    result = fetch.fetch("https://pfrest.org/api-docs/openapi.json", accept="application/json")
    assert result.cache_control == "max-age=600"
    assert result.etag == '"abc123"'
    assert result.last_modified == "Sun, 23 Aug 2026 15:59:54 GMT"
