"""Bounded, allowlisted HTTPS GET-only fetcher for the pfREST upstream
documentation site (pfREST_LIVE_GUIDANCE_ARC Phase 3/4).

This is the ONLY module in this package that performs network I/O, and
the only module in the whole codebase allowed to speak to a
public-internet host outside pfSense itself. Deliberately narrow --
this is not a generic web-fetch primitive:

- **HTTPS only, GET only.** No other scheme or method is representable
  by this module's public function.
- **Fixed exact-host allowlist** (`ALLOWED_HOSTS`), never a
  caller-supplied host, never a suffix/wildcard match. `www.pfrest.org`
  is deliberately NOT in the allowlist even though it currently
  redirects to `pfrest.org` (verified live, 2026-08-28) -- this module
  never originates a request to it, so that redirect is never
  encountered by this code, only by prior manual research.
- **At most one redirect, and only to a URL whose host is also in the
  allowlist.** A redirect to any other host is refused, not silently
  followed and not silently downgraded to the original response.
- **Streamed, byte-counted response reading with a hard cap
  (`MAX_RESPONSE_BYTES`).** Never trusts `Content-Length` alone (a
  response can omit or lie about it) -- the cap is enforced against
  bytes actually read, aborting the read (not merely truncating the
  result) the moment the cap is exceeded.
- **Content-Type allowlist** (`application/json`, `text/html` only).
  Anything else is refused before the body is used for anything.
- **No credentials, no cookies, no caller-supplied headers.** The only
  headers this module ever sends are a fixed `Accept` value the caller
  selects from a closed set, and a fixed, descriptive `User-Agent`.
- **Explicit connect/read timeouts**, short enough that one hung
  upstream request cannot meaningfully stall an MCP tool call.
- **Fails closed.** Every failure mode raises a narrow `FetchError`
  subclass with a short, fixed message -- never a partial/best-effort
  result, never a raw upstream exception or response body leaked to
  the caller.

Nothing here is called at import time or MCP server startup -- see this
package's own `__init__.py` docstring.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from urllib.parse import urljoin, urlsplit

import httpx

#: Exact-match only -- never a suffix or wildcard match. A change to
#: this set is a reviewed, deliberate diff (mirrors
#: `pfsense_mcp.guidance.models.ALLOWED_DOCUMENT_HOSTS`'s own discipline
#: for a different, unrelated host).
ALLOWED_HOSTS: frozenset[str] = frozenset({"pfrest.org"})

#: 8 MiB: comfortably above the full public OpenAPI document (~4.2 MiB,
#: measured live 2026-08-28) with headroom for upstream growth, while
#: still bounding worst-case memory use for a single fetch.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 15.0

#: The only two content-types this package ever expects: the OpenAPI
#: document (`application/json`) and a guide-topic HTML page
#: (`text/html`). Anything else (an image, a redirect to a login page,
#: a misconfigured upstream) is refused before any parsing is attempted.
ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset({"application/json", "text/html"})

_USER_AGENT = "pfsense-mcp-server-pfrest-docs/1 (+https://github.com/night4me/pfsense-mcp-server)"


class FetchError(Exception):
    """Base class for every failure this module can raise. Callers
    should catch this one class, not its subclasses individually,
    unless they specifically need to distinguish failure modes --
    every subclass carries a short, fixed, non-leaking message."""


class FetchDisallowedURLError(FetchError):
    """The requested (or a redirect target) URL is not https, or its
    host is not in `ALLOWED_HOSTS`."""


class FetchTooManyRedirectsError(FetchError):
    """More than one redirect was returned."""


class FetchOversizedResponseError(FetchError):
    """The response body exceeded `MAX_RESPONSE_BYTES`."""


class FetchContentTypeError(FetchError):
    """The response's Content-Type is not in `ALLOWED_CONTENT_TYPES`."""


class FetchNetworkError(FetchError):
    """A connection, timeout, or other transport-level failure."""


class FetchStatusError(FetchError):
    """The response's HTTP status was not 200."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Unexpected HTTP status {status_code}")


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int
    content_type: str
    body: str
    content_hash: str
    fetched_at: str
    cache_control: str | None
    etag: str | None
    last_modified: str | None


def _validate_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchDisallowedURLError(f"URL scheme must be https, got {parts.scheme!r}")
    if parts.hostname not in ALLOWED_HOSTS:
        raise FetchDisallowedURLError(f"Host {parts.hostname!r} is not in the allowlist {sorted(ALLOWED_HOSTS)}")


def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise FetchOversizedResponseError(f"Response exceeded {MAX_RESPONSE_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _get_once(client: httpx.Client, url: str, *, accept: str) -> httpx.Response:
    try:
        with client.stream("GET", url, headers={"Accept": accept}) as response:
            body = _read_bounded(response)
            # `iter_bytes()` already transparently decompresses per the
            # original Content-Encoding; the headers copied onto the
            # reconstructed Response below must drop content-encoding/
            # content-length (now stale/wrong for the decompressed body)
            # or httpx tries to decompress the already-decompressed body
            # a second time and raises a DecodingError.
            headers = [
                (name, value)
                for name, value in response.headers.raw
                if name.lower() not in (b"content-encoding", b"content-length")
            ]
            # The streamed Response is closed at the end of this `with`
            # block; construct a fresh, fully-materialized Response so the
            # caller can read status/headers/content after it returns.
            return httpx.Response(
                status_code=response.status_code,
                headers=headers,
                content=body,
                request=response.request,
            )
    except httpx.TimeoutException:
        raise FetchNetworkError(f"Timed out fetching {url}") from None
    except FetchOversizedResponseError:
        raise
    except httpx.TransportError:
        raise FetchNetworkError(f"Network error fetching {url}") from None


def fetch(url: str, *, accept: str) -> FetchResult:
    """One bounded, allowlisted HTTPS GET, following at most one
    same-allowlist redirect. Raises a `FetchError` subclass on any
    failure -- never returns a partial result."""

    _validate_url(url)
    timeout = httpx.Timeout(
        connect=CONNECT_TIMEOUT_SECONDS,
        read=READ_TIMEOUT_SECONDS,
        write=CONNECT_TIMEOUT_SECONDS,
        pool=CONNECT_TIMEOUT_SECONDS,
    )
    with httpx.Client(timeout=timeout, follow_redirects=False, headers={"User-Agent": _USER_AGENT}) as client:
        response = _get_once(client, url, accept=accept)
        final_url = url

        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location")
            if not location:
                raise FetchDisallowedURLError("Redirect response had no Location header")
            redirect_url = urljoin(url, location)
            _validate_url(redirect_url)
            response = _get_once(client, redirect_url, accept=accept)
            final_url = redirect_url
            if response.status_code in (301, 302, 303, 307, 308):
                raise FetchTooManyRedirectsError("More than one redirect encountered")

        if response.status_code != 200:
            raise FetchStatusError(response.status_code)

        content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in ALLOWED_CONTENT_TYPES:
            raise FetchContentTypeError(f"Unexpected content-type {content_type!r} from {final_url}")

        body_bytes = response.content
        try:
            body = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise FetchContentTypeError(f"Response from {final_url} was not valid UTF-8") from None

        return FetchResult(
            url=final_url,
            status_code=response.status_code,
            content_type=content_type,
            body=body,
            content_hash=sha256(body_bytes).hexdigest(),
            fetched_at=datetime.now(timezone.utc).isoformat(),
            cache_control=response.headers.get("cache-control"),
            etag=response.headers.get("etag"),
            last_modified=response.headers.get("last-modified"),
        )
