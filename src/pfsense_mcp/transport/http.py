"""Real network-backed Transport implementations.

``HttpTransport`` is the normal reusable X-API-Key transport.
``BasicAuthHttpTransport`` is deliberately single-use and exists only
for ADR-033's self-service API-key bootstrap call.  Neither transport
selects an endpoint or HTTP method; those closed operations remain
owned by their callers.
"""

from __future__ import annotations

from urllib.parse import unquote, urlsplit

import httpx

from .base import (
    TransportConfigurationError,
    TransportConnectionError,
    TransportRequestNotSentError,
    TransportResponse,
    TransportTimeoutError,
)

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)


class HttpTransport:
    def __init__(self, base_url: str, api_key: str, verify: bool | str) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            verify=verify,
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        try:
            headers = {"Content-Type": "application/json"} if body is not None else None
            response = self._client.request(method, path, content=body, headers=headers)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
            raise TransportRequestNotSentError(f"Could not connect for {method} {path}") from None
        except httpx.TimeoutException:
            raise TransportTimeoutError(f"Request timed out for {method} {path}") from None
        except httpx.TransportError:
            raise TransportConnectionError(f"Transport failed for {method} {path}") from None
        return TransportResponse(status_code=response.status_code, text=response.text)

    def close(self) -> None:
        self._client.close()


def _contains_header_unsafe_character(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_basic_auth_target(base_url: str, verify: bool | str) -> None:
    """Fail closed before credentials can be attached to an unsafe target."""

    if not isinstance(base_url, str) or base_url != base_url.strip() or not base_url:
        raise TransportConfigurationError("Basic Auth target URL is invalid.")
    if _contains_header_unsafe_character(base_url) or _contains_header_unsafe_character(unquote(base_url)):
        raise TransportConfigurationError("Basic Auth target URL is invalid.")
    try:
        parsed = urlsplit(base_url)
        _port = parsed.port
    except ValueError:
        raise TransportConfigurationError("Basic Auth target URL is invalid.") from None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise TransportConfigurationError("Basic Auth target must be an HTTPS origin without embedded credentials.")
    if verify is False or (isinstance(verify, str) and not verify):
        raise TransportConfigurationError("Basic Auth requires TLS certificate verification.")
    if not isinstance(verify, (bool, str)):
        raise TransportConfigurationError("Basic Auth TLS verification configuration is invalid.")


def _validate_basic_auth_credentials(username: str, password: str) -> None:
    if (
        not isinstance(username, str)
        or not username
        or username != username.strip()
        or ":" in username
        or _contains_header_unsafe_character(username)
    ):
        raise TransportConfigurationError("Basic Auth username is invalid.")
    if (
        not isinstance(password, str)
        or not password
        or password != password.strip()
        or _contains_header_unsafe_character(password)
    ):
        raise TransportConfigurationError("Basic Auth password is invalid.")


class BasicAuthHttpTransport:
    """Single-use HTTPS Basic-Auth transport for one bootstrap request.

    The single-attempt contract matches ``security_bootstrap_engine``:
    its self-service factory creates one transport solely for
    ``BootstrapProvisioningClient.create_auth_key()``.  Closing and
    dropping the client in ``request()`` avoids adding close ownership
    to the existing ``Transport`` protocol and mechanically prevents a
    retry or a second endpoint call with the transient password.
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool | str) -> None:
        _validate_basic_auth_target(base_url, verify)
        _validate_basic_auth_credentials(username, password)
        try:
            self._client: httpx.Client | None = httpx.Client(
                base_url=base_url,
                verify=verify,
                auth=httpx.BasicAuth(username, password),
                headers={"Accept": "application/json"},
                timeout=_TIMEOUT,
                follow_redirects=False,
            )
        except (TypeError, ValueError):
            raise TransportConfigurationError("Basic Auth transport configuration is invalid.") from None

    def __repr__(self) -> str:
        return "BasicAuthHttpTransport(single_use=True)"

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        client = self._client
        if client is None:
            raise TransportConfigurationError("Basic Auth transport is single-use and has already been consumed.")
        self._client = None
        request_failed = True
        try:
            headers = {"Content-Type": "application/json"} if body is not None else None
            response = client.request(method, path, content=body, headers=headers)
            request_failed = False
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
            raise TransportRequestNotSentError("Basic Auth request could not connect") from None
        except httpx.TimeoutException:
            raise TransportTimeoutError("Basic Auth request timed out") from None
        except httpx.TransportError:
            raise TransportConnectionError("Basic Auth request transport failed") from None
        finally:
            try:
                client.close()
            except Exception:  # the configured httpx transport may raise an arbitrary close error
                if not request_failed:
                    raise TransportConnectionError("Basic Auth transport close failed") from None
        return TransportResponse(status_code=response.status_code, text=response.text)

    def close(self) -> None:
        """Discard an unused transport without sending anything."""

        client = self._client
        self._client = None
        if client is not None:
            try:
                client.close()
            except Exception:
                raise TransportConnectionError("Transport close failed before use") from None
