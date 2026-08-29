"""Real network-backed Transport implementations.

``HttpTransport`` is the normal reusable X-API-Key transport.
``BasicAuthHttpTransport`` is deliberately single-use and exists only
for ADR-033's self-service API-key bootstrap call.  Neither transport
selects an endpoint or HTTP method; those closed operations remain
owned by their callers.
"""

from __future__ import annotations

import ssl
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

# v1.0.0 Product/UX arc (UX-D): httpx/httpcore collapse DNS failure,
# "connection refused", and a TLS handshake/certificate-verification
# failure into the exact same `httpx.ConnectError` -- confirmed live
# against real hosts: httpcore never preserves the underlying
# `ssl.SSLError` as a distinct type through its own wrapping (its
# `__cause__` is `None`), only in the message text ("[SSL:
# CERTIFICATE_VERIFY_FAILED] ..." vs "[Errno -2] Name or service not
# known" vs "[Errno 111] Connection refused"). This message-only
# classification exists purely to make the distinction mission text
# asks for readable to a human; it changes no exception class, no
# control flow, and no security-relevant behavior anywhere -- a
# classification miss (an unrecognized message shape) silently falls
# back to the prior generic wording rather than misclassifying.
_TLS_FAILURE_MARKERS = ("ssl", "certificate", "cert_verify", "certificate_verify")

# v1.0.0 clean-room finding (2026-08-29): a real LAB target with a
# valid, correctly-trusted private-CA certificate produced only "TLS
# certificate verification failed -- the server's certificate could
# not be verified" when connected to by IP address instead of its
# certificate's own DNS name -- concealing the actually useful
# distinction (independently confirmed via `openssl s_client
# -verify_return_error`: trust chain verified fine, "IP address
# mismatch" specifically). `exc.__cause__` (what httpcore/httpx
# themselves expose) never carries this detail -- confirmed above --
# but `exc.__context__` still does: Python's interpreter sets
# `__context__` to whatever exception was active whenever a new one is
# raised inside an `except` block, and this happens unconditionally,
# regardless of an explicit `raise ... from None` (that only clears
# `__cause__` and suppresses *traceback display* of the context, never
# the `__context__` attribute itself -- PEP 3134). Verified directly:
# a real `ssl.SSLCertVerificationError` (with real, populated
# `.verify_code`/`.verify_message`) is reachable a few `__context__`
# hops down from httpx's own `ConnectError`, through httpcore's own
# `ConnectError` wrapping, in the exact live scenario above. `verify_code`
# is a standard, stable OpenSSL `X509_V_ERR_*` numeric constant (not
# httpx/httpcore's own API, and not parsed from English prose) --
# empirically confirmed for the hostname-mismatch (62), IP-mismatch
# (64), and untrusted-CA (20, "unable to get local issuer certificate")
# cases against this exact codebase's own transport; the
# expired/not-yet-valid codes (10/9) are long-standing, unchanged
# OpenSSL constants documented since early `openssl/x509_vfy.h` and are
# included on that same structural basis, not re-derived from a live
# expired-certificate probe this session.
#
# This is a diagnostic-message improvement only: it never changes
# whether a connection is accepted, never weakens verification, and
# never falls back to guessing -- `_classify_ssl_verification_error()`
# returns `None` (not a wrong classification) for any `verify_code` it
# does not specifically recognize, or if no `ssl.SSLCertVerificationError`
# is found in the (bounded) `__context__` walk at all -- e.g. a future
# httpx/httpcore release that stops setting `__context__` this way, or
# a non-CPython `ssl` implementation without `.verify_code`. Either way
# `_classify_connect_failure()` below falls back to the pre-existing,
# already-tested marker-based classification, exactly as it always did.
_TLS_HOSTNAME_IDENTITY_MISMATCH_CODES = frozenset({62, 64})  # HOSTNAME_MISMATCH, IP_ADDRESS_MISMATCH
# self-signed / unable-to-get-issuer / untrusted-chain family
_TLS_UNTRUSTED_CA_CODES = frozenset({18, 19, 20, 21, 24, 27, 33})
_TLS_CERT_NOT_YET_VALID_CODE = 9
_TLS_CERT_EXPIRED_CODE = 10
_MAX_EXCEPTION_CONTEXT_WALK_DEPTH = 8


def _classify_ssl_verification_error(exc: BaseException) -> str | None:
    """Walks `exc.__context__` (bounded depth) for the real
    `ssl.SSLCertVerificationError` Python's own TLS stack raised, and
    turns its structured `.verify_code`/`.verify_message` into a
    specific, actionable distinction. Returns `None` -- never a guess
    -- if no such exception is found, or its `verify_code` is not one
    of the specific families recognized above; see this module's own
    top-level comment for what was actually verified and how."""

    current: BaseException | None = exc
    for _ in range(_MAX_EXCEPTION_CONTEXT_WALK_DEPTH):
        if current is None:
            return None
        if isinstance(current, ssl.SSLCertVerificationError):
            code = current.verify_code
            detail = (current.verify_message or "").strip()
            if code in _TLS_HOSTNAME_IDENTITY_MISMATCH_CODES:
                return (
                    "the certificate authority is trusted, but the certificate is not valid for the "
                    f"address you connected to ({detail or 'hostname/IP mismatch'}) -- connect using "
                    "the exact hostname the certificate was issued for instead"
                )
            if code in _TLS_UNTRUSTED_CA_CODES:
                return (
                    "the certificate authority that signed the server's certificate is not trusted "
                    f"({detail or 'unable to verify the certificate chain'}) -- for a private/internal "
                    "CA, verify PFSENSE_TLS_CA_FILE points at its own public certificate"
                )
            if code == _TLS_CERT_EXPIRED_CODE:
                return f"the server's certificate has expired ({detail or 'certificate has expired'})"
            if code == _TLS_CERT_NOT_YET_VALID_CODE:
                return f"the server's certificate is not yet valid ({detail or 'certificate is not yet valid'})"
            return None
        current = current.__context__
    return None


def _classify_connect_failure(exc: BaseException) -> str:
    structured = _classify_ssl_verification_error(exc)
    if structured is not None:
        return structured
    text = f"{exc} {exc.__cause__}".lower()
    if any(marker in text for marker in _TLS_FAILURE_MARKERS):
        return "TLS certificate verification failed -- the server's certificate could not be verified"
    if "name or service not known" in text or "nodename nor servname" in text or "getaddrinfo failed" in text:
        return "the hostname could not be resolved (DNS lookup failed)"
    if "connection refused" in text:
        return "the host refused the connection (nothing is listening on that address/port)"
    return "the host could not be reached"


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
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            detail = _classify_connect_failure(exc)
            raise TransportRequestNotSentError(f"Could not connect for {method} {path}: {detail}") from None
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
