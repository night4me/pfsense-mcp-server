"""NexusTransport -- READ-only, device-scoped HTTP transport (Phase F,
ADR-032).

Exactly one public method, `get_json()`, and it only accepts a
`NexusEndpointInfo` instance -- never a caller-supplied raw path
string. This is the same allow-list discipline `Endpoints`/
`EndpointInfo` already enforce for the community backend
(`endpoints.py`, `rest_api_client.py`): the set of Nexus paths this
class can ever reach is exactly the set of `NexusEndpoints` attributes
below, not arbitrary caller input. No method on this class accepts an
HTTP method argument, and no POST/PUT/PATCH/DELETE method exists
anywhere on it -- those verbs exist only inside `NexusSession`, scoped
to `/login` and `/login/refresh`.

TLS verification defaults to strict (the `verify` parameter mirrors
`tls.py::resolve_verify()`'s exact return shape, `bool | str`) --
Netgate's own official examples disable verification
(`verify_ssl=False`) on every client they construct; this project
explicitly does not inherit that default (ADR-032 Section 3). Redirect
-following is disabled (matching the generated `pfapi` client's own
default, confirmed this phase) and no retry is performed (also
confirmed this phase: the generated client issues one unwrapped
request with no retry wrapper).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ...errors import PfSenseAPIError, PfSenseConnectionError, PfSenseResponseShapeError
from .routing import build_device_base_path

logger = logging.getLogger("pfsense_mcp.backends.nexus.transport")


class _TokenProvider(Protocol):
    """What NexusTransport actually needs from a session -- exactly
    one method, matching this project's own established narrow-
    Protocol dependency-injection pattern (backends/ports.py). Typed
    against this instead of the concrete NexusSession class so tests
    can inject a minimal fake without constructing a real session, and
    so this module never needs to import session.py at all (no
    coupling beyond the one method it actually calls)."""

    def get_valid_access_token(self) -> str: ...


@dataclass(frozen=True)
class NexusEndpointInfo:
    """One allowed Nexus READ endpoint, relative to the device-scoped
    base path `NexusTransport` is constructed with."""

    path_suffix: str  # e.g. "/services/carp/status" -- no device/api prefix


class NexusEndpoints:
    """The complete, exact allow-list of Nexus paths this transport
    may ever reach. Mirrors `Endpoints` (community backend) exactly."""

    CARP_STATUS = NexusEndpointInfo(path_suffix="/services/carp/status")


class NexusTransport:
    """GET-only. Owns no credential directly -- takes a `NexusSession`
    and asks it for a token immediately before each request, so no
    token is ever stored on this class's own instance state (nothing
    for a `NexusTransport` repr/log line to leak even by accident)."""

    def __init__(
        self,
        *,
        controller_url: str,
        device_type: str,
        device_id: str,
        session: _TokenProvider,
        verify: bool | str = True,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        # Fails closed on a malformed device_type/device_id before any
        # client is constructed -- see routing.py.
        device_base_path = build_device_base_path(device_type, device_id)
        self._session = session
        self._device_type = device_type
        self._device_id = device_id
        self._client = httpx.Client(
            base_url=controller_url.rstrip("/") + device_base_path,
            verify=verify,
            follow_redirects=False,
            timeout=timeout or httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
        )

    def __repr__(self) -> str:
        return f"NexusTransport(device_type={self._device_type!r}, device_id={self._device_id!r})"

    def close(self) -> None:
        self._client.close()

    def get_json(self, endpoint: NexusEndpointInfo) -> dict[str, Any]:
        if not isinstance(endpoint, NexusEndpointInfo):
            # Structural guard, not just a type hint: a caller passing
            # a raw string (bypassing the allow-list) must fail
            # immediately rather than be silently accepted.
            raise TypeError("NexusTransport.get_json() requires a NexusEndpointInfo, not a raw path.")

        token = self._session.get_valid_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        start = time.monotonic()
        try:
            response = self._client.get(endpoint.path_suffix, headers=headers)
        except httpx.TimeoutException:
            logger.warning("nexus_get_timeout device_id=%s path=%s", self._device_id, endpoint.path_suffix)
            raise PfSenseConnectionError(f"Nexus request to {endpoint.path_suffix} timed out.") from None
        except httpx.TransportError:
            logger.warning("nexus_get_connection_error device_id=%s path=%s", self._device_id, endpoint.path_suffix)
            raise PfSenseConnectionError(f"Could not connect to Nexus for {endpoint.path_suffix}.") from None

        duration_ms = (time.monotonic() - start) * 1000

        if response.status_code != 200:
            logger.warning(
                "nexus_get_error device_id=%s path=%s status=%s duration_ms=%.1f",
                self._device_id,
                endpoint.path_suffix,
                response.status_code,
                duration_ms,
            )
            raise PfSenseAPIError(response.status_code, "Nexus API returned an error status.")

        try:
            body = response.json()
        except ValueError:
            raise PfSenseResponseShapeError(f"Nexus {endpoint.path_suffix} response was not valid JSON.") from None

        if not isinstance(body, dict):
            raise PfSenseResponseShapeError(f"Nexus {endpoint.path_suffix} response was not a JSON object.")

        logger.info(
            "nexus_get_success device_id=%s path=%s status=%s duration_ms=%.1f",
            self._device_id,
            endpoint.path_suffix,
            response.status_code,
            duration_ms,
        )
        return body
