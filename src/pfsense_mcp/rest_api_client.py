"""RestApiClient — the only place a full pfSense REST API path is
constructed. Owns the GET-only contract, API-version resolution,
JSON parsing, status-to-exception mapping, and per-call duration
logging. Knows nothing about pfSense domain semantics beyond that.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import urlencode

from .api_version import ApiVersion, version_at_least
from .endpoints import EndpointInfo
from .errors import PfSenseAPIError, PfSenseAuthError, PfSenseConnectionError, UnsupportedOperationError
from .transport.base import Transport, TransportConnectionError, TransportTimeoutError

logger = logging.getLogger("pfsense_mcp.rest_api_client")


def _try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


class RestApiClient:
    def __init__(self, transport: Transport, *, identity: str, api_version: ApiVersion) -> None:
        self._transport = transport
        self._identity = identity
        self._api_version = api_version

    def get(self, endpoint: EndpointInfo, *, params: dict[str, str | int] | None = None) -> dict[str, Any]:
        if not version_at_least(self._api_version, endpoint.min_api_version):
            raise UnsupportedOperationError(
                f"Endpoint requires API version >= {endpoint.min_api_version.value}, "
                f"client is configured for {self._api_version.value}."
            )
        path = f"/api/{self._api_version.value}{endpoint.path_suffix}"
        if params:
            path = f"{path}?{urlencode(params)}"
        return self._request("GET", path)

    def _request(self, method: str, path: str) -> dict[str, Any]:
        if method != "GET":
            raise UnsupportedOperationError(f"{method!r} is not permitted (GET-only).")

        start = time.monotonic()
        try:
            response = self._transport.request(method, path)
        except TransportConnectionError:
            duration_ms = (time.monotonic() - start) * 1000
            logger.warning("connection_error identity=%s path=%s duration_ms=%.1f", self._identity, path, duration_ms)
            raise PfSenseConnectionError(f"Could not connect to pfSense host for {path}") from None
        except TransportTimeoutError:
            duration_ms = (time.monotonic() - start) * 1000
            logger.warning("timeout identity=%s path=%s duration_ms=%.1f", self._identity, path, duration_ms)
            raise PfSenseConnectionError(f"Request to {path} timed out") from None

        duration_ms = (time.monotonic() - start) * 1000
        body = _try_parse_json(response.text)
        response_id = body.get("response_id") if isinstance(body, dict) else None

        if response.status_code in (401, 403):
            logger.warning(
                "auth_error identity=%s path=%s status=%s response_id=%s duration_ms=%.1f",
                self._identity,
                path,
                response.status_code,
                response_id,
                duration_ms,
            )
            raise PfSenseAuthError("Authentication with pfSense failed.")

        if response.status_code >= 400:
            logger.warning(
                "api_error identity=%s path=%s status=%s response_id=%s duration_ms=%.1f",
                self._identity,
                path,
                response.status_code,
                response_id,
                duration_ms,
            )
            raise PfSenseAPIError(response.status_code, "pfSense API returned an error status.")

        logger.info(
            "response identity=%s path=%s status=%s response_id=%s duration_ms=%.1f",
            self._identity,
            path,
            response.status_code,
            response_id,
            duration_ms,
        )

        if body is None:
            raise PfSenseAPIError(response.status_code, "Response was not valid JSON.")
        return body
