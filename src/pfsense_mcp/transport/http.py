"""HttpTransport — the real, network-backed Transport implementation."""

from __future__ import annotations

import httpx

from .base import TransportConnectionError, TransportResponse, TransportTimeoutError


class HttpTransport:
    def __init__(self, base_url: str, api_key: str, verify: bool | str) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            verify=verify,
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
        )

    def request(self, method: str, path: str) -> TransportResponse:
        try:
            response = self._client.request(method, path)
        except httpx.ConnectError:
            raise TransportConnectionError(f"Could not connect for {method} {path}") from None
        except httpx.TimeoutException:
            raise TransportTimeoutError(f"Request timed out for {method} {path}") from None
        return TransportResponse(status_code=response.status_code, text=response.text)

    def close(self) -> None:
        self._client.close()
