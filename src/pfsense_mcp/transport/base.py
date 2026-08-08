"""Transport protocol and its response/error types.

A Transport's only job is to send a request and return a response —
it knows nothing about pfSense, JSON, or which HTTP methods are
permitted. Those rules live in RestApiClient, one layer up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    text: str


class TransportError(Exception):
    """Base for transport-level failures. Never includes credential values."""


class TransportConnectionError(TransportError):
    pass


class TransportTimeoutError(TransportError):
    pass


class Transport(Protocol):
    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse: ...
