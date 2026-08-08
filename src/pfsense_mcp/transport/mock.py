"""MockTransport — in-memory Transport for tests. No HTTP library involved."""

from __future__ import annotations

from .base import TransportResponse


class MockTransport:
    def __init__(self) -> None:
        self._responses: dict[tuple[str, str], TransportResponse] = {}
        self.calls: list[tuple[str, str]] = []
        #: One entry per request(), in the same order as `calls` -- kept
        #: as a separate list (not folded into `calls`) so every existing
        #: `transport.calls == [(method, path), ...]` assertion across the
        #: test suite continues to work unchanged.
        self.request_bodies: list[bytes | None] = []

    def register(self, method: str, path: str, *, status_code: int, text: str) -> None:
        self._responses[(method, path)] = TransportResponse(status_code=status_code, text=text)

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self.calls.append((method, path))
        self.request_bodies.append(body)
        key = (method, path)
        if key not in self._responses:
            raise KeyError(f"No mock response registered for {method} {path}")
        return self._responses[key]
