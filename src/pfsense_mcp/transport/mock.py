"""MockTransport — in-memory Transport for tests. No HTTP library involved."""

from __future__ import annotations

from .base import TransportResponse


class MockTransport:
    def __init__(self) -> None:
        self._responses: dict[tuple[str, str], TransportResponse] = {}
        self.calls: list[tuple[str, str]] = []

    def register(self, method: str, path: str, *, status_code: int, text: str) -> None:
        self._responses[(method, path)] = TransportResponse(status_code=status_code, text=text)

    def request(self, method: str, path: str) -> TransportResponse:
        self.calls.append((method, path))
        key = (method, path)
        if key not in self._responses:
            raise KeyError(f"No mock response registered for {method} {path}")
        return self._responses[key]
