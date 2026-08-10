from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator

import pytest

from witness_daemon.errors import WitnessError
from witness_daemon.http_server import WitnessHTTPServer
from witness_daemon.service import AdvanceOutcome


class _FakeService:
    def __init__(self, *, read_value: int | None = 2, read_error: bool = False) -> None:
        self._read_value = read_value
        self._read_error = read_error
        self.read_calls = 0
        self.advance_calls: list[int] = []
        self._advance_outcome: AdvanceOutcome | None = None
        self._advance_error = False

    def read(self) -> int:
        self.read_calls += 1
        if self._read_error:
            raise WitnessError("unavailable")
        assert self._read_value is not None
        return self._read_value

    def set_advance_outcome(self, outcome: AdvanceOutcome | None, *, error: bool = False) -> None:
        self._advance_outcome = outcome
        self._advance_error = error

    def advance(self, expected_current: int) -> AdvanceOutcome:
        self.advance_calls.append(expected_current)
        if self._advance_error:
            raise WitnessError("unavailable")
        assert self._advance_outcome is not None
        return self._advance_outcome


@pytest.fixture
def running_server() -> Iterator[tuple[WitnessHTTPServer, _FakeService, int]]:
    service = _FakeService()
    server = WitnessHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, service, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(port: int, path: str) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        body = json.loads(response.read())
        return response.status, body
    finally:
        conn.close()


def _post(port: int, path: str, body: bytes | None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"Content-Type": "application/json"}
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        parsed = json.loads(response.read())
        return response.status, parsed
    finally:
        conn.close()


def test_read_success(running_server):
    _server, service, port = running_server
    status, body = _get(port, "/anchor/read")
    assert status == 200
    assert body == {"value": 2}
    assert service.read_calls == 1


def test_read_unavailable_maps_to_503(running_server):
    _server, service, port = running_server
    service._read_error = True
    status, body = _get(port, "/anchor/read")
    assert status == 503
    assert body == {"error": "anchor unavailable"}


def test_unknown_get_path_is_404_and_never_touches_service(running_server):
    _server, service, port = running_server
    status, _body = _get(port, "/anchor/advance")
    assert status == 404
    assert service.read_calls == 0
    assert service.advance_calls == []


def test_advance_match_returns_200(running_server):
    _server, service, port = running_server
    service.set_advance_outcome(AdvanceOutcome(conflict=False, value=3))
    status, body = _post(port, "/anchor/advance", json.dumps({"expected_current": 2}).encode())
    assert status == 200
    assert body == {"value": 3}
    assert service.advance_calls == [2]


def test_advance_conflict_returns_409(running_server):
    _server, service, port = running_server
    service.set_advance_outcome(AdvanceOutcome(conflict=True, value=5))
    status, body = _post(port, "/anchor/advance", json.dumps({"expected_current": 2}).encode())
    assert status == 409
    assert body == {"error": "conflict"}


def test_advance_unavailable_maps_to_503(running_server):
    _server, service, port = running_server
    service.set_advance_outcome(None, error=True)
    status, body = _post(port, "/anchor/advance", json.dumps({"expected_current": 2}).encode())
    assert status == 503
    assert body == {"error": "anchor unavailable"}


def test_advance_ignores_extraneous_handle_field_in_body(running_server):
    """A caller attempting to smuggle a handle override must be silently
    ignored -- only expected_current is ever read from the body."""

    _server, service, port = running_server
    service.set_advance_outcome(AdvanceOutcome(conflict=False, value=3))
    status, _body = _post(port, "/anchor/advance", json.dumps({"expected_current": 2, "handle": "0x01999999"}).encode())
    assert status == 200
    assert service.advance_calls == [2]


def test_advance_malformed_json_is_400(running_server):
    _server, service, port = running_server
    status, _body = _post(port, "/anchor/advance", b"not json")
    assert status == 400
    assert service.advance_calls == []


def test_advance_missing_expected_current_is_400(running_server):
    _server, service, port = running_server
    status, _body = _post(port, "/anchor/advance", json.dumps({}).encode())
    assert status == 400
    assert service.advance_calls == []


@pytest.mark.parametrize("bad_value", [-1, "2", 2.5, True])
def test_advance_invalid_expected_current_types_are_400(running_server, bad_value):
    _server, service, port = running_server
    status, _body = _post(port, "/anchor/advance", json.dumps({"expected_current": bad_value}).encode())
    assert status == 400
    assert service.advance_calls == []


def test_advance_oversized_body_is_400(running_server):
    _server, service, port = running_server
    huge = json.dumps({"expected_current": 2, "padding": "x" * 10000}).encode()
    status, _body = _post(port, "/anchor/advance", huge)
    assert status == 400
    assert service.advance_calls == []


def test_unknown_post_path_is_404(running_server):
    _server, service, port = running_server
    status, _body = _post(port, "/anchor/read", json.dumps({"expected_current": 2}).encode())
    assert status == 404
    assert service.advance_calls == []
