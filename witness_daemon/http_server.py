"""The witness daemon's entire network-facing surface: exactly two
routes, nothing else (G3 -- "the witness daemon's network-facing surface
exposes exactly the two operations AntiRollbackAnchor needs and
nothing else"). Built on `http.server` (stdlib only, no third-party
framework) -- deliberately: a two-endpoint, security-critical daemon
does not need a web framework's dependency surface, request routing, or
templating.

Every HTTP response body is a fixed, generic JSON object -- never a raw
exception message, traceback, or subprocess output. Distinguishing "TPM
unreachable" from "auth failed" from "malformed output" on the wire
would hand a network caller a diagnostic oracle into the host's internal
state; that distinction is drawn only in `witness_daemon.errors`'
exception hierarchy and (if the deployer wires it up) host-local logs,
never in what this class writes back to the guest.

Transport security (mTLS) is wired by `main.py`, not this module: this
class only implements request routing/dispatch against an already
-constructed `WitnessService` -- it has no TLS/certificate code of its
own, keeping this file's own review surface to "does the routing/status
-code mapping match the protocol," nothing else.
"""

from __future__ import annotations

import http.server
import json
from typing import Any, Protocol

from .errors import WitnessError
from .service import AdvanceOutcome

_MAX_BODY_BYTES = 4096


class WitnessServiceProtocol(Protocol):
    """Structural type for whatever `WitnessHTTPServer` dispatches to --
    the real `WitnessService`, or a test double satisfying the same
    shape. Kept as a Protocol (matching this daemon's own `TpmClient`
    Protocol in `service.py`) so tests never need to subclass or
    monkeypatch the real class."""

    def read(self) -> int: ...
    def advance(self, expected_current: int) -> AdvanceOutcome: ...


class WitnessRequestHandler(http.server.BaseHTTPRequestHandler):
    """`server` is expected to be a `WitnessHTTPServer` (below), which
    carries the one `WitnessService` instance this handler dispatches
    to. Every other HTTP method/path this class does not explicitly
    implement falls through to `http.server.BaseHTTPRequestHandler`'s
    own default (501/404) -- there is no catch-all handler that could
    accidentally forward an unrecognized request anywhere."""

    server: "WitnessHTTPServer"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Default access logging only (method/path/status) -- never
        # request/response bodies, so a logged line can never contain
        # the anchor value's meaning beyond what the protocol already
        # exposes, and certainly never any TPM secret (this handler
        # never sees one).
        super().log_message(format, *args)

    def do_GET(self) -> None:
        if self.path != "/anchor/read":
            self._send_json(404, {"error": "not found"})
            return
        try:
            value = self.server.witness_service.read()
        except WitnessError:
            self._send_json(503, {"error": "anchor unavailable"})
            return
        self._send_json(200, {"value": value})

    def do_POST(self) -> None:
        if self.path != "/anchor/advance":
            self._send_json(404, {"error": "not found"})
            return

        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header is not None else -1
        except ValueError:
            self._send_json(400, {"error": "invalid request"})
            return
        if length < 0 or length > _MAX_BODY_BYTES:
            self._send_json(400, {"error": "invalid request"})
            return
        raw = self.rfile.read(length)

        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid request"})
            return
        # Deliberately strict: only "expected_current" is read. Any
        # other field a caller might include (e.g. an attempted "handle"
        # override) is silently ignored, never plumbed into the TPM
        # call -- advance() below always operates on the one handle the
        # daemon was configured with.
        if not isinstance(body, dict) or "expected_current" not in body:
            self._send_json(400, {"error": "invalid request"})
            return
        expected_current = body["expected_current"]
        if not isinstance(expected_current, int) or isinstance(expected_current, bool) or expected_current < 0:
            self._send_json(400, {"error": "invalid request"})
            return

        try:
            outcome = self.server.witness_service.advance(expected_current)
        except WitnessError:
            self._send_json(503, {"error": "anchor unavailable"})
            return
        if outcome.conflict:
            self._send_json(409, {"error": "conflict"})
            return
        self._send_json(200, {"value": outcome.value})


class WitnessHTTPServer(http.server.HTTPServer):
    """Carries exactly one `WitnessService` for the lifetime of the
    process; `main.py` wraps this server's socket with an mTLS
    `ssl.SSLContext` before calling `serve_forever()`."""

    def __init__(self, server_address: tuple[str, int], witness_service: WitnessServiceProtocol) -> None:
        super().__init__(server_address, WitnessRequestHandler)
        self.witness_service = witness_service
