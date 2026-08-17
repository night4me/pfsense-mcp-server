"""NexusSession -- Controller authentication and JWT session lifecycle
(Phase F, ADR-032).

Owns exactly the two mutation-shaped HTTP verbs this entire Nexus
track is permitted to ever issue: `POST /login` and
`POST /login/refresh`. No other class under `backends/nexus/` may
issue a non-GET request -- see `transport.py`, which is GET-only by
construction.

Resolves two of ADR-032's open questions from authoritative source
(`Netgate/pfsense-api`'s generated `py/pfapi/client.py`/
`py/pfapi/api/login/login.py`, fetched directly this phase): the
official client issues one unwrapped `httpx.Client(...).request()`
call with no retry logic anywhere, and defaults to
`follow_redirects=False`. This module matches both: no retry, no
redirect-following.

Access-token TTL beyond the JWT's own `exp` claim remains unresolved
(ADR-032) -- this module never assumes a duration; it decodes `exp`
from the token actually issued and refuses to proceed if that claim is
missing or malformed, exactly the "fail closed if token expiry cannot
be safely determined" requirement.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any

import httpx

from ...errors import PfSenseAuthError, PfSenseConnectionError

logger = logging.getLogger("pfsense_mcp.backends.nexus.session")

_LOGIN_PATH = "/login"
_REFRESH_PATH = "/login/refresh"

# Refresh proactively rather than race a request against expiry. An
# explicit, independent choice -- Netgate's own example refreshes
# every 4 minutes on a fixed timer with no stated relationship to the
# real token TTL (ADR-032), so it is not evidence for this value; this
# margin is deliberately conservative and applied relative to the
# token's own decoded `exp`, not a fixed schedule.
_REFRESH_SAFETY_MARGIN_SECONDS = 30


def _decode_jwt_exp(token: str) -> int:
    """Decode a JWT's `exp` claim without verifying its signature --
    the Controller is the signer and this only reads a token this
    session itself just received, never a third party's claim. Fails
    closed (PfSenseAuthError) on any malformed token or missing/
    invalid `exp`. Never assumes or defaults an expiry."""

    parts = token.split(".")
    if len(parts) != 3:
        raise PfSenseAuthError("Nexus access token is not a well-formed JWT.")

    payload_b64 = parts[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        raise PfSenseAuthError("Nexus access token payload could not be decoded.") from None

    if not isinstance(payload, dict) or "exp" not in payload:
        raise PfSenseAuthError("Nexus access token does not contain an 'exp' claim.")

    exp = payload["exp"]
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise PfSenseAuthError("Nexus access token 'exp' claim is not a valid timestamp.")

    return int(exp)


class NexusSession:
    """Owns Controller login, the current JWT access token, and
    refresh. Never exposes the token, password, or base64-encoded
    credential via `__repr__`, an exception message, or a log line --
    `get_valid_access_token()` is the only way to obtain the token,
    and it is never logged by this class or any caller it hands the
    value to."""

    def __init__(
        self,
        *,
        controller_url: str,
        username: str,
        password: str,
        secondfactor: str | None = None,
        verify: bool | str = True,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        self._controller_url = controller_url.rstrip("/")
        self._username = username
        self._password = password
        self._secondfactor = secondfactor
        self._client = httpx.Client(
            base_url=self._controller_url + "/api",
            verify=verify,
            follow_redirects=False,
            timeout=timeout or httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
        )
        self._token: str | None = None
        self._exp: int | None = None

    def __repr__(self) -> str:
        return f"NexusSession(controller_url={self._controller_url!r}, authenticated={self._token is not None})"

    def close(self) -> None:
        self._client.close()

    def _login_payload(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "username": base64.b64encode(self._username.encode("utf-8")).decode("ascii"),
            "password": base64.b64encode(self._password.encode("utf-8")).decode("ascii"),
        }
        if self._secondfactor is not None:
            body["secondfactor"] = self._secondfactor
        return body

    def login(self) -> None:
        """POST /login. Raises PfSenseAuthError on failure or a
        malformed/inexpirable token; PfSenseConnectionError on
        network/timeout failure. Never includes the password, the
        base64-encoded credential, or the token value in any
        exception message or log line."""

        start = time.monotonic()
        try:
            response = self._client.post(_LOGIN_PATH, json=self._login_payload())
        except httpx.TimeoutException:
            logger.warning("nexus_login_timeout controller=%s", self._controller_url)
            raise PfSenseConnectionError("Nexus Controller login request timed out.") from None
        except httpx.TransportError:
            logger.warning("nexus_login_connection_error controller=%s", self._controller_url)
            raise PfSenseConnectionError("Could not connect to the Nexus Controller for login.") from None

        self._handle_login_like_response(response, operation="login")
        logger.info(
            "nexus_login_success controller=%s duration_ms=%.1f",
            self._controller_url,
            (time.monotonic() - start) * 1000,
        )

    def refresh(self) -> None:
        """POST /login/refresh, relying on the refresh-token cookie
        already held by this session's HTTP client from a prior
        login(). Raises PfSenseAuthError if the refresh token is no
        longer valid -- callers must call login() again in that case;
        this method never does so automatically."""

        if self._token is None:
            raise PfSenseAuthError("Cannot refresh a Nexus session that has never logged in.")

        start = time.monotonic()
        try:
            response = self._client.post(_REFRESH_PATH, json={"username": self._login_payload()["username"]})
        except httpx.TimeoutException:
            logger.warning("nexus_refresh_timeout controller=%s", self._controller_url)
            raise PfSenseConnectionError("Nexus Controller refresh request timed out.") from None
        except httpx.TransportError:
            logger.warning("nexus_refresh_connection_error controller=%s", self._controller_url)
            raise PfSenseConnectionError("Could not connect to the Nexus Controller for refresh.") from None

        self._handle_login_like_response(response, operation="refresh")
        logger.info(
            "nexus_refresh_success controller=%s duration_ms=%.1f",
            self._controller_url,
            (time.monotonic() - start) * 1000,
        )

    def _handle_login_like_response(self, response: httpx.Response, *, operation: str) -> None:
        if response.status_code != 200:
            logger.warning(
                "nexus_%s_failed controller=%s status=%s", operation, self._controller_url, response.status_code
            )
            raise PfSenseAuthError("Nexus Controller authentication failed.")

        try:
            body = response.json()
        except ValueError:
            raise PfSenseAuthError("Nexus Controller authentication response was not valid JSON.") from None

        if not isinstance(body, dict) or not isinstance(body.get("token"), str) or not body["token"]:
            raise PfSenseAuthError("Nexus Controller authentication response did not contain a token.")

        token = body["token"]
        exp = _decode_jwt_exp(token)  # fails closed on malformed/missing exp -- see module docstring

        self._token = token
        self._exp = exp

    def get_valid_access_token(self) -> str:
        """Returns a currently-valid access token, refreshing first if
        the token is within the safety margin of its known expiry (or
        already expired). Raises PfSenseAuthError if no session has
        been established yet, or if expiry cannot be safely
        determined -- never returns a token whose validity is
        unknown, and never guesses an expiry."""

        if self._token is None or self._exp is None:
            raise PfSenseAuthError("Nexus session is not authenticated; call login() first.")

        if time.time() >= (self._exp - _REFRESH_SAFETY_MARGIN_SECONDS):
            self.refresh()

        if self._token is None:
            # Unreachable in practice (refresh() always sets a token or
            # raises), but checked explicitly rather than with `assert`
            # -- assertions are stripped under Python's -O flag, which
            # would silently defeat this exact fail-closed guarantee.
            raise PfSenseAuthError("Nexus session lost its access token unexpectedly.")
        return self._token
