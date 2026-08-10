"""Guest-side `AntiRollbackAnchor` implementation for the TPM-backed
host witness service (ADR-011's decided backend, see
docs/tier1/specs/anti_rollback_tpm_host_witness.md).

Not constructed by production. The Proxmox host's physical TPM NV
counter has been provisioned (2026-08-10, Slice A) and is the real,
authoritative anchor, but no witness daemon exists yet to serve the
protocol this class calls, and this store has not been seeded with the
provisioned counter's real baseline (Slice B provides the store-side
primitives for that in `anti_rollback.py`; the actual seed call is a
separate, later, not-yet-authorized administrative step). This class is
therefore inert by construction, not merely by convention: nothing in
`pfsense_mcp.application`/`factory`/`tools` imports or constructs it.

Wire protocol this class implements the guest side of (the daemon side
does not exist yet -- whoever builds it, per the spec's "Host service
protocol" section, must conform to this):

    GET  {base_url}/anchor/read
        -> 200 {"value": <non-negative integer>}

    POST {base_url}/anchor/advance
        body {"expected_current": <non-negative integer>}
        -> 200 {"value": <non-negative integer>}   (advanced)
        -> 409                                      (conflict -- expected_current stale)
        -> any other status / malformed body / transport failure -> unavailable

Authentication (mutual TLS) is the caller's responsibility: this class
receives an already-configured `httpx.Client` (matching this project's
existing "adapters/clients receive already-validated inputs, they never
construct their own trust materials" discipline --
capability_adapter_contract.md's own I2, applied here) and never
constructs, loads, or holds any certificate, key, or the TPM index's own
authorization secret. The TPM authorization boundary never crosses into
this guest process at all -- only the witness daemon (host-side, not
this module) ever holds it. See `witness_daemon/README.md`'s
"Connecting from the guest" section for the confirmed-working (real-
hardware verified, 2026-08-10) `httpx.Client` mTLS construction --
build an explicit `ssl.SSLContext`, not the `cert=`/`verify=<path>`
shorthand, which was found unreliable for client-certificate
configuration on `httpx>=0.28`.
"""

from __future__ import annotations

import httpx

from .errors import AnchorConflictError, AnchorUnavailableError


class TpmHostWitnessAnchor:
    """`AntiRollbackAnchor` Protocol implementation. Every failure mode
    (connection refused, TLS handshake failure, timeout, non-2xx/409
    status, malformed response body) maps to `AnchorUnavailableError` --
    fail closed, never a stale or guessed value -- except an explicit 409
    response, which maps to `AnchorConflictError` (the caller's
    `expected_current` no longer matches, per `AntiRollbackAnchor.
    advance()`'s own contract)."""

    def __init__(self, *, client: httpx.Client, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    def _decode_value(self, response: httpx.Response) -> int:
        try:
            body = response.json()
            value = body["value"]
        except (ValueError, KeyError, TypeError):
            raise AnchorUnavailableError("Witness service returned a malformed response body.") from None
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise AnchorUnavailableError("Witness service returned a non-integer or negative anchor value.")
        return value

    def read(self) -> int:
        try:
            response = self._client.get(f"{self._base_url}/anchor/read")
        except httpx.ConnectError:
            raise AnchorUnavailableError("Could not connect to the anchor witness service.") from None
        except httpx.TimeoutException:
            raise AnchorUnavailableError("Anchor witness service request timed out.") from None
        except httpx.TransportError:
            raise AnchorUnavailableError("Anchor witness service transport failed.") from None
        if response.status_code != 200:
            raise AnchorUnavailableError(f"Anchor witness service returned status {response.status_code} for read.")
        return self._decode_value(response)

    def advance(self, *, expected_current: int) -> int:
        if not isinstance(expected_current, int) or isinstance(expected_current, bool) or expected_current < 0:
            raise AnchorUnavailableError("expected_current must be a non-negative integer.")
        try:
            response = self._client.post(
                f"{self._base_url}/anchor/advance",
                json={"expected_current": expected_current},
            )
        except httpx.ConnectError:
            raise AnchorUnavailableError("Could not connect to the anchor witness service.") from None
        except httpx.TimeoutException:
            raise AnchorUnavailableError("Anchor witness service request timed out.") from None
        except httpx.TransportError:
            raise AnchorUnavailableError("Anchor witness service transport failed.") from None
        if response.status_code == 409:
            raise AnchorConflictError("Anchor witness service reported a conflicting current value.")
        if response.status_code != 200:
            raise AnchorUnavailableError(f"Anchor witness service returned status {response.status_code} for advance.")
        return self._decode_value(response)
