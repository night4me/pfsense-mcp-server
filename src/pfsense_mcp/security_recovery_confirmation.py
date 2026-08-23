"""ADR-033 recovery-execution confirmation token.

The `pfsense-mcp-security recover` CLI's read-only inspection step prints
a token; its destructive execution step requires that exact token back.
The token is a confirmation artifact, not a substitute for
authentication/authorization -- it never weakens, replaces, or is
consulted by any of `security_bootstrap_recovery.py`'s own existing
identity/ownership/reread/postcondition checks, all of which still run
unconditionally on the execution path. Its only job is to make it hard
for a stale, copy-pasted, or cross-incident command to reach even the
first mutating HTTP request.

The token is an HMAC-SHA256 over a canonical JSON payload, keyed by the
same local operation-journal integrity key (`PFSENSE_ADMIN_JOURNAL_KEY_FILE`)
already used to authenticate every ADR-033 journal/lock record -- no new
secret, no new authentication mechanism. The payload deliberately binds
six independent facts, so a token is refused if *any* of them differs
from what is true right now:

  - the target appliance (origin + identity)
  - which of the two recovery actions this token authorizes
  - the exact object (API key or user) this token was computed for,
    fingerprinted from its own non-secret authoritative identity
  - the *originating* incident: the operation_id of the bootstrap
    operation that first reached ``RECOVERY_REQUIRED``, and that
    journal record's own HMAC (already an integrity-protected digest of
    the exact incident state) -- so a token computed for one incident
    can never silently authorize a later, unrelated incident that
    happens to involve a similarly-shaped object.

Nothing here makes a network call, reads a file, or knows about
`Transport`/HTTP at all -- pure, deterministic, easily unit-tested.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from .security_bootstrap_client import ObservedApiKey, ObservedUser
from .security_operation_journal import RecoveryAction

_TOKEN_DOMAIN = b"pfsense-mcp-adr033-recovery-confirm-v1\x00"


@dataclass(frozen=True)
class RecoveryIncidentBinding:
    """Every fact one confirmation token must be bound to.

    Constructing this from live/journal data (never from caller-supplied
    strings the token itself is being checked against) is the caller's
    responsibility -- see `security_recovery_orchestration.py`."""

    target_origin: str
    target_identity: str
    recovery_action: RecoveryAction
    object_fingerprint: str
    incident_operation_id: str
    incident_record_mac: str


def object_fingerprint(observed: ObservedApiKey | ObservedUser) -> str:
    """Deterministic, order-independent fingerprint of an object's
    complete non-secret authoritative identity, as actually observed.
    Two reads of the identical object always fingerprint identically;
    any difference in any field changes the fingerprint."""

    if isinstance(observed, ObservedApiKey):
        payload = {
            "kind": "api_key",
            "id": observed.id,
            "username": observed.username,
            "descr": observed.descr,
            "hash_algo": observed.hash_algo,
            "length_bytes": observed.length_bytes,
        }
    else:
        payload = {
            "kind": "user",
            "id": observed.id,
            "name": observed.name,
            "descr": observed.descr,
            "priv": sorted(observed.priv),
            "disabled": observed.disabled,
            "scope": observed.scope,
        }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _canonical_payload(binding: RecoveryIncidentBinding) -> bytes:
    payload = {
        "target_origin": binding.target_origin,
        "target_identity": binding.target_identity,
        "recovery_action": binding.recovery_action.value,
        "object_fingerprint": binding.object_fingerprint,
        "incident_operation_id": binding.incident_operation_id,
        "incident_record_mac": binding.incident_record_mac,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def derive_confirmation_token(binding: RecoveryIncidentBinding, *, integrity_key: bytes) -> str:
    """The token a correct, current, same-incident `--execute` invocation
    must supply back. Deterministic: calling this twice with the same
    binding and key always returns the same token."""

    return hmac.new(integrity_key, _TOKEN_DOMAIN + _canonical_payload(binding), hashlib.sha256).hexdigest()


def confirmation_token_matches(
    candidate: str | None, binding: RecoveryIncidentBinding, *, integrity_key: bytes
) -> bool:
    """Constant-time comparison against the token this exact binding
    would produce right now. `candidate` is untrusted operator input --
    never assume it is well-formed."""

    if not isinstance(candidate, str) or not candidate:
        return False
    expected = derive_confirmation_token(binding, integrity_key=integrity_key)
    return hmac.compare_digest(candidate, expected)
