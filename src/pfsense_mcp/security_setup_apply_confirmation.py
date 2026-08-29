"""`pfsense-mcp-security setup apply` confirmation token -- Slice 2.

`setup apply`'s read-only inspection step (no `--confirm`) prints a
token bound to the exact plan just recomputed; actually applying that
plan requires that exact token back. The token is a confirmation
artifact, not a substitute for authentication/authorization -- it never
weakens, replaces, or is consulted by any of the underlying primitives'
own checks (`generate_setup_plan()`'s own discovery, the live
connectivity probe, `run_doctor_checks()`), all of which still run
unconditionally on the apply path regardless of what the token proves.
Its only job is to make it hard for a stale, copy-pasted, or
cross-target/cross-posture command to reach even the first live
network call.

Mirrors `security_recovery_confirmation.py`'s design exactly (same
domain-separated HMAC-SHA256 construction over a canonical JSON
payload, same constant-time comparison discipline) -- the "simpler
incident/plan-bound HMAC-style confirmation approach" this run's own
owner decisions name explicitly, reused for a plan instead of a
recovery incident. Does not wire ADR-022/023 signing into setup.

The payload binds six independent facts, so a token is refused if
*any* of them differs from what is true right now:

  - the plan's own deterministic identity (`plan_digest`, from
    `security_setup_plan_digest.compute_setup_plan_digest()`)
  - the target appliance (origin + identity)
  - the exact capability posture and anchor assurance the plan was
    generated for
  - for `read_only`, the exact `read_only_account_mode` (`byo` or
    `managed`) the plan was generated for -- `None` for
    `write_protected` (POST-v1.0 MANAGED READ-ONLY WIZARD INTEGRATION
    mission, 2026-08-29)

A plan digest alone already changes if any of these differ (they are
themselves part of what the digest is computed over) -- binding them
again explicitly here is defense in depth, not redundancy: it means
`confirmation_token_matches()` never has to trust that the caller
supplied a digest that was actually computed the way this module
expects, since the binding is reconstructed from the same values the
caller already independently re-validated (see
`security_setup_apply.py`). `read_only_account_mode` in particular
means a token derived for a reviewed BYOK plan can never be replayed
to authorize a managed-provisioning apply for the identical target/
posture, or vice versa -- the token itself, not only the recomputed
plan digest it already depends on, refuses to match.

Nothing here makes a network call, reads a file, or knows about
`Transport`/HTTP at all -- pure, deterministic, easily unit-tested.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

_TOKEN_DOMAIN = b"pfsense-mcp-setup-apply-confirm-v1\x00"


@dataclass(frozen=True)
class ApplyConfirmationBinding:
    """Every fact one confirmation token must be bound to.

    Constructing this from a freshly-recomputed plan (never from
    caller-supplied strings the token itself is being checked against)
    is the caller's responsibility -- see `security_setup_apply.py`."""

    plan_digest: str
    target_origin: str | None
    target_identity: str | None
    capability_posture: str
    anchor_assurance: str
    #: `None` for `write_protected`; `"byo"` or `"managed"` for
    #: `read_only`. Defaults to `None` so every existing keyword-argument
    #: construction of this dataclass (including every pre-existing test)
    #: remains valid unchanged -- see this module's own docstring for why
    #: this field must be bound here, not only inside `plan_digest`.
    read_only_account_mode: str | None = None


def _canonical_payload(binding: ApplyConfirmationBinding) -> bytes:
    payload = {
        "plan_digest": binding.plan_digest,
        "target_origin": binding.target_origin,
        "target_identity": binding.target_identity,
        "capability_posture": binding.capability_posture,
        "anchor_assurance": binding.anchor_assurance,
        "read_only_account_mode": binding.read_only_account_mode,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def derive_confirmation_token(binding: ApplyConfirmationBinding, *, integrity_key: bytes) -> str:
    """The token a correct, current, same-plan `--confirm` invocation
    must supply back. Deterministic: calling this twice with the same
    binding and key always returns the same token."""

    return hmac.new(integrity_key, _TOKEN_DOMAIN + _canonical_payload(binding), hashlib.sha256).hexdigest()


def confirmation_token_matches(
    candidate: str | None, binding: ApplyConfirmationBinding, *, integrity_key: bytes
) -> bool:
    """Constant-time comparison against the token this exact binding
    would produce right now. `candidate` is untrusted operator input --
    never assume it is well-formed."""

    if not isinstance(candidate, str) or not candidate:
        return False
    expected = derive_confirmation_token(binding, integrity_key=integrity_key)
    # `hmac.compare_digest()` raises `TypeError` outright for a `str`
    # argument containing non-ASCII characters -- `candidate` is
    # untrusted operator input and must never crash the comparison.
    # Bytes-like arguments have no such restriction and remain
    # constant-time for equal-length inputs; `surrogateescape`
    # round-trips argv values containing invalid UTF-8 byte sequences
    # instead of raising a fresh encoding error.
    return hmac.compare_digest(candidate.encode("utf-8", errors="surrogateescape"), expected.encode("ascii"))
