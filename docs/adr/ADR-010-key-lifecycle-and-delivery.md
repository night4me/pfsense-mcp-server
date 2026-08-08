# ADR-010: Key lifecycle and delivery

- **Status:** Accepted
- **Date:** 2026-08-08
- **Accepted:** 2026-08-08 — implemented as `key_lifecycle.py`/
  `secure_file.py` (Phase 2); status field corrected to match
  already-merged implementation. Whether a systemd-managed deployment
  model changes the key-delivery recommendation remains open if the
  actual production deployment differs from what this session observed
  — an operational confirmation, not a reopening of this decision.

## Context

`ADR-009` selects a codec but not how its key (and the pre-existing HMAC
integrity key `SqliteRecoveryContractStore` already requires) is
generated, rotated, and destroyed. Today, `SqliteRecoveryContractStore.
__init__` accepts `integrity_key: bytes` as a caller-supplied parameter
with no defined production sourcing — this ADR closes that gap for both
keys.

## Options considered

| Option | Strengths | Costs / failure modes |
|---|---|---|
| Single shared key for encryption + HMAC | Simplest to provision | Violates key separation (compromise of one purpose compromises both); rejected outright, not a serious option |
| Manual, ad hoc rotation (no tooling) | Zero implementation cost | Exactly how key-custody mistakes happen under incident pressure; rejected |
| **Two independent `KeyRecord`s, local-file delivery, counter-based nonce, resumable per-record rotation (recommended)** | Reuses `config.py`'s proven loading pattern; rotation is safe to interrupt; nonce reuse is structurally prevented | Requires implementing `NonceCounter` durability correctly — the one genuinely new piece of engineering here |
| Automatic time-based rotation (e.g., rotate every 30 days unconditionally) | Removes a manual step | Silent rotation without an operator confirming the old key's artifacts have all migrated risks the old key being destroyed prematurely; rejected in favor of explicit operator-confirmed destruction |

## Recommendation

Two independently generated 256-bit keys (encryption, HMAC), each a
`KeyRecord`, loaded via a shared `O_NOFOLLOW`/`fstat()` helper factored
out of `config.py`'s existing key-loading code. Nonce uniqueness for the
encryption key is enforced by a durable, fsync-before-return
`NonceCounter`, not `os.urandom()` alone. Rotation is per-contract,
resumable, and never destroys the old key automatically — destruction is
a separate, explicit operator action after a zero-count verification.
Full specification: [key_lifecycle.md](../tier1/specs/key_lifecycle.md).

### Self-challenge

*"Isn't a counter-based nonce over-engineering compared to just using
`os.urandom(12)` per encryption, which is what most AEAD examples show?"*
— For AES-GCM specifically, a 96-bit random nonce has a meaningful
collision probability once billions of encryptions have occurred under
one key (birthday bound); for a long-lived server key that could
plausibly encrypt many records over months, a random nonce is the wrong
choice for the number of encryptions this system may eventually perform,
even if any single day's volume looks negligible. A monotonic counter
makes reuse structurally impossible up to 2^64 encryptions per key epoch,
which is the correct engineering choice given AES-GCM's well-documented
nonce-reuse catastrophic failure mode. This is not caution for its own
sake — nonce reuse under GCM leaks the authentication key.

*"Why not let `rotate_key()` run as one big transaction so it's atomic
instead of resumable-but-interruptible?"* — Because the store's own design
principle (see `store.py`'s per-record `BEGIN IMMEDIATE` transactions,
never a whole-database lock) is to keep any single transaction narrow —
a store with potentially many contracts held under one giant rotation
transaction would block all other store operations for the duration and
would make a mid-rotation crash's blast radius the entire store instead of
one record. Resumable-per-record is the design already used everywhere
else in this store; rotation should not be the one place that breaks that
pattern.

## Consequences

### Positive

- No new credential-loading pattern beyond what `config.py` already
  proves works.
- Rotation is safe under crash/interruption without operator guesswork.
- Nonce reuse is structurally, not just statistically, prevented.

### Negative

- Requires factoring existing production code (`config.py`'s key-loading
  helpers) into a shared location — a refactor of already-tested code,
  which must preserve exact existing behavior (explicit review
  requirement in `key_lifecycle.md`'s review checklist).
- Two key files to manage operationally instead of one.

## Future migration path

If a hardware-backed key provider (TPM-sealed key, HSM) is adopted later,
only `load_key_material()`'s implementation changes — `KeyRecord`'s shape
and every downstream consumer (`crypto.py`, `store.py`) are unaffected.
Revisit the "manual rotation only" decision if operational experience
shows rotation is needed frequently enough that manual per-rotation
review becomes a bottleneck rather than a safety feature.

## References

- [key_lifecycle.md](../tier1/specs/key_lifecycle.md)
- [ADR-009](ADR-009-protected-artifact-encryption-provider.md)
- `src/pfsense_mcp/config.py` (existing key-loading pattern)
