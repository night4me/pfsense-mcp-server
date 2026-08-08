# Tier 1 — Protected artifact encryption

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 3 (persistence and crash contract) in
[TIER1_ROADMAP.md](../../TIER1_ROADMAP.md); requires
[ADR-009](../../adr/ADR-009-protected-artifact-encryption-provider.md).
Related: [key_lifecycle.md](key_lifecycle.md),
[RECOVERY_CONTRACT_SPEC.md](../../RECOVERY_CONTRACT_SPEC.md).

## Purpose

Define exactly how `ProtectedArtifact.ciphertext` (target identity, intent,
snapshot — see `src/pfsense_mcp/tier1/contract.py`) is produced and consumed,
so the inert `ProtectedArtifact` dataclass — currently opaque, provider-free
ciphertext metadata — gains a concrete, reviewed codec before any capability
adapter can construct a real one.

## Security goals

- G1: Protected artifact plaintext (raw target identity, raw intent, raw
  snapshot) is never recoverable from the SQLite store file alone, even by
  an attacker who has read access to the entire store directory.
- G2: Tampering with `ciphertext`, `algorithm`, or `key_id` is detected
  before any plaintext is returned to a caller.
- G3: The encryption key never enters the SQLite database, a log, an
  exception message, or a Git-tracked file, under any code path.
- G4: Loss of the encryption key is a defined, safe failure (refuse to
  decrypt), never a silent fallback to plaintext or a weaker codec.
- G5: Key rotation does not require rewriting the entire store in one
  operation and does not require decrypting-then-re-encrypting outside a
  reviewed, tested code path.

## Invariants

- I1: `ProtectedArtifact.algorithm` is drawn from a closed enum of accepted
  codec identifiers; an unrecognized value fails closed at decode time,
  never falls back to a default codec.
- I2: Every encryption operation uses a fresh, unique nonce/IV; nonces are
  never reused under the same key. Nonce derivation must be deterministic
  from a source that cannot repeat within a key's lifetime (see
  `key_lifecycle.md` for the counter-based nonce scheme).
- I3: The codec is authenticated encryption (AEAD) — integrity of
  ciphertext and any associated data is verified as part of decryption,
  not by a separate step that can be skipped.
- I4: Associated data (AEAD "AAD") binds the ciphertext to its
  `contract_id` and artifact role (`target_identity` / `intent` /
  `snapshot`), so ciphertext from one contract or one field cannot be
  substituted into another without decryption failing.
- I5: Decryption failure is a `Tier1Error` subclass, never a generic
  exception that could be mistaken for "empty" or "absent" data.
- I6: No convenience plaintext codec is ever added to this module. A
  caller that wants plaintext must go through the one reviewed decrypt
  path and is responsible for immediately discarding the result.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Key material vs. store file | In-memory key, loaded once per process | SQLite file on disk, backups, any copy of the store | Key never derived from or stored in the DB (I3 in `key_lifecycle.md`) |
| Ciphertext vs. plaintext | Process memory holding decrypted artifact, held only as long as needed | Persisted `ciphertext` column | AEAD tag verification before any byte is treated as plaintext |
| One contract's artifacts vs. another's | Decrypted plaintext for contract A | Ciphertext for contract B | AAD binding (I4) — decryption with the wrong AAD fails even with the correct key |

## State ownership

- `src/pfsense_mcp/tier1/crypto.py` (new module, not yet created) owns the
  codec: `encrypt_artifact()` / `decrypt_artifact()`. It is the only module
  that imports the encryption library (e.g., `cryptography`).
- `contract.py`'s `ProtectedArtifact` remains a passive, opaque data holder.
  It does not import `crypto.py` and does not know how to decrypt itself —
  keeping the codec swappable without touching the contract model, and
  keeping `ProtectedArtifact.__post_init__`'s validation (bytes,
  non-empty, size-bounded) codec-agnostic.
- The key itself is owned exclusively by whatever component constructs
  the executor (see `sealed_executor.md`) and is passed to `crypto.py`
  functions as an explicit parameter — never a module-level global, never
  attached to `SqliteRecoveryContractStore`.

## Interfaces

```python
# src/pfsense_mcp/tier1/crypto.py (new; not created yet)


class ArtifactAlgorithm(str, Enum):
    AES_256_GCM_V1 = "aes-256-gcm-v1"


class ArtifactRole(str, Enum):
    TARGET_IDENTITY = "target-identity"
    INTENT = "intent"
    SNAPSHOT = "snapshot"


def encrypt_artifact(
    *,
    key: bytes,  # exactly 32 bytes; caller-owned, never logged
    key_id: str,  # matches KeyRecord.key_id from key_lifecycle.md
    contract_id: str,
    role: ArtifactRole,
    plaintext: bytes,  # canonical_json() output; caller's responsibility
) -> ProtectedArtifact: ...


def decrypt_artifact(
    *,
    key: bytes,
    artifact: ProtectedArtifact,
    contract_id: str,
    role: ArtifactRole,
) -> bytes:
    """Raises ArtifactDecryptionError (new Tier1Error subclass) on any
    AEAD authentication failure, unknown algorithm, or AAD mismatch.
    Never returns partially-verified plaintext."""
```

Nonce construction (see `key_lifecycle.md` for the counter source):
`nonce = key_epoch_prefix(4 bytes) || monotonic_counter(8 bytes)`, 12 bytes
total for AES-GCM. The counter is owned by `key_lifecycle.md`'s
`NonceCounter`, not by this module — `crypto.py` consumes a nonce, it does
not generate the counter state.

AAD construction: `AAD = domain_prefix || contract_id || role.value`,
canonicalized the same way `canonical.py` frames digest context (reuse
`_framed()`-equivalent length-prefixing, do not introduce a second
delimiter convention — this is a direct application of the "Required
correction 1" finding from the architecture review: **new code in this
area must use length-prefixed framing from day one**, not NUL or another
ad hoc delimiter).

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Wrong key supplied | AEAD tag mismatch | `ArtifactDecryptionError`, contract load fails closed | No |
| Ciphertext tampered (bit flip, truncation) | AEAD tag mismatch | `ArtifactDecryptionError` | No |
| Ciphertext for wrong contract/role substituted | AAD mismatch | `ArtifactDecryptionError` | No |
| Unknown `algorithm` value | Enum lookup failure at decode | `ArtifactDecryptionError`, no decrypt attempted | No |
| Key unavailable (deleted, wrong permissions, process has no key loaded) | Key load failure upstream (see `key_lifecycle.md`) | Contract cannot be loaded/decrypted; store-level operations that don't need plaintext (state transitions, audit) remain unaffected | No — this is an operational stop, not a retryable fault |
| Nonce counter exhausted for current key epoch | Counter overflow check in `key_lifecycle.md` | Encryption refused; forces key rotation before any further `create()` | No |

## Recovery behavior

- Decryption is never required to authenticate a stored record's identity,
  state, or version — `store.py`'s HMAC (over the still-opaque ciphertext
  bytes) already proves the record hasn't been tampered with, independent
  of whether the key to decrypt it is currently available. This means
  **losing the encryption key does not break state-machine integrity or
  audit-chain verification** — it only blocks operations that need the
  plaintext (constructing an execution request, computing a rollback
  diff). This separation must be preserved: never make HMAC verification
  depend on successful decryption.
- On restart, `store.reconcile_interrupted()` (existing, unchanged) can run
  and move `EXECUTING`/`ROLLING_BACK` records to `RECONCILIATION` without
  ever decrypting an artifact — reconciliation triage does not require
  plaintext access, only state metadata. Only the human/authenticated
  reconciliation step (see `reconciliation_authority.md`) needs the key,
  and only once it is available again.

## Non-goals

- This module does not manage key storage, rotation, or delivery — that is
  entirely `key_lifecycle.md`.
- This module does not decide when plaintext is safe to log or display —
  callers (a future executor) are responsible for never doing so; this
  spec does not weaken the existing "no payload/snapshot/response in
  logs" invariant.
- This module does not implement compression. Do not add it: compression
  before AEAD encryption on attacker-influenceable plaintext (e.g., an
  intent field a caller partially controls) creates a compression-ratio
  side channel (CRIME/BREACH-class). If size is a concern, address it via
  the existing canonical-size bounds, not compression.

## Required tests

- Round-trip: `decrypt_artifact(encrypt_artifact(...))` recovers exact
  plaintext, for boundary sizes (empty-after-canonicalization is invalid
  per `ProtectedArtifact`, 1 byte, max size).
- Tamper tests: flip one bit in ciphertext, in the stored `algorithm`
  string, in `key_id` → all raise `ArtifactDecryptionError`.
- AAD-substitution test: encrypt under contract A's `contract_id`/role,
  attempt to decrypt while asserting contract B's `contract_id` or a
  different role → must fail even with the correct key.
- Wrong-key test: decrypt with a different, validly-shaped 32-byte key →
  fails.
- Unknown-algorithm test: hand-craft a `ProtectedArtifact` with an
  `algorithm` value not in `ArtifactAlgorithm` → decode/decrypt refuses
  before touching the ciphertext bytes.
- Nonce-uniqueness test: encrypt N artifacts under one key/epoch, assert
  all N nonces are distinct (statistical/property test over a large N,
  not just a handful).
- Fuzz test: random bytes as ciphertext with a valid-looking structure →
  never raises anything other than `ArtifactDecryptionError` (no unhandled
  exception, no crash, no plaintext-shaped garbage returned).

## Activation requirements

- [ ] `ADR-009` accepted by the owner (algorithm/library choice).
- [ ] `cryptography` (or the accepted alternative) added as a pinned,
      reviewed runtime dependency in `pyproject.toml` with an explicit
      version constraint, per `DEPENDENCY_POLICY.md`.
- [ ] `crypto.py` implemented and 100%-branch-tested per "Required tests".
- [ ] Security review confirms AAD binding actually prevents
      cross-contract/cross-role substitution (test, not just code read).
- [ ] `key_lifecycle.md` accepted and implemented (dependency).
- [ ] No caller outside `pfsense_mcp.tier1` imports `crypto.py` until the
      sealed executor (`sealed_executor.md`) is itself authorized —
      enforced by extending `tests/tier1/test_isolation.py`'s existing
      AST-walk pattern.

## Implementation checklist

- [ ] Create `src/pfsense_mcp/tier1/crypto.py` with `ArtifactAlgorithm`,
      `ArtifactRole`, `encrypt_artifact`, `decrypt_artifact`.
- [ ] Add `ArtifactDecryptionError(Tier1Error)` to `errors.py`.
- [ ] Implement length-prefixed AAD framing (reuse the exact framing
      helper pattern from `canonical.py`, do not reinvent it).
- [ ] Wire nonce sourcing to `key_lifecycle.md`'s `NonceCounter` interface
      (do not generate nonces from `os.urandom()` alone — see
      `key_lifecycle.md` for why a counter-based scheme is required for
      an AEAD mode with a 96-bit nonce under a long-lived key).
- [ ] Add the dependency to `pyproject.toml` under the `[project]`
      `dependencies` list (not optional — it is required once Tier 1
      activates, but the import must stay unreachable from production
      until then, same as `mcp`/`httpx`/`pydantic` are unconditionally
      imported today but only reachable through explicit bootstrap).

## Review checklist

- [ ] Confirm `crypto.py` has zero imports of `transport`, `tools`,
      `write_api_client`, or any production module (extend
      `test_isolation.py`'s forbidden-import-roots set).
- [ ] Confirm no plaintext convenience function exists (I6) — grep for any
      function whose only job is "decrypt and return" without a
      documented, reviewed caller.
      review must independently re-derive that AAD framing rejects a hand-
      constructed collision (do not trust the length-prefix claim without
      a test proving it, mirroring how the digest-framing fix was
      verified in the prior architecture review).
- [ ] Confirm key material is `bytes`, never `str`, throughout — a `str`
      key risks accidental encoding-related nonce/key corruption and is
      more likely to be accidentally logged as human-readable text.

## Security checklist

- [ ] No key material appears in any exception message raised by
      `crypto.py` (test: trigger every failure path, assert `str(exc)`
      contains no key-shaped byte sequence).
- [ ] No plaintext appears in any exception message.
- [ ] Bandit/`ruff` security rules pass on the new module.
- [ ] Confirm `ProtectedArtifact` continues to reject empty ciphertext —
      an all-zero or empty AEAD output must never be treated as "no
      artifact" by any caller (I5's "never mistaken for absent data").

## Test checklist

- [ ] Round-trip tests (all artifact roles, boundary sizes).
- [ ] Tamper tests (ciphertext, algorithm, key_id).
- [ ] AAD-substitution tests (cross-contract, cross-role).
- [ ] Wrong-key test.
- [ ] Unknown-algorithm test.
- [ ] Nonce-uniqueness property test.
- [ ] Fuzz test on ciphertext bytes.
- [ ] Negative test: `crypto.py` module has zero forbidden imports (AST
      isolation test, same family as `test_isolation.py`).
