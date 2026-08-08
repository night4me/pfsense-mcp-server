# Tier 1 — Key lifecycle

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 3 in [TIER1_ROADMAP.md](../../TIER1_ROADMAP.md);
requires [ADR-010](../adr/ADR-010-key-lifecycle-and-delivery.md).
Related: [protected_artifact_encryption.md](protected_artifact_encryption.md).

## Purpose

Define how the 256-bit encryption key used by `protected_artifact_
encryption.md` and the HMAC integrity key already used by
`SqliteRecoveryContractStore` are generated, delivered to the process,
rotated, and destroyed — reusing the exact local-file-descriptor validation
pattern already implemented and tested for the pfSense API key in
`src/pfsense_mcp/config.py`, rather than inventing a new one.

## Security goals

- G1: The encryption key and the HMAC integrity key are never derived from
  each other and never share storage — compromise of one does not
  automatically compromise the other.
- G2: Neither key is ever written to the SQLite database, a log file, a
  report, or any Git-tracked location.
- G3: Key rotation is possible without data loss and without a window in
  which any stored record is unauthenticated or undecryptable.
- G4: A key file with wrong ownership, wrong permissions, or that is a
  symlink is rejected before use, identically to how `config.py` already
  rejects an unsafe pfSense API key file.
- G5: Nonce reuse under the same encryption key is structurally
  prevented, not just discouraged (see Invariant I3).

## Invariants

- I1: The encryption key file and the HMAC key file are two distinct
  files, in the same owner-only (`0700`) directory convention already
  required for the SQLite store (`store.py::_prepare_path`), but **not**
  the same directory as the store file itself — a directory listing of
  the store's parent must not also reveal the key material's location.
- I2: Keys are loaded through `O_NOFOLLOW` + `fstat()`-validated
  descriptors — the same three checks `config.py::_validate_key_file_
  descriptor` already performs (regular file, owner-only mode, bounded
  size) — applied via a shared helper, not a re-implementation.
- I3: Each key has an associated **epoch** and **monotonic nonce
  counter**, persisted alongside the key (not in the SQLite store).
  `encrypt_artifact()` must never be called with a counter value that has
  been used before under the same key; the counter is incremented and
  fsynced to its own file *before* the corresponding ciphertext is
  returned to the caller, so a crash can only skip counter values
  (safe — wastes nonce space) and never reuse one (unsafe).
- I4: A key is retired (moved to "rotated-out, decrypt-only") the moment
  its nonce counter reaches a conservative threshold (recommended: 2^32
  of the 2^64 theoretical space for the 8-byte counter half — see
  `protected_artifact_encryption.md`'s nonce construction), never reused
  for new encryption after that point.
- I5: Key material is held in process memory only as `bytes`, never
  written to a Python `str`, and the module holding it is responsible for
  overwriting the buffer where the runtime allows it (`bytearray`, not a
  `bytes` literal, where feasible) — best-effort, since CPython does not
  guarantee secure memory wiping, but the intent must be explicit in code
  and comments, not silently absent.
- I6: Every rotation event is itself recorded as a Tier 1 audit event
  (event/key-id/epoch metadata only — never key bytes), so key lifecycle
  is auditable the same way contract state transitions are.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Key file vs. filesystem | Process holding an open, validated descriptor | Any other process/user on the host | `O_NOFOLLOW` + `fstat()` (I2), owner-only directory (I1) |
| Nonce counter vs. crash | Durable counter file, fsynced before ciphertext release | Process crash between encrypt and persist | Counter-before-ciphertext ordering (I3) |
| One key epoch vs. the next | Current active key | Retired keys (decrypt-only) | Epoch tagging in `key_id` (see Interfaces) |

## State ownership

- `src/pfsense_mcp/tier1/key_lifecycle.py` (new module) owns:
  `KeyRecord`, `NonceCounter`, `load_key_material()`,
  `rotate_key()`.
- The **encryption key** and **HMAC integrity key** are each a
  `KeyRecord`; they are loaded independently and passed independently to
  `crypto.py` and `SqliteRecoveryContractStore.__init__(integrity_key=...)`
  respectively. This module does not merge them and does not derive one
  from the other (G1).
- The nonce counter file is owned exclusively by this module; no other
  module reads or writes it.
- This module never constructs a `WriteApiClient`, imports `transport`, or
  otherwise touches production code — same isolation requirement as the
  rest of `pfsense_mcp.tier1`.

## Interfaces

```python
# src/pfsense_mcp/tier1/key_lifecycle.py (new; not created yet)

@dataclass(frozen=True)
class KeyRecord:
    key_id: str        # e.g. "enc-2026-08-08-0001"; matches ArtifactAlgorithm key_id
    epoch: int          # monotonically increasing per key purpose
    material: bytes      # 32 bytes for AES-256-GCM / HMAC-SHA256
    purpose: KeyPurpose   # ENCRYPTION | INTEGRITY
    retired: bool

class KeyPurpose(str, Enum):
    ENCRYPTION = "encryption"
    INTEGRITY = "integrity"

def load_key_material(path: Path, *, purpose: KeyPurpose) -> KeyRecord:
    """O_NOFOLLOW + fstat-validated load, mirroring
    config.py::_open_key_file / _validate_key_file_descriptor exactly.
    Raises Tier1Error subclass on any validation failure."""

class NonceCounter:
    """Durable, fsync-before-return monotonic counter scoped to one
    KeyRecord. One instance per active encryption key."""
    def __init__(self, path: Path, *, key_id: str) -> None: ...
    def next(self) -> int:
        """Increments and fsyncs before returning. Raises
        KeyExhaustedError once the retirement threshold (I4) is reached."""

def rotate_key(
    *,
    old: KeyRecord,
    new: KeyRecord,
    store: SqliteRecoveryContractStore,
    decrypt: Callable[[ProtectedArtifact], bytes],
    encrypt: Callable[[bytes], ProtectedArtifact],
) -> RotationReport:
    """Re-encrypts every stored artifact under `new`, one contract at a
    time, inside the store's existing transactional replace path — never
    a bulk unauthenticated rewrite. See Recovery behavior for the
    required incremental/resumable design."""
```

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Key file missing/wrong permissions/symlink | `fstat()` validation | `Tier1Error`, process cannot decrypt or encrypt | No |
| Nonce counter file corrupted/unreadable | Parse/fsync-marker check at load | Refuse to encrypt under this key; decrypt-only operations unaffected | No |
| Nonce counter exhausted | Threshold check in `NonceCounter.next()` | `KeyExhaustedError`; forces rotation before further `create()` calls | No |
| Rotation interrupted mid-way (process crash) | Rotation is per-contract and idempotent (see Recovery) | Some contracts under old key, some under new; both remain decryptable | Resume, not retry-from-scratch |
| Two `KeyRecord`s with the same `key_id` loaded simultaneously | `key_id` uniqueness check at load | Refuse to start | No |

## Recovery behavior

- **Rotation must be incremental and resumable, not atomic-for-the-whole-
  store.** `rotate_key()` iterates contracts one at a time using the
  store's existing `_replace()` compare-and-set path (already
  transactional per record). If interrupted, some records are under the
  old key and some under the new — this is safe (both keys remain
  available until the old key is explicitly destroyed) and `rotate_key()`
  must be safely re-runnable: it should skip contracts already re-encrypted
  under the target `key_id` (detectable from the stored `ProtectedArtifact.
  key_id` field) rather than assuming a global "rotation in progress" flag.
- The old key is **not** destroyed automatically at the end of a rotation
  run. Destruction is a separate, explicit operator action, performed only
  after confirming (via a count query) that zero stored artifacts
  reference the old `key_id`.
- Losing the nonce counter file (but not the key) is recoverable by
  re-initializing the counter at a value strictly greater than any
  previously observed — but this requires manual operator action and
  proof (e.g., scanning stored artifacts' implied nonce ranges is not
  possible since nonces are inside ciphertext framing, not stored
  separately) — **the safe default on counter loss is to retire the key
  and rotate**, not to guess a safe restart value.

## Non-goals

- This module does not implement OS keyring, systemd credentials, or
  TPM-sealed key backends. `ADR-010` documents why the local-file pattern
  is the v1 recommendation and how a future backend would plug in without
  changing `KeyRecord`'s shape.
- This module does not handle the anti-rollback anchor's key/counter (see
  `whole_store_anti_rollback.md`) — that is a structurally different
  counter with different durability requirements (must be independent of
  this host's filesystem) and must not be implemented in this module.
- This module does not decide *when* to rotate (schedule/policy) — that is
  an operational runbook decision, out of scope for this spec, though
  `ADR-010` recommends a default cadence.

## Required tests

- Load succeeds for a correctly-permissioned key file; fails for
  world/group-readable, symlinked, oversized, or missing files (mirror
  `config.py`'s existing key-file test matrix exactly).
- `NonceCounter.next()` returns strictly increasing values across
  repeated calls, including across process restarts against the same
  counter file.
- Simulated crash between `next()`'s fsync and the caller's use of the
  value: restarting must never re-issue an already-used counter value
  (test by killing the "process" — i.e., not calling `next()` again — and
  asserting the persisted counter already reflects the increment).
- `KeyExhaustedError` raised at the documented threshold, not after it.
- `rotate_key()` resumability: interrupt after N of M contracts rotated
  (fault-hook pattern, same as `store.py`'s existing `FaultHook`), restart
  `rotate_key()`, assert all M end up under the new key and none are
  double-processed or corrupted.
- Two keys with colliding `key_id` at load time → refused.

## Activation requirements

- [ ] `ADR-010` accepted.
- [ ] `key_lifecycle.py` implemented and tested per "Required tests".
- [ ] `protected_artifact_encryption.md` implemented and depends on this
      module's `NonceCounter`, not `os.urandom()` directly.
- [ ] Operational runbook exists for: initial key generation, rotation
      cadence, old-key destruction confirmation, and counter-loss recovery
      (the "retire and rotate" path above) — this is documentation, not
      code, but is a hard activation gate because an untested runbook is
      exactly how key material gets mishandled under incident pressure.

## Implementation checklist

- [ ] Create `src/pfsense_mcp/tier1/key_lifecycle.py`.
- [ ] Factor `config.py`'s `_open_key_file`/`_validate_key_file_descriptor`
      logic into a shared helper both `config.py` and `key_lifecycle.py`
      call, rather than duplicating the O_NOFOLLOW/fstat logic a second
      time — this is a refactor of existing, already-tested production
      code and must preserve `config.py`'s current behavior and tests
      exactly (add tests first, refactor, confirm identical behavior).
- [ ] Implement `NonceCounter` with fsync-before-return ordering.
- [ ] Implement `rotate_key()` as a resumable per-contract loop.
- [ ] Add `KeyExhaustedError` to `errors.py`.

## Review checklist

- [ ] Confirm the shared O_NOFOLLOW/fstat helper extraction did not change
      `config.py`'s existing observable behavior (diff the test suite
      output before/after the refactor, not just re-reading the code).
- [ ] Confirm `NonceCounter.next()` truly fsyncs before returning — check
      for `os.fsync(fd)` on the actual file descriptor, not just a
      buffered write that a reviewer might mistake for durable.
  - [ ] Confirm rotation never holds both old and new plaintext for a
      contract in memory longer than one record's re-encryption — no
      batch-decrypt-then-batch-encrypt that would multiply the amount of
      plaintext resident in memory at once.

## Security checklist

- [ ] No key material in logs, exceptions, or audit events (grep-based
      test across all failure paths, same discipline as
      `protected_artifact_encryption.md`'s security checklist).
- [ ] Key file directory is verified distinct from the SQLite store's
      directory at startup (I1), refusing to start if they coincide.
- [ ] Confirm the nonce counter threshold in `ADR-010`/`ArtifactAlgorithm`
      is consistent between `key_lifecycle.py` and
      `protected_artifact_encryption.md` — a mismatch here is exactly the
      kind of cross-module inconsistency the architecture review flagged
      once already (MAC framing) and must not recur.

## Test checklist

- [ ] Key file permission/ownership/symlink rejection tests (parity with
      `config.py`'s existing suite).
- [ ] Nonce monotonicity test, including simulated-crash variant.
- [ ] Key exhaustion threshold test.
- [ ] Rotation resumability test with fault injection.
- [ ] Duplicate `key_id` rejection test.
- [ ] Negative test: `key_lifecycle.py` has zero forbidden imports (AST
      isolation test).
