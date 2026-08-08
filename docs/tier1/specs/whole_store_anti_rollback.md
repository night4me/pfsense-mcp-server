# Tier 1 — Whole-store anti-rollback

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 3; requires
[ADR-011](../../adr/ADR-011-whole-store-anti-rollback-anchor.md).
Related: `tests/tier1/test_store.py::test_whole_store_rollback_remains_
an_explicit_external_anchor_blocker` (existing, executable proof of the
gap this spec closes).

## Purpose

Detect and refuse the one class of attack the current store cannot defend
against by construction: an attacker (or a careless backup/restore
procedure) replacing the entire SQLite file with an older, internally
self-consistent, correctly-HMAC-authenticated copy. Every record-level
check in `store.py` passes against such a copy today, because the HMAC
key and verification logic were the same when the old copy was genuine.
This spec adds one additional check — comparing store state against an
**independent** monotonic anchor — that a same-file, same-directory
attacker cannot roll back along with the database.

## Security goals

- G1: Restoring any earlier, internally-valid copy of the store is
  detected at the next store operation, before any contract state is
  trusted or any mutation is permitted.
- G2: The anchor itself cannot be rolled back by an attacker who can only
  modify the store's own file or directory — it must live outside that
  blast radius (independent device, independent host, or independent
  administrative domain).
- G3: Anchor unavailability at startup or at any mutating operation is a
  hard stop for mutation, never a silent skip of the check.
- G4: The anchor check does not require the anchor to be consulted on
  every read-only operation (load/audit inspection) — only before a
  mutating state transition is allowed to proceed — so anchor
  unavailability degrades to "read-only, cannot mutate," not "server
  unusable."

## Invariants

- I1: The store maintains a monotonically increasing **high-water mark**
  (the maximum `state_version` ever committed, summed across all
  contracts, or an equivalent strictly-increasing counter) that is
  reported to the anchor on every committed state transition.
- I2: Before any transition into `EXECUTING` (the state that authorizes an
  actual send), the anchor's currently-recorded value must **exactly
  equal** the store's own last-persisted high-water mark — not merely be
  greater-than-or-equal. Under normal single-writer operation the two are
  always equal immediately before a new attempt: the previous attempt
  advanced the anchor by exactly one and persisted that same new value.
  A restored older store file remembers a *smaller* mark than the
  (untouched, externally durable) anchor now reports
  (`anchor > persisted`); a tampered or reset anchor reports a *smaller*
  value than the (unaffected) file remembers (`anchor < persisted`). Both
  directions are real anomalies and both must refuse — only exact
  equality proceeds. **Implementation note (corrected during Phase 2
  implementation):** an earlier draft of this invariant specified
  `anchor < persisted` as the sole detection condition. That check is
  wrong for the primary threat this subsystem exists to address —
  restoring an old file makes the file's mark *smaller*, not the
  anchor's, so `anchor < persisted` never fires for a whole-store
  rollback. `tests/tier1/test_anti_rollback.py::
  test_whole_store_rollback_is_detected_when_anchor_configured` caught
  this with a real DID-NOT-RAISE failure before the fix landed. The
  corrected, implemented, and tested condition is exact inequality in
  either direction (`current != persisted`), not one-sided comparison.
  A store with no persisted mark yet defaults to comparing against `0`
  — deliberately, not treated as "nothing to compare" — because a store
  restored to a point *before* its first-ever `EXECUTING` attempt is
  indistinguishable, from the file alone, from a genuinely fresh store
  (see `whole_store_anti_rollback.py::HighWaterMark.read`'s docstring).
  The configured anchor must therefore be dedicated to the store and
  start at `0`, or be explicitly provisioned to the correct baseline as
  part of the concrete backend's setup procedure — this is a provisioning
  responsibility for `ADR-011`'s chosen backend, not something this
  generic class can safely infer.
- I3: The anchor update and the store's local transaction commit are not
  required to be a single atomic operation (that would require distributed
  transactions across two independent systems, which is disproportionate
  here) — but the **order** is fixed: anchor advance must be confirmed
  **before** the local `EXECUTING` transition commits, never after. A
  crash between the two leaves the anchor ahead of the store, which is
  the safe direction (see Failure modes).
- I4: The anchor mechanism is pluggable behind one interface (see
  Interfaces) so that a TPM-based implementation and a remote-witness
  implementation are interchangeable without changing `store.py`.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Local SQLite file vs. anchor | Anchor's independently-durable counter | Any copy/backup/restore of the SQLite file | Anchor comparison before `EXECUTING` (I2) |
| Anchor availability vs. mutation | "Anchor reachable and confirmed" | "Anchor unreachable" | Hard refusal of mutation-path transitions (G3); read paths unaffected (G4) |

## State ownership

- `src/pfsense_mcp/tier1/anti_rollback.py` (new module) owns the
  `AntiRollbackAnchor` protocol and the store-side high-water-mark
  bookkeeping helper `HighWaterMark`.
- `store.py` gains one new call site: immediately before the
  `PREPARED -> EXECUTING` transition's `_replace()` call, it consults the
  configured `AntiRollbackAnchor`. `store.py` does not know which
  concrete anchor implementation is in use — it depends only on the
  protocol.
- The anchor's own durable state (TPM NV index value, or the remote
  witness log) is owned entirely outside `pfsense_mcp` — this repository
  only owns the client code that talks to it.

## Interfaces

```python
# src/pfsense_mcp/tier1/anti_rollback.py (new; not created yet)


class AntiRollbackAnchor(Protocol):
    def read(self) -> int:
        """Return the anchor's current monotonic value. Raises
        AnchorUnavailableError if the anchor cannot be reached/read."""

    def advance(self, *, expected_current: int) -> int:
        """Atomically advance the anchor past expected_current and return
        the new value. Raises AnchorConflictError if the anchor's actual
        current value does not match expected_current (someone else
        advanced it, or it moved backward — both are refusals, never
        auto-resolved). Raises AnchorUnavailableError if unreachable."""


class HighWaterMark:
    """Store-side bookkeeping: what value does the store believe the
    anchor was last confirmed at. Persisted in a dedicated, HMAC-
    authenticated `anchor_state` table (schema v3), using the same
    per-row integrity discipline as every other authenticated store
    field. (Implementation note: landed as its own table, not a
    `metadata` key as an earlier draft of this spec suggested — the
    metadata table's existing rows are unauthenticated, and this value
    specifically needs authentication.)"""

    def before_executing_transition(self, anchor: AntiRollbackAnchor, connection: sqlite3.Connection) -> None:
        """Raises WholeStoreRollbackDetected if the anchor's read() value
        does not *exactly equal* the persisted high-water mark (both
        directions are anomalies — see Invariant I2). Raises
        AnchorUnavailableError/AnchorConflictError (propagated) if the
        anchor cannot be reached or advanced — caller must treat this
        identically to a detected rollback for the purpose of refusing
        EXECUTING."""
```

`store.py`'s `transition()` gains one parameter,
`anti_rollback_anchor: AntiRollbackAnchor | None`, defaulting to `None`
(no anchor configured — see Activation requirements for why `None` must
itself refuse `EXECUTING` once this spec is implemented, not silently skip
the check). This is an additive, backward-compatible signature change to
an already-inert module.

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Whole-store rollback (old copy restored) | `HighWaterMark.before_executing_transition` sees anchor behind local mark | `WholeStoreRollbackDetected`; every interrupted/executing contract forced to `RECONCILIATION` at next reconciliation scan | Never |
| Anchor temporarily unreachable | `AnchorUnavailableError` from `read()`/`advance()` | `EXECUTING` transitions refused; `PREPARED`, load, audit-inspection unaffected | Caller may retry the anchor call later; the mutation itself is never auto-retried |
| Anchor and store both crash mid-transition, anchor already advanced | On restart, anchor `read()` ahead of local high-water mark | Safe: this is the expected "anchor ahead" case, not rollback; store proceeds normally, updates its local high-water mark to match | N/A |
| Two processes race to advance the anchor | `advance()`'s `expected_current` mismatch | `AnchorConflictError`; caller must re-read and retry the *anchor* call (not the mutation) or refuse | Anchor-level retry only, never blind |

## Recovery behavior

- On every store startup, before `reconcile_interrupted()` runs, read the
  anchor once and compare to the persisted high-water mark. A detected
  rollback at this point must force **every** non-terminal contract into
  `RECONCILIATION`, not just ones that were `EXECUTING`/`ROLLING_BACK` —
  because a whole-store rollback can also reintroduce contracts that were
  already `VERIFIED`/`FAILED` locally-terminal but whose real-world
  outcome is now unknown relative to the restored point in time.
- If the anchor is unreachable at startup, the store must still start
  (read-only operations continue to work — G4) but must set an internal
  "mutation refused: anchor unavailable" flag that every `EXECUTING`
  transition attempt checks and reports clearly, rather than failing with
  a generic error that looks like a different kind of bug.

## Non-goals

- This spec does not select the anchor backend (TPM vs. remote witness) —
  that is `ADR-011`. It defines the interface both backends must satisfy.
- This spec does not implement distributed consensus, leader election, or
  multi-writer coordination for the anchor — this server is a single
  local process; the anchor only needs to detect *this* process's store
  being rolled back, not coordinate multiple writers.
- This spec does not attempt to make whole-store rollback **impossible**
  (that would require the SQLite file itself to be unwritable by the
  operating account, which contradicts the server's own need to write it)
  — only **detectable before it can authorize a new mutation**. A rollback
  that only affects already-terminal, already-audited history is a
  forensic/audit concern, not something this spec tries to prevent.

## Required tests

- Extend the existing
  `test_whole_store_rollback_remains_an_explicit_external_anchor_blocker`
  test: after adding the anchor check, the identical rollback scenario
  must now raise `WholeStoreRollbackDetected` (or force reconciliation) at
  the next `EXECUTING` attempt, where today it silently succeeds — this
  test is the direct, measurable proof this spec closes the gap the prior
  review confirmed.
- Anchor-ahead test (normal case): store restarts with anchor correctly
  ahead → no false positive, `EXECUTING` proceeds normally.
- Anchor-unavailable test: `EXECUTING` refused; `PREPARED`/load/audit
  operations unaffected.
- Anchor-conflict test (concurrent advance): `advance()` raises
  `AnchorConflictError`; store does not silently proceed.
- Fake/in-memory `AntiRollbackAnchor` test double used throughout
  `tests/tier1/` (never a real TPM or network call in offline tests, per
  existing `MockTransport`-equivalent conventions).

## Activation requirements

- [ ] `ADR-011` accepted, naming the concrete anchor backend for the
      actual production deployment target. **(Genuine owner/infrastructure
      decision — blocked pending TPM availability confirmation on the
      actual production host; not resolved by this implementation pass.)**
- [x] `anti_rollback.py` implemented and tested (protocol + store-side
      bookkeeping; concrete backend deliberately not implemented — see
      above).
- [ ] `store.py` modified to require a non-`None` anchor before any
      `EXECUTING` transition is permitted **once this spec activates** —
      i.e., the `anti_rollback_anchor=None` default must itself become a
      refusal path at activation time, not a silent bypass. **Deliberately
      not done in this implementation pass**: `store.py`'s current
      behavior preserves `anti_rollback_anchor=None` as "check skipped,"
      not "refused," so the 223 pre-existing Tier 1 tests that drive
      contracts through `EXECUTING` without configuring an anchor
      continue to pass unchanged. Flipping this default is the correct
      activation-time behavior but requires ADR-011's backend to be
      selected first (there is no anchor to require yet) and, separately,
      updating every existing test that exercises `EXECUTING` to inject a
      test-double anchor — tracked as follow-up work for whoever performs
      activation, not deferred silently.
- [ ] Anchor backend concretely provisioned and reachable in the target
      deployment (TPM present and initialized, or remote witness endpoint
      configured) — verified as part of Milestone 8 (private test-
      appliance acceptance), not assumed.

## Implementation checklist

- [x] Create `src/pfsense_mcp/tier1/anti_rollback.py` with the
      `AntiRollbackAnchor` protocol and `HighWaterMark`.
- [x] Add `WholeStoreRollbackDetected` and `AnchorUnavailableError` /
      `AnchorConflictError` to `errors.py`.
- [x] Add the high-water-mark storage to `store.py`'s schema (schema
      version bump to 3, per the existing `_SCHEMA_VERSION` /
      `_verify_schema` discipline). Landed as a dedicated, HMAC-
      authenticated `anchor_state` table rather than a `metadata` key, as
      an earlier draft of this spec suggested — `metadata`'s existing
      rows are unauthenticated, and this value specifically needs
      authentication (see Invariant I2's implementation note).
- [x] Wire the anchor check into `transition()` immediately before the
      `PREPARED -> EXECUTING` `_replace()` call — opt-in via the
      constructor's `anti_rollback_anchor` parameter (see Activation
      requirements above for why the default stays permissive for now).
- [ ] Implement the chosen concrete anchor backend per `ADR-011` as a
      separate module (e.g., `anti_rollback_tpm.py` or
      `anti_rollback_remote.py`) implementing the protocol — keep the
      protocol and the concrete backend in separate files so the protocol
      stays swappable. **Blocked on `ADR-011`.**

## Review checklist

- [ ] Confirm the anchor check happens **before** the `_replace()` call
      commits, not after — an after-the-fact check cannot prevent the
      unsafe transition from having already been recorded.
- [ ] Confirm anchor unavailability really does block `EXECUTING` in a
      test, not just in the docstring.
- [ ] Confirm the schema-version bump follows the existing
      `_verify_schema` exact-match discipline (type/nullability/PK/UK/FK),
      not just a new column name.
- [ ] Confirm a rollback that reintroduces a `VERIFIED`/`FAILED` (locally
      terminal) contract is still caught by the startup-time anchor check,
      not only by the `EXECUTING`-time check (Recovery behavior, second
      bullet).

## Security checklist

- [ ] Confirm the anchor backend implementation cannot be satisfied by
      anything living in the same 0700 directory as the SQLite store —
      review the concrete backend's storage location explicitly against
      this requirement (G2), don't just trust the interface name.
- [ ] Confirm `AnchorConflictError`/`AnchorUnavailableError` messages
      contain no key material, no anchor credentials, no store contents.

## Test checklist

- [ ] Regression test on the existing whole-store-rollback proof (must
      now detect, not just document, the rollback).
- [ ] Anchor-ahead (normal), anchor-unavailable, anchor-conflict tests.
- [ ] Startup-time detection test for reintroduced terminal contracts.
- [ ] Schema-version bump test (old-schema store refuses to open under
      new code, per existing `_verify_schema` test pattern).
