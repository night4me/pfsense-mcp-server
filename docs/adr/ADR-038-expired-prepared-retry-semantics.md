# ADR-038: Expired/terminal-PREPARED retry semantics

- **Status:** Accepted (2026-09-05, owner). Implemented (Slices 1-2).
- **Date:** 2026-09-05
- **Scope:** Architecture and implemented behavior for
  `idempotency_key` uniqueness scope and PREPARED-contract retry. Does not
  authorize or describe CLI/operator/MCP-tool exposure of `expire_prepared()`
  -- that remains a separate, future owner decision.

## Context

ADR-025 introduced `idempotency_key` as, in its own words, "a replay guard,
not authorization proof" (see that ADR's field table). Until this ADR, the
recovery-contract store enforced this as a single, global, column-level
`UNIQUE(idempotency_key)` constraint: once any contract existed for a given
semantic idempotency identity, no second contract -- ever, in any state --
could be created for it again.

During the first live Batch-1 authorization pilot (ADR-037), an authorized
`PREPARED` contract's own confirmation window elapsed before confirmation
was delivered. The contract was never confirmed and never executed --
`MutationExecutor` was never contacted, pfSense was never mutated -- but
the global uniqueness constraint meant no fresh, freshly-authorized retry
attempt could ever be created for that exact operation again. A permanently
inert `PREPARED` row blocked all future legitimate use of its own semantic
identity.

## Decision

A historical contract's ability to block a fresh attempt at the same
semantic idempotency identity now depends on its `RecoveryState`, not
merely its existence. `derive_idempotency_key()` itself is unchanged --
byte-for-byte -- so `idempotency_key` values computed before this ADR remain
valid and comparable after it; only the uniqueness *scope* changed, from
"the whole table" to "rows whose real-world outcome is not yet fully,
confidently resolved."

### Classification

`state_machine.blocks_fresh_idempotency_attempt(state)` is the single
source of truth:

| State | Blocks fresh attempt? | Why |
|---|---|---|
| `PREPARING` | Yes | Contract creation itself is not even known to have completed; `_INTERRUPTED_STATES` does not sweep this state on restart. |
| `PREPARED` | Yes | Confirmed-or-not, its real-world outcome is unresolved. |
| `EXECUTING` | Yes | A send may be in flight or ambiguous (see `MutationExecutor`/`faults.py`). |
| `VERIFIED` | Yes, **deliberately** | Every capability adapter's own `prepare()` happens to already refuse a semantically-identical request as a no-op today (verified across all six adapters this ADR's implementation checked), but that is an adapter-authored convention, not a structural invariant this state machine enforces for every future adapter. A deliberate re-application of an already-successful mutation must go through an explicit `ROLLING_BACK -> ROLLED_BACK` cycle first -- a conscious human acknowledgment that the prior success is being unwound -- rather than silently permitting a second, unrelated-looking contract to coexist with an unacknowledged verified one. This is exactly the "did I already do this?" confusion ADR-025's replay guard exists to prevent. |
| `RECONCILIATION` | Yes | Outcome is ambiguous by definition; a human must resolve it first. |
| `ROLLING_BACK` | Yes | Unwind is in flight; not yet resolved either way. |
| `ROLLBACK_FAILED` | Yes | Unwind itself failed; requires manual reconciliation, not a silent parallel attempt. |
| `FAILED` | **No** | ADR-037's own recovery classification already documents FAILED as "proven zero effect" for the boundary/knowledge cases that reach it through the general fault-classification path. (The narrower "2xx received but not semantically verified" sub-case also reaches FAILED via its own explicit `classify_fault()` call in `executor.py::execute()` -- a separate code path from the general boundary/knowledge switch, noted here as a pre-existing design point, not reopened by this ADR.) |
| `ROLLED_BACK` | **No** | An explicitly *verified* rollback proves the live target was confirmed reverted to baseline; a fresh attempt afterward is a new intentional action. |
| `EXPIRED` | **No** | By construction, no legal transition into `EXECUTING` skips the confirmed-and-unexpired check in `store.transition()`; a contract that expired while still `PREPARED` structurally could never have reached pfSense. |

### Schema

The store's `contracts` table drops its column-level
`UNIQUE(idempotency_key)` and replaces it with a partial unique index scoped
to exactly the blocking-state set above (`ux_contracts_active_idempotency`,
`CREATE UNIQUE INDEX ... WHERE state IN (...)`). Historical, non-blocking
rows may freely share an `idempotency_key` with each other and with the one
currently-active row, if any. A v7->v8 migration rebuilds the table via
SQLite's own documented technique (no `ALTER TABLE DROP CONSTRAINT`
exists); no row's `payload`/`mac`/state is altered by the migration, only
the constraint's enforcement scope.

`find_by_idempotency_key()` now returns only the one currently-blocking row,
if any -- this is the check both `authorize_and_create()` implementations
and both composition layers use to decide whether a fresh attempt may
proceed. `find_historical_by_idempotency_key()` is a new, separately-named
API returning every row regardless of state, for audit/lookup purposes
distinct from the active-attempt check.

### `expire_prepared()`

A new, narrow, local-only store primitive: `PREPARED -> EXPIRED`, requiring
exact `PREPARED` state, genuine wall-clock expiry, no confirmation evidence
present, and an exact `expected_version` match (double-expire and
concurrent-caller races both fail cleanly via the normal optimistic-version
check). It makes zero pfSense contact and zero witness/anti-rollback anchor
contact -- proven both by construction (the `PREPARED -> EXPIRED` transition
is a plain state write, never routing through
`HighWaterMark.before_executing_transition()`) and by an adversarial test
using a poisoned anchor stub that raises if touched at all.

**This ADR does not authorize exposing `expire_prepared()` to any CLI
command, MCP tool, or automated sweep.** A separate, previously-identified
observability gap remains open: if a process crashes between the
witness-advance transaction committing and the outer contract-row replace
completing (both required for a `PREPARED -> EXECUTING` transition), the
witness could show an advance that no contract row reflects. This ADR's own
implementation re-examined that gap specifically for `expire_prepared()`'s
safety and concluded it is **not** a blocker for the primitive as
implemented: `expire_prepared()` requires the contract to currently show
`PREPARED`, and a row still showing `PREPARED` structurally proves
`execute()` never advanced it past that state -- the crash window in
question can only occur *after* a row has already left `PREPARED`, which
`expire_prepared()`'s own precondition excludes by construction. The gap
itself is a separate, still-open, real observability limitation (a witness
advance cannot always be attributed to a specific contract attempt after
that specific crash) and remains untouched by this ADR; it does not,
however, make `expire_prepared()` itself unsafe to call under its stated
preconditions. Operator/automated exposure remains a distinct future
decision specifically because releasing an idempotency guard is
security-sensitive independent of this crash-window question.

### Execution-core preflight

Both `authorize_and_create()` implementations (`WriteExecutionCoreV1`,
`AliasDescriptionExecutionCoreV1`) now check `find_by_idempotency_key()`
*before* calling `try_consume()`: a currently-blocking collision is refused
before a fresh authorization is ever consumed. This is a preflight, not a
race guard -- the partial unique index at `create_authorized()`'s `INSERT`
time remains the sole authoritative defense against two attempts racing
between the preflight read and the insert. A losing racer's authorization
is consumed uselessly in that case; this is a pre-existing, documented
reliability property of the one-shot consumption store's ordering
(`try_consume()` precedes contract creation), not newly introduced or
newly fixed by this ADR.

### Composition-layer wiring

`production_runtime.py`'s `request_alias_description_change()` and its
Batch1 analog (`shape_a_acceptance_orchestration.py`'s
`ShapeAAcceptanceOrchestrator.request_change()`) each perform their own
dedup lookup independent of the execution core. Both now distinguish three
cases:

1. A currently-blocking contract exists: existing resume/refuse semantics,
   unchanged.
2. No blocking contract, but terminal historical attempts exist: the
   fixed-inbox authorization artifact is compared against every historical
   attempt's own recorded `authorization_provenance.authorization_id`; a
   match means this artifact was already consumed for that attempt and is
   refused before any consumption is attempted again. A non-matching
   (genuinely fresh) artifact proceeds normally.
3. No historical attempt at all: normal first-attempt path, unaffected.

Case 2 exists because the fixed-inbox artifact-exchange convention never
auto-deletes a consumed artifact, and the durable one-shot consumption
store alone would only catch reuse *after* attempting `authorize_and_create()`
-- later than necessary given the historical row's own provenance already
proves the answer.

## What this ADR does not do

- Does not implement any automatic expiry sweep, background housekeeping,
  or automatic retry. A retry always requires a new, independently
  delivered, genuinely fresh authorization artifact -- never synthesized,
  never inferred from a terminal state, never triggered by this codebase
  on its own.
- Does not delete, archive, or otherwise remove any historical contract row
  or its audit trail. Every historical attempt -- blocking or not -- remains
  permanently queryable via `find_historical_by_idempotency_key()`.
- Does not eliminate the residual preflight/INSERT race described above.
- Does not expose `expire_prepared()` through any CLI, MCP tool, or operator
  workflow.
- Does not change `derive_idempotency_key()`'s inputs, algorithm, or output
  for any existing input tuple.
