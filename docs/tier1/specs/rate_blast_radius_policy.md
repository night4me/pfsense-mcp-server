# Tier 1 — Rate and blast-radius policy

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 2 (concurrency) / Milestone 9 (numeric defaults
require lab evidence); requires
[ADR-015](../../adr/ADR-015-rate-and-blast-radius-defaults.md).
Related: [sealed_executor.md](sealed_executor.md),
[disposable_lab_execution_model.md](disposable_lab_execution_model.md).

## Purpose

Define atomic, store-backed damage-containment limits that apply
**regardless of authorization** — a fully authorized, fully confirmed
mutation can still be refused by this layer if it would exceed a
concurrency or frequency bound. This is explicitly not an authorization
mechanism (policy.py and the confirmation/reconciliation authorities
remain the only authorization); it exists so a single misbehaving or
compromised caller cannot turn "one approved capability" into "unbounded
mutation of that capability."

## Security goals

- G1: No more than one mutation can be `EXECUTING`/`ROLLING_BACK` per
  canonical target at a time (already structurally guaranteed by the
  existing target-reservation mechanism in `store.py` — this spec does
  not duplicate that, only extends the same atomic pattern to
  coarser-grained scopes).
- G2: A capability's or the whole system's total in-flight mutation count
  is bounded and enforced atomically, independent of how many distinct
  targets are involved.
- G3: A caller cannot bypass a cooldown by preparing a new contract for
  the same target immediately after a prior one completes.
- G4: Systemic trouble (many contracts stuck in `RECONCILIATION`
  simultaneously) automatically halts new mutation preparation, without
  requiring a human to notice and intervene first.
- G5: Rate-limit bookkeeping itself cannot be used to leak information
  (it must not record target identity, intent, or any sensitive value —
  counts and digests only, consistent with the existing audit-value-
  freedom principle).

## Invariants

- I1: All counters are maintained in the same SQLite store, using the
  same `BEGIN IMMEDIATE` atomic-transaction pattern already used for
  contract state, so a rate check and the state transition it gates
  cannot race against each other.
- I2: Rate/concurrency checks happen at `PREPARE` time (before a contract
  is created) for outstanding-count limits, and at the `PREPARED ->
  EXECUTING` transition for in-flight limits — mirroring the two-phase
  shape the rest of the system already uses (prepare vs. execute are
  already separate authorization moments).
- I3: A refused `PREPARE` due to rate policy produces **no** contract row
  at all (nothing to clean up, no partial state) — refusal happens before
  `store.create()` is called.
- I4: Cooldown timers use the store's own clock abstraction
  (`Clock`/`_now()`, already injectable for deterministic testing in
  `store.py`) — never wall-clock time read independently elsewhere, to
  keep rate logic testable the same way contract expiry already is.
- I5: The global `RECONCILIATION` lockout (G4) is itself a rate-policy
  state, not a manual flag an operator sets — it activates automatically
  when the threshold is crossed and deactivates automatically once the
  count drops below it (no separate "re-enable" action needed, though an
  operator resolving reconciliations is what naturally clears it).

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Rate policy vs. authorization | `MutationPolicy`/confirmation/reconciliation (authorization) | Rate/concurrency counters (containment only) | Rate policy is checked *in addition to*, never *instead of*, authorization — a rate-policy pass never substitutes for a policy/confirmation check |
| Single caller vs. system-wide budget | Global/per-capability counters | Any individual `PREPARE`/`execute()` call | Atomic counter increments inside the same transaction as the state change they gate |

## State ownership

- New SQLite table `rate_counters` (or equivalent), owned by
  `src/pfsense_mcp/tier1/rate_policy.py` (new module) and a corresponding
  schema addition in `store.py` (same `_verify_schema` exact-match
  discipline as every other table).
- Scopes tracked: per-`target_identity_digest`, per-`capability`, and one
  global singleton row — three logical scopes, not a generic arbitrary-
  key system, to keep the schema closed and reviewable.
- `rate_policy.py` does not own contract state — it only reads/writes its
  own counters and is consulted by `store.py`/`executor.py` at the two
  checkpoints in I2.

## Interfaces

```python
# src/pfsense_mcp/tier1/rate_policy.py (new; not created yet)


@dataclass(frozen=True)
class RateLimits:
    max_outstanding_prepared_per_target: int
    max_global_in_flight: int
    target_cooldown_seconds: int
    reconciliation_lockout_threshold: int


class RatePolicy:
    def __init__(self, limits: RateLimits) -> None: ...

    def check_prepare_allowed(
        self,
        connection: sqlite3.Connection,
        *,
        target_identity_digest: str,
        capability: Capability,
        now: datetime,
    ) -> None:
        """Raises RateLimitExceededError if outstanding-PREPARED, cooldown,
        or reconciliation-lockout limits would be violated. Must run
        inside the same transaction as the eventual store.create() call
        it gates — i.e. this is called from within store.py, not before
        a separate connection is opened."""

    def check_execute_allowed(self, connection: sqlite3.Connection, *, now: datetime) -> None:
        """Raises RateLimitExceededError if max_global_in_flight would be
        exceeded. Called from within the same transaction as the
        PREPARED -> EXECUTING _replace() call."""

    def record_terminal(self, connection: sqlite3.Connection, *, target_identity_digest: str, now: datetime) -> None:
        """Records the cooldown start for a target reaching any terminal
        state (VERIFIED, FAILED, ROLLED_BACK, ROLLBACK_FAILED)."""
```

`RateLimitExceededError` is a new `Tier1Error` subclass — refusal, not a
different kind of state transition; a rate-limited `PREPARE` attempt
leaves no trace beyond an ordinary refusal (I3), matching how a policy
refusal today leaves no contract row.

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Target already has an outstanding `PREPARED` contract | Count query inside `check_prepare_allowed` | `RateLimitExceededError`, no new contract created | No |
| Target in cooldown window | Cooldown timestamp comparison | Same | No — caller must wait, not retry in a loop |
| Global in-flight limit reached | Count query inside `check_execute_allowed` | `RateLimitExceededError` at the `EXECUTING` transition; contract remains `PREPARED` | No |
| Reconciliation lockout active | Count of contracts in `RECONCILIATION` >= threshold | All new `PREPARE` calls refused system-wide until the count drops | No — resolved only by an operator resolving existing reconciliations |

## Recovery behavior

- All counters are derived, at any point, from the existing contract
  table's state (outstanding `PREPARED` count, in-flight `EXECUTING`/
  `ROLLING_BACK` count, and `RECONCILIATION` count are all just `COUNT(*)
  ... WHERE state = ...` queries) **except** the cooldown timestamps,
  which need their own small table since cooldown outlives the state
  transition that triggered it. On restart, no counters need
  reconstruction beyond the cooldown table, which is itself durable
  SQLite state and survives restart normally.
- This design deliberately avoids in-memory-only counters specifically so
  that a restart cannot reset rate limits to zero and accidentally permit
  a burst right after recovery — durability of the containment layer
  matters as much as durability of the authorization layer.

## Non-goals

- This spec does not implement per-MCP-caller rate limiting — the trust
  model (`THREAT_MODEL.md` TB1) already treats the local stdio channel as
  one undifferentiated caller; rate policy here is about capability/
  target/global blast radius, not per-user quota.
- This spec does not implement adaptive/ML-based anomaly detection —
  fixed, reviewable, owner-approved numeric limits only (`ADR-015`).
- This spec does not implement a way to override the limits at runtime
  (no "admin bypass" flag) — changing limits requires a configuration
  change and restart, so a limit change is always a deliberate,
  reviewable action, not something reachable from an MCP tool call.

## Required tests

- Outstanding-`PREPARED`-per-target refusal and recovery once the
  existing one terminates.
- Cooldown refusal immediately after a terminal state, success after the
  cooldown window elapses (using the injectable clock, not real sleep).
- Global in-flight limit refusal at the `EXECUTING` boundary specifically
  (not at `PREPARE`), and recovery once an in-flight operation
  terminates.
- Reconciliation-lockout activation at exactly the threshold, and
  automatic deactivation once resolved below it.
- Concurrency test: simultaneous `PREPARE` attempts for the same target
  from multiple connections — exactly one succeeds if the limit is 1
  (same atomic-transaction discipline as the existing target-reservation
  tests).
- Restart test: cooldown state survives a store restart.

## Activation requirements

- [ ] `ADR-015` accepted with numeric defaults validated by
      `disposable_lab_execution_model.md`'s lab evidence, not shipped as
      permanent guesses. **The current implementation ships ADR-015's
      provisional defaults as the only defaults offered** — no lab
      evidence exists yet to revise them.
- [x] `rate_policy.py` implemented and tested
      (`tests/tier1/test_rate_policy.py`, 7 tests).
- [x] `store.py` schema extended (version bump to 4) and wired at the two
      checkpoints in I2, plus `record_terminal` wired into `_replace()`
      (fires for every state change reaching a cooldown state, regardless
      of which method drove it — `transition()`, `resolve_reconciliation()`,
      etc.).
- [ ] `executor.py` calls `check_execute_allowed` immediately before its
      own `EXECUTING` transition (see `sealed_executor.md`'s verification
      flow — this spec adds one more pre-transition check to that
      sequence). **Not yet applicable** — `executor.py` does not exist
      until Phase 3; `store.transition()`'s own `EXECUTING` branch already
      calls `check_execute_allowed` directly today, so the check is fully
      enforced at the store layer independent of whether an executor
      exists yet.

## Implementation checklist

- [x] Create `src/pfsense_mcp/tier1/rate_policy.py`.
- [x] Add `RateLimitExceededError` to `errors.py`.
- [x] Extend `store.py` schema with a `rate_cooldowns` table (schema
      version bumped to 4, following the exact discipline established for
      the anchor_state table's v3 bump). Deliberately unauthenticated (no
      `mac` column) — containment, not an authorization/integrity
      boundary; documented inline in the schema SQL.
- [x] Wire `check_prepare_allowed`/`check_execute_allowed`/
      `record_terminal` into `store.py`'s `create()`/`transition()`/
      `_replace()`.

## Review checklist

- [ ] Confirm every count query used for a limit check runs inside the
      same `BEGIN IMMEDIATE` transaction as the state change it gates —
      a check-then-act pattern across two transactions would reintroduce
      exactly the race this design exists to prevent.
- [ ] Confirm `RateLimitExceededError` never contains target
      identity/intent content (G5) — counts and digests only.
- [ ] Confirm the reconciliation lockout genuinely blocks **all**
      capabilities' `PREPARE` calls, not just the capability that
      produced the reconciliations (systemic trouble should pause
      everything, not just the misbehaving capability, until an operator
      has assessed the situation).

## Security checklist

- [ ] Confirm no rate-limit bypass exists via a code path that skips
      `store.create()`/`store.transition()` (there should be exactly one
      way to create/transition a contract, so this is largely inherited
      from existing store discipline, but must be explicitly re-verified
      once `rate_policy.py` is wired in).
- [ ] Confirm cooldown/limit values are read from configuration, not
      hardcoded, so they can be tightened without a code change if lab or
      production experience warrants it — but confirm there is no
      *runtime* (in-process, MCP-reachable) way to change them (Non-goals).

## Test checklist

- [ ] Per-target outstanding-PREPARED test.
- [ ] Cooldown refusal/recovery test (injectable clock).
- [ ] Global in-flight limit test.
- [ ] Reconciliation lockout activation/deactivation test.
- [ ] Same-target concurrent PREPARE race test.
- [ ] Restart durability test for cooldown state.
