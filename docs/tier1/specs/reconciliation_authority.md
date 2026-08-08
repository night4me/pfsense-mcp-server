# Tier 1 — Reconciliation authority

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 6; requires
[ADR-013](../adr/ADR-013-reconciliation-authority.md).
Related: [confirmation_authority.md](confirmation_authority.md) (this spec
reuses its signature mechanism), `state_machine.py`'s
`RECONCILIATION -> {VERIFIED, FAILED, ROLLING_BACK, ROLLED_BACK,
ROLLBACK_FAILED}` manual-only edges (existing, currently unreachable by
any code — no resolver exists yet).

## Purpose

Define the authenticated service that resolves a contract sitting in
`RECONCILIATION` — the state a contract enters whenever the true
real-world outcome of a mutation or rollback attempt cannot be proven
automatically (timeout after send, lost response, ambiguous read-back).
Today, `store.py` has no code path that ever leaves `RECONCILIATION`; this
spec defines the one path that will exist, and it must be at least as
strong an authority check as confirmation, because a wrong reconciliation
decision is exactly as dangerous as a wrong initial mutation — it directly
sets the contract's final, trusted, audited state.

## Security goals

- G1: Only a human operator who has independently observed pfSense's
  actual state can resolve a `RECONCILIATION` — never an automatic
  inference from HTTP status, response presence, or elapsed time.
- G2: A reconciliation decision cannot be reused for a different contract
  or a different resolution than the one specifically signed.
- G3: A reconciliation decision cannot be forged by anything with only
  MCP-caller-level access (no prompt, no tool argument, no LLM output can
  satisfy this).
- G4: The recorded reconciliation outcome is exactly one of a small,
  closed set of typed conclusions — never free text that a downstream
  reader would have to interpret.

## Invariants

- I1: Reconciliation evidence reuses `ConfirmationEvidence`'s shape
  conceptually but is a **distinct type** (`ReconciliationEvidence`) bound
  via a distinct `DigestPurpose` (new: `RECONCILIATION`), so a
  confirmation signature can never be presented as a reconciliation
  signature or vice versa (domain separation, same principle
  `canonical.py` already applies to target-identity vs. fingerprint vs.
  intent digests).
- I2: `ReconciliationEvidence` binds `contract_id`, `operation_id`, the
  contract's state at the time of observation (`state_version`), and the
  **declared outcome** (one of the closed enum values below) into what is
  signed — so the signature covers not just "I looked" but "I looked and
  concluded X."
- I3: The declared outcome enum is exactly:
  `CONFIRMED_APPLIED` (mutation took effect; store should move toward
  `VERIFIED`), `CONFIRMED_NOT_APPLIED` (mutation did not take effect;
  store should move toward `FAILED`), `CONFIRMED_ROLLBACK_APPLIED`
  (rollback took effect; `ROLLED_BACK`), `CONFIRMED_ROLLBACK_NOT_APPLIED`
  (`ROLLBACK_FAILED`). There is no `UNKNOWN`/`RETRY` value — an operator
  who cannot determine the outcome does not resolve the contract; it
  remains in `RECONCILIATION` until they can.
- I4: Resolution requires the contract's `state_version` at resolution
  time to match what the evidence was signed against (the same
  compare-and-set discipline `store.py` already applies everywhere else)
  — a reconciliation decision signed against a stale view of the contract
  is refused, not silently applied to whatever the current state happens
  to be.
- I5: The resolver, like the confirmation verifier, never persists raw
  proof bytes and never leaks which specific check failed.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Operator observation vs. automated inference | Signed `ReconciliationEvidence` | Any HTTP status/timing/heuristic the executor observed | `RECONCILIATION` is manual-only in `state_machine.py` (existing); no automated path in or out |
| Reconciliation signature vs. confirmation signature | Distinct `DigestPurpose.RECONCILIATION` | A confirmation signature for the same contract | Domain-separated digest (I1) — cannot be cross-presented |
| Declared outcome vs. actual pfSense state | Operator's independent read of pfSense (outside this system) | The contract's own stored (possibly stale/ambiguous) view | This module does not verify the outcome is *true* — that is the operator's responsibility outside the system; the module verifies only that an authorized operator *declared* it (see Non-goals) |

## State ownership

- `src/pfsense_mcp/tier1/reconciliation.py` (new module) owns
  `ReconciliationEvidence`, `ReconciliationVerifier` (Protocol, mirroring
  `ConfirmationVerifier`'s shape exactly), and the resolution function
  that performs the store transition.
- `store.py` gains one new method, `resolve_reconciliation()` (see
  Interfaces) — this is new store surface, not a repurposing of
  `transition()`, because reconciliation resolution has a different
  authorization requirement (`ReconciliationEvidence`, not
  `ConfirmationEvidence`) and a different set of legal target states.

## Interfaces

```python
# src/pfsense_mcp/tier1/reconciliation.py (new; not created yet)

class ReconciliationOutcome(str, Enum):
    CONFIRMED_APPLIED = "confirmed_applied"
    CONFIRMED_NOT_APPLIED = "confirmed_not_applied"
    CONFIRMED_ROLLBACK_APPLIED = "confirmed_rollback_applied"
    CONFIRMED_ROLLBACK_NOT_APPLIED = "confirmed_rollback_not_applied"

_OUTCOME_TARGET_STATE = {
    ReconciliationOutcome.CONFIRMED_APPLIED: RecoveryState.VERIFIED,
    ReconciliationOutcome.CONFIRMED_NOT_APPLIED: RecoveryState.FAILED,
    ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED: RecoveryState.ROLLED_BACK,
    ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED: RecoveryState.ROLLBACK_FAILED,
}

@dataclass(frozen=True)
class ReconciliationEvidence:
    authority_id: str
    algorithm: str
    contract_id: str
    operation_id: str
    observed_state_version: int
    outcome: ReconciliationOutcome
    issued_at: datetime
    proof: bytes
    # __post_init__ validation mirrors ConfirmationEvidence exactly
    # (safe-token checks, UTC checks, bounded proof size).

    @property
    def evidence_digest(self) -> str:
        """digest_value(DigestPurpose.RECONCILIATION, {...}) — same
        construction discipline as ConfirmationEvidence.evidence_digest."""

class ReconciliationVerifier(Protocol):
    def verify(self, evidence: ReconciliationEvidence) -> bool: ...

# store.py addition:
def resolve_reconciliation(
    self,
    contract_id: str,
    *,
    evidence: ReconciliationEvidence,
) -> RecoveryContract:
    """Loads contract, requires state == RECONCILIATION and
    state_version == evidence.observed_state_version, requires a
    configured ReconciliationVerifier (fail closed if None, identical
    discipline to confirm()), verifies evidence, transitions to
    _OUTCOME_TARGET_STATE[evidence.outcome] with manual=True (the one
    legitimate caller of require_transition(..., manual=True) in the
    entire codebase), records the resolution as an audit event distinct
    from ordinary state_transition (event_type="reconciliation_resolved")."""
```

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| No verifier configured | Same fail-closed check as `confirm()` | `ConfirmationError`-family exception; contract remains in `RECONCILIATION` | No |
| Forged/invalid signature | `ReconciliationVerifier.verify()` returns `False` | Refused; contract remains in `RECONCILIATION` | No |
| Stale `observed_state_version` | Compare-and-set mismatch | `ContractConflictError`; operator must re-observe current state and re-sign | No — this is intentional: a stale observation must not resolve a contract that has since changed |
| Evidence for wrong contract/operation | Binding check (mirrors `ConfirmationEvidence.verify_bindings`) | Refused | No |
| Contract not actually in `RECONCILIATION` | `state == RECONCILIATION` precondition | Refused (`ContractConflictError`) | No |

## Recovery behavior

- A contract can remain in `RECONCILIATION` indefinitely — this is by
  design (`is_terminal()` in `state_machine.py` already excludes
  `RECONCILIATION` from terminal states, meaning it's expected to persist
  across restarts until resolved). No automatic timeout moves it anywhere
  else; adding one would reintroduce an automatic-inference path this
  spec specifically forbids (G1).
- If the whole-store anti-rollback anchor (see
  `whole_store_anti_rollback.md`) detects a rollback, contracts that were
  previously resolved out of `RECONCILIATION` and are reintroduced at an
  earlier state must be forced back into `RECONCILIATION` — the
  resolution history for that specific `state_version` sequence is no
  longer trustworthy relative to the current real world.

## Non-goals

- This module does not verify that the operator's declared outcome is
  actually true — it verifies only that a specific authorized operator,
  identified by a valid signature, declared a specific outcome for a
  specific contract at a specific observed state. Ensuring the operator
  actually checked pfSense correctly is an operational/runbook
  responsibility (see `disposable_lab_execution_model.md` and the
  eventual production runbook), not something software can verify.
- This module does not implement multi-party approval (e.g., two
  operators must agree) for v1. `ADR-013` records this as a considered,
  rejected-for-now option and the condition under which it should be
  revisited (e.g., if reconciliation events become frequent enough to
  justify the added friction).
- This module does not attempt to automatically retry the original
  mutation under any circumstance — reconciliation only records what
  happened; it never causes a second send.

## Required tests

- Valid evidence with each of the four `ReconciliationOutcome` values →
  contract transitions to the correct target state.
- Stale `observed_state_version` → refused, contract state unchanged.
- Evidence bound to a different `contract_id`/`operation_id` → refused.
- No verifier configured → refused (fail-closed parity with `confirm()`).
- Contract not in `RECONCILIATION` → refused.
- Cross-domain replay: a valid `ConfirmationEvidence` signature bytes
  cannot be reinterpreted as valid `ReconciliationEvidence` (different
  digest purpose makes the signed bytes different) — explicit test, not
  just an assumption.
- Audit event for `reconciliation_resolved` is present, correctly
  chained, and HMAC-verified alongside ordinary `state_transition` events
  in `_verified_audit_rows`.

## Activation requirements

- [ ] `ADR-013` accepted.
- [ ] `reconciliation.py` implemented and tested.
- [ ] `store.resolve_reconciliation()` implemented and tested.
- [ ] Operator runbook exists describing exactly how to independently
      observe pfSense's actual state for each capability before signing
      a reconciliation decision — capability-specific, written alongside
      the first adapter (see `capability_adapter_contract.md`), not
      generic.
- [ ] Reuses the same signing tool built for
      `confirmation_authority.md` (extended to support the
      `RECONCILIATION` digest purpose), not a second, separately-built
      tool.

## Implementation checklist

- [ ] Create `src/pfsense_mcp/tier1/reconciliation.py`.
- [ ] Add `DigestPurpose.RECONCILIATION` to `canonical.py`.
- [ ] Add `store.resolve_reconciliation()`.
- [ ] Add `reconciliation_resolved` as a recognized `event_type` alongside
      `contract_created`/`contract_confirmed`/`state_transition` (extend,
      don't replace, the existing audit event-type vocabulary).

## Review checklist

- [ ] Confirm `resolve_reconciliation()` is the **only** caller of
      `require_transition(..., manual=True)` in the codebase — grep to
      verify no other code path can exit `RECONCILIATION`.
- [ ] Confirm the four-outcome enum has no gap that would let an operator
      express "I don't know" as anything other than not resolving the
      contract at all.
- [ ] Confirm evidence digest construction is genuinely domain-separated
      from `ConfirmationEvidence`'s (write the cross-domain-replay test
      before declaring this done, not after).

## Security checklist

- [ ] No raw proof bytes persisted (parity check with `confirm()`'s
      existing behavior).
- [ ] Failure messages generic, no distinguishing detail (I5).
- [ ] Confirm `resolve_reconciliation()` cannot be reached with a
      `ConfirmationEvidence` object by type-checking alone (mypy strict
      mode should already catch this given distinct types, but add an
      explicit runtime `isinstance` guard as defense in depth, consistent
      with how the rest of `tier1` favors explicit checks over implicit
      trust in type annotations).

## Test checklist

- [ ] All four outcome-transition tests.
- [ ] Stale-version refusal test.
- [ ] Cross-contract binding refusal test.
- [ ] Cross-domain (confirmation vs. reconciliation) signature refusal
      test.
- [ ] Fail-closed-with-no-verifier test.
- [ ] Audit event presence/chaining test.
- [ ] Negative test: module has zero forbidden imports (AST isolation).
