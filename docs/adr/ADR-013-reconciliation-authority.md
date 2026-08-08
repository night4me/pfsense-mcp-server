# ADR-013: Reconciliation authority

- **Status:** Accepted
- **Date:** 2026-08-08
- **Accepted:** 2026-08-08 — implemented as `reconciliation.py`/
  `reconciliation_providers.py` (Phase 2); status field corrected to
  match already-merged implementation.

## Context

`RECONCILIATION` is a manual-only state in `state_machine.py` with no
resolver anywhere in the codebase today — a contract that enters it stays
there indefinitely. A resolution decision is exactly as consequential as
an initial confirmation (it sets the contract's final, trusted, audited
outcome), so it needs an authority at least as strong.

## Options considered

| Option | Strengths | Costs |
|---|---|---|
| **Reuse the confirmation signing mechanism, distinct digest domain (recommended)** | No new cryptographic primitive to review; reuses the already-recommended signing tool | Requires extending that tool to support a second digest purpose |
| Separate reconciliation-specific authority/key | Allows separation of duties (different person resolves ambiguity than approves mutation) | Optional, not mandatory — recorded as allowed but not required, since it adds operational overhead without being necessary for a first capability |
| Multi-party approval (two operators must agree) | Reduces single-operator error risk | Meaningfully more friction; not justified until reconciliation events are frequent enough to warrant it |
| Automatic inference from HTTP status/timing | Removes the human step entirely | Directly contradicts the state machine's own design intent — `RECONCILIATION` exists specifically because automatic inference was judged unsafe; rejected outright |

## Recommendation

Reuse the Ed25519 detached-signature mechanism from ADR-012, with a
distinct `DigestPurpose.RECONCILIATION` domain separator so a confirmation
signature can never be replayed as a reconciliation signature. The
resolution's declared outcome is one of exactly four typed values
(applied / not-applied / rollback-applied / rollback-not-applied) — never
free text. Separate reconciliation-specific keys are permitted for
deployments that want separation of duties, but not required. Full
specification:
[reconciliation_authority.md](../tier1/specs/reconciliation_authority.md).

### Self-challenge

*"Isn't requiring a full cryptographic signature for reconciliation
excessive compared to, say, an authenticated CLI session performing the
resolution?"* — Considered and rejected: an authenticated CLI session
still needs *something* proving the operator's identity and their
specific declared conclusion for this specific contract at this specific
observed state — which is exactly what the signed evidence already
provides. A "logged-in session did X" audit trail is weaker than a
portable, independently verifiable signed artifact, and building a second,
weaker authority mechanism alongside the confirmation one adds complexity
without adding safety.

*"Should the four-outcome enum include an explicit 'escalate/unresolved'
value instead of just never resolving?"* — Rejected: adding such a value
would let an operator "resolve" a contract into an unresolved-shaped
terminal state, which defeats the purpose. Not resolving *is* the correct
representation of "still unknown" — `RECONCILIATION` staying
`RECONCILIATION` indefinitely is not a bug to be papered over with a fifth
enum value, it is the state machine correctly refusing to manufacture
certainty that doesn't exist.

## Consequences

### Positive

- No new cryptographic mechanism, only a domain-separated reuse of an
  already-recommended one.
- Structured outcome typing prevents ambiguous or freeform resolution
  records from entering the audit trail.

### Negative

- A contract can remain in `RECONCILIATION` indefinitely if the operator
  is unavailable or unable to determine the true outcome — an intentional
  tradeoff, not a defect, but an operational reality that must be
  reflected in the eventual runbook.

## Future migration path

Multi-party approval can be added later as an additional requirement
layered on top of the existing single-signature check (e.g., requiring
two distinct `authority_id` signatures for `RECONCILIATION` resolution)
without changing `ReconciliationEvidence`'s shape. Revisit if
reconciliation frequency in production experience justifies the added
friction.

## References

- [reconciliation_authority.md](../tier1/specs/reconciliation_authority.md)
- [ADR-012](ADR-012-confirmation-authority.md)
- `src/pfsense_mcp/tier1/state_machine.py` (existing manual-only edges)
