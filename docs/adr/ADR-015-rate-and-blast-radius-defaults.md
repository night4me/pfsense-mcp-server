# ADR-015: Rate and blast-radius defaults

- **Status:** Recommended — pending owner decision and lab validation
- **Date:** 2026-08-08

## Context

Authorization (policy, confirmation) answers "is this mutation allowed";
it does not bound how much damage a single authorized-but-misbehaving
caller could cause by repeatedly exercising an approved capability. No
rate or concurrency containment exists in the codebase today beyond the
structural one-`EXECUTING`-per-target guarantee already provided by the
target reservation table.

## Options considered

| Option | Strengths | Costs |
|---|---|---|
| No additional limits beyond target reservation | Simplest | A caller could still rapidly cycle prepare/execute across many *different* targets, or retry aggressively after every terminal outcome; insufficient containment |
| **Atomic store-backed counters at per-target/per-capability/global scope, conservative starting defaults (recommended)** | Reuses existing transactional pattern; defaults are explicitly provisional | Adds schema/complexity; wrong defaults could be either too strict (blocks legitimate use) or too loose (insufficient containment) until lab-validated |
| Externally-configured rate-limiting middleware/proxy | Decouples rate policy from the store | Would sit outside the atomic transaction boundary that gates state transitions, reintroducing exactly the check-then-act race this system otherwise avoids everywhere else; rejected |

## Recommendation

Atomic, store-backed counters (per-target, per-capability, global) with
conservative starting defaults, explicitly marked provisional pending
disposable-lab evidence: global concurrent in-flight = 1, outstanding
`PREPARED` per target = 1, target cooldown = 60 seconds, reconciliation
lockout threshold = 3 simultaneous `RECONCILIATION` contracts. Full
specification:
[rate_blast_radius_policy.md](../tier1/specs/rate_blast_radius_policy.md).

### Self-challenge

*"Is global concurrency of 1 too restrictive to be useful — won't this
make the system feel broken if two unrelated, safe mutations can't run
simultaneously?"* — For the *first* capability, yes, this is intentionally
restrictive, and that is the point: there is no throughput requirement
yet that justifies the added concurrency-interaction risk, and every
additional simultaneous in-flight mutation multiplies the state space a
reviewer must reason about for crash/interleaving correctness. Loosening
this is cheap later (a config change, once lab evidence and production
experience justify it) — starting loose and tightening after an incident
is the wrong order for a system whose entire purpose is avoiding
uncontained mutation.

*"Why pick 3 as the reconciliation lockout threshold instead of 1 (any
reconciliation halts everything) or a higher number?"* — 1 was
considered and rejected as likely too sensitive for a first deployment —
a single ambiguous network blip (e.g., one timeout) would halt the entire
system, which creates pressure to work around the safety mechanism rather
than respect it. A higher threshold (5+) was rejected as too tolerant of
what should be a rare event for a well-behaved capability. 3 is a
judgment call, explicitly not derived from data — hence "pending lab
validation" in this ADR's status, not a final number.

## Consequences

### Positive

- Bounds damage even from a fully authorized, repeatedly-invoked caller.
- Provisional-by-design framing means the numbers can be tightened or
  loosened based on real lab evidence rather than being treated as
  load-bearing decisions made without data.

### Negative

- Very restrictive defaults may require deliberate loosening before the
  system is useful for anything beyond single-operation testing —
  intentional friction, but real friction nonetheless.
- Adds a new schema table and two new checkpoints to review/test.

## Future migration path

Numeric defaults should be revisited explicitly after
`disposable_lab_execution_model.md`'s harness produces evidence (timing
of legitimate operations, frequency of ambiguous outcomes under realistic
fault injection) — this ADR's numbers are a lab starting point, not a
production commitment, and the roadmap should not treat them as settled
until that evidence exists.

## References

- [rate_blast_radius_policy.md](../tier1/specs/rate_blast_radius_policy.md)
- [disposable_lab_execution_model.md](../tier1/specs/disposable_lab_execution_model.md)
