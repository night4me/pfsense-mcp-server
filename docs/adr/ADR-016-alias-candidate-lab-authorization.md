# ADR-016: Alias-candidate disposable-lab authorization

- **Status:** Accepted — research authorization only; does not authorize
  any endpoint, adapter, tool, capability, or production activation
- **Date:** 2026-08-08
- **Accepted:** 2026-08-08 — owner authorized disposable-lab research
  time on the firewall-alias description-only candidate specifically, as
  recommended below. The system-tunable fallback remains unauthorized
  unless the alias candidate's lab run surfaces a disqualifying problem.

## Context

`WRITE_ENDPOINT_RISK_MATRIX.md` and `TIER1_ACTIVATION_DECISIONS.md`
identify firewall-alias description-only `PATCH` as the preferred
first-capability design study, with system-tunable description-only
`PATCH` as a weaker fallback. Neither has disposable-lab evidence yet.
This ADR is scoped narrowly: whether to authorize spending lab time on the
alias candidate specifically, not whether to authorize any adapter,
endpoint, or production capability.

## Options considered

| Option | Strengths | Costs |
|---|---|---|
| **Authorize lab research on the alias candidate (recommended)** | Aliases have a stable name-based natural identity, a REST surface that already models partial update, and the smallest plausible blast radius among all 240 inventoried writable endpoint classes | Aliases feed firewall rule evaluation; residual risk that a "descriptive" update triggers broader config writes or implicit reload remains unproven either way — that is exactly what the lab is for |
| Authorize lab research on the system-tunable fallback instead/first | Simpler conceptually (no policy-evaluation coupling) | Tunables are closer to raw system/kernel configuration; description/value coupling is unproven and plausibly worse than the alias candidate's risk profile |
| Authorize both candidates in parallel | Produces comparative evidence faster | Doubles lab provisioning/review effort for a decision that already has a clear technical preference; not justified unless the alias candidate's lab run reveals a disqualifying problem |
| Decline lab authorization entirely for now | Zero risk, zero cost | Blocks all forward progress on Milestone 8/9; not recommended given the framework is otherwise ready for design-phase closure |

## Recommendation

Authorize disposable-lab research on the firewall-alias description-only
candidate first. Do not authorize the system-tunable fallback unless the
alias candidate's lab run surfaces a disqualifying problem (e.g., the lab
proves partial `PATCH` silently rewrites unrelated fields, or triggers an
implicit reload with unacceptable blast radius). This authorization is
strictly research: it does not approve an endpoint, an adapter
implementation, a tool, a capability, or any production activation.

### Self-challenge

*"Given the architecture review explicitly said code review cannot
increase confidence this candidate is safe, why recommend authorizing it
at all rather than waiting for more analysis?"* — Because further
document-level analysis has a diminishing return here: the specific open
questions (does partial PATCH touch unrelated fields, does it trigger
implicit reload, what does concurrent-edit/rollback behavior actually
look like) are empirical facts about the pfSense REST API's actual
behavior that no amount of additional document review can resolve — they
require the disposable lab described in `TIER1_LAB_PLAN.md`. Continuing
to defer lab authorization does not produce more safety, it only delays
producing the evidence that would let a real safety judgment be made.

*"Should this ADR recommend a specific pfSense/pfrest version to pin for
the lab, given the risk matrix was generated against one specific
community-package commit?"* — Yes, implicitly required by
`TIER1_LAB_PLAN.md`'s existing provisioning step 1 ("Install a pinned
pfSense and pfrest package version from verified artifacts") — this ADR
does not re-specify the exact version (that is an operational detail for
whoever executes the lab plan, and should match whatever version the
eventual production appliance actually runs, which is not yet fixed in
these documents) but flags it explicitly as a required input to lab
execution, not something to leave implicit.

## Consequences

### Positive

- Unblocks the one remaining piece of empirical evidence needed before
  any adapter design can move from "design" to "implementation-ready."
- Keeps the fallback candidate available without spending effort on it
  prematurely.

### Negative

- Lab provisioning (VM, synthetic identity, network isolation) is real
  work with a real time cost before any evidence is produced.
- If the alias candidate fails lab evidence, the fallback candidate still
  has zero lab evidence and the project is back to a similar decision
  point, just later.

## Future migration path

If lab evidence disqualifies the alias candidate, this ADR's
recommendation should be revisited and either the system-tunable fallback
or a re-examination of the full 240-class inventory
(`WRITE_ENDPOINT_RISK_MATRIX.md`) should follow, using the same
disqualification evidence to refine the risk criteria for whatever
candidate is considered next.

## References

- [disposable_lab_execution_model.md](../tier1/specs/disposable_lab_execution_model.md)
- [WRITE_ENDPOINT_RISK_MATRIX.md](../WRITE_ENDPOINT_RISK_MATRIX.md)
- [TIER1_ACTIVATION_DECISIONS.md](../TIER1_ACTIVATION_DECISIONS.md)
- [TIER1_LAB_PLAN.md](../TIER1_LAB_PLAN.md)
