# ADR-020: Milestone 0 — first WRITE capability candidate authorization

- **Status:** Accepted — candidate naming authorization only. Does not
  authorize implementation, the live disposable-lab run, WRITE allow-list
  population, WRITE capability activation, or any production activation.
- **Date:** 2026-08-10
- **Accepted:** 2026-08-10 — owner authorized naming firewall-alias
  description-only `PATCH` as `TIER1_ROADMAP.md`'s Milestone 0 candidate,
  exactly as recommended by the decision package this ADR records,
  explicitly scoped to naming only.

## Context

`TIER1_ROADMAP.md`'s Milestone 0 ("capability and threat-model
selection") requires a separate, explicit owner authorization naming one
candidate capability and exact pfSense endpoint/method before any
adapter design work is meaningful — the roadmap deliberately does not
choose the first capability itself. `ADR-016` (Accepted, 2026-08-08)
previously authorized spending *disposable-lab research time* on this
same candidate specifically, but explicitly stated that authorization
"does not authorize any endpoint, adapter, tool, capability, or
production activation" — it was research-time authorization, not
Milestone 0's own naming decision. This ADR closes that specific,
narrower gap.

A dedicated decision-preparation review (Phase 5 owner-decision package,
2026-08-10 — recorded externally in `reports-ai/reviews/
PHASE_5_MILESTONE_0_DECISION_PACKAGE_2026-08-10.md`, not duplicated here)
re-evaluated `WRITE_ENDPOINT_RISK_MATRIX.md`'s existing recommendation
against the current accepted architecture, Recovery Contract model,
`capability_adapter_contract.md`, the threat model, and
`docs/tier1/PHASE_5_READINESS_REVIEW_2026-08.md`, and attempted to
falsify it rather than assume it correct because it already existed. No
falsifying finding was produced; no better-evidenced alternative exists
in the 240-endpoint inventory.

## Decision

**Firewall-alias description-only `PATCH`
(`/api/v2/firewall/alias`, `descr` field only) is named as
`TIER1_ROADMAP.md` Milestone 0's first WRITE capability candidate.**

This is the only entry in `WRITE_ENDPOINT_RISK_MATRIX.md`'s complete
240-endpoint inventory rated an unconditional "T1 candidate" — every
other entry is `Critical`/`Defer`/`Reject`, or (the system-tunable
description-only `PATCH` fallback) explicitly rated weaker ("T1
conditional... rejected unless the lab proves..."). The matrix's own text
states no third candidate meets the combination of a verified READ
dependency, stable non-numeric natural identity, deterministic rollback,
no credential effect, and narrow blast radius that this candidate and its
one weaker fallback share.

### Exact scope named

- **Endpoint / operation:** `PATCH /api/v2/firewall/alias`. The exact
  request shape must still be independently confirmed against the
  disposable-lab appliance's own generated OpenAPI document before an
  adapter is written — `WRITE_ENDPOINT_RISK_MATRIX.md`'s source review
  predates any live verification and is explicitly labeled "discovery
  evidence, not sufficient OpenAPI or appliance verification."
- **Mutable field:** `descr` (description) only.
- **Forbidden fields:** `name`, `type`, address/content entries, `detail`,
  bulk fields, create, delete, and apply/reload — any field not in this
  approved projection. `capability_adapter_contract.md`'s
  `extra="forbid"` `TypedWriteRequest` requirement is the structural
  enforcement, not merely a stated intent.
- **Natural identity:** exact normalized alias `name`; numeric `id` is a
  transient locator only, never authoritative.
- **Capability:** a new adapter scoped to the existing (currently
  inactive) `Capability.ALIAS_WRITE` enum member — one tool, one
  capability, exactly one fixed underlying client method, per the
  permanent MCP dispatch invariant.

## What this authorization grants

- Permission to proceed with concrete `CapabilityAdapter`
  interface/design work for this specific candidate (still design-only —
  no code path becomes reachable by this alone).
- Justification to provision the disposable-lab VM for Milestone 8, since
  the candidate that lab run must exercise is now named.
- The naming deliverable of `TIER1_ROADMAP.md` Milestone 0
  ("Name one candidate capability and exact pfSense endpoint/method").

## What this authorization does NOT grant

- **Implementation** of any `CapabilityAdapter`, `TypedWriteRequest`, or
  intent model for this candidate.
- **The live disposable-lab run** (Milestone 8) — its own separate,
  later, command-level approval, requiring a disposable/non-production
  test appliance.
- **WRITE allow-list population** — `WriteEndpoints` remains empty;
  `scripts/write_allow_list_check.py` continues to enforce this
  mechanically.
- **WRITE capability activation** — `Capability.ALIAS_WRITE` remains
  outside `SUPPORTED_CAPABILITIES_THIS_BUILD`.
- **Any production activation, MCP tool registration, or public contract
  change.**
- Resolution of Milestone 0's remaining, *empirically lab-dependent*
  deliverables: proving natural-identity uniqueness rules, confirming
  upstream API semantics/idempotency/response codes/concurrency behavior,
  and identifying the read-back endpoint. `ADR-016`'s own self-challenge
  already established that code review cannot resolve these — they
  require Milestone 8's live lab evidence, not merely being named here.
- Resolution of `ADR-011`'s anti-rollback backend selection — an
  independent gate, unchanged by this decision.

## Consequences

### Positive

- Unblocks scoping the adapter's concrete interface design against a
  named, evidenced target instead of a hypothetical one.
- Converts the standing "no candidate named" blocker into a "candidate
  named, lab evidence pending" state — a real, visible step forward
  without touching any security boundary.

### Negative / residual risk

- The candidate's safety remains fundamentally unproven until Milestone
  8's live lab run — this ADR names the target, it does not validate it.
  Aliases feed firewall rule evaluation; an unproven implicit reload or
  unrelated-field rewrite triggered by a "descriptive" update remains the
  named, un-closed residual risk `WRITE_ENDPOINT_RISK_MATRIX.md` itself
  flags.

## Alternatives considered

System-tunable description-only `PATCH` — the only other candidate with
any evidence behind it in `WRITE_ENDPOINT_RISK_MATRIX.md`/
`TIER1_ACTIVATION_DECISIONS.md`. Explicitly rated weaker: tunables are
closer to raw system/kernel configuration, and the description/value
coupling is unproven and plausibly worse than the alias candidate's own
risk profile. Not recommended unless the alias candidate's eventual lab
run surfaces a disqualifying finding, per `ADR-016`'s own already-accepted
position — unchanged by this ADR. No third, previously-unconsidered
candidate was identified or invented; the 2026-08-10 decision-package
review searched the full 240-endpoint inventory specifically for one and
found none.

## References

- [TIER1_ROADMAP.md](../TIER1_ROADMAP.md) — Milestone 0 and Milestone 8.
- [WRITE_ENDPOINT_RISK_MATRIX.md](../WRITE_ENDPOINT_RISK_MATRIX.md) — the
  240-endpoint inventory and comparative ratings.
- [TIER1_ACTIVATION_DECISIONS.md](../TIER1_ACTIVATION_DECISIONS.md) —
  Candidate 1/2 technical detail.
- [ADR-016](ADR-016-alias-candidate-lab-authorization.md) — prior
  research-time-only authorization on the same candidate.
- [capability_adapter_contract.md](../tier1/specs/capability_adapter_contract.md) —
  the interface this candidate's eventual adapter must satisfy.
- [PHASE_5_READINESS_REVIEW_2026-08.md](../tier1/PHASE_5_READINESS_REVIEW_2026-08.md) —
  the readiness review this decision responds to.
- `reports-ai/reviews/PHASE_5_MILESTONE_0_DECISION_PACKAGE_2026-08-10.md`
  (external, operational record — not in Git) — the full comparative
  analysis and attempted falsification behind this decision.
