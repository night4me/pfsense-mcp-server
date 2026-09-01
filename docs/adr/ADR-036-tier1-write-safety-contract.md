# ADR-036: Tier1 WRITE Safety Contract — Architecture Gap Closure Before Any Second Capability

- **Status:** Proposed
- **Date:** 2026-09-01

## Context

A design-only mission (`reports-ai/POST_READ_CLOSURE_WRITE_ARCHITECTURE_THREAT_MODEL.md`)
was commissioned to determine whether the existing Tier1 WRITE architecture
is a sufficient foundation for exposing carefully-controlled pfSense
mutations in future releases, and, if so, what the first implementation
slice should be. The single most important finding of that review is that
the premise needed correcting: `set_firewall_alias_description_v1`
(`FIREWALL_ALIAS_DESCRIPTION`, `PATCH` on a firewall alias's `descr` field
only) is not a design candidate. It is a fully implemented, twice
live-LAB-verified (including once via a dedicated least-privilege pfSense
identity), explicitly owner-authorized capability, shipped in the
v0.4.0/v0.4.1/v0.4.2 release line and documented today in `README.md` and
`docs/SECURITY_MODEL.md`. It remains live and reachable now for any
operator who explicitly selects `PFSENSE_PROFILE=write_protected` and
completes the full Tier1 production-runtime configuration. `docs/
TIER1_ROADMAP.md`'s own Milestone 9 status line already records this:
"this decision has been made for `set_firewall_alias_description_v1` only
... does not lower the bar for any future second capability, which
requires this same milestone satisfied independently."

The correct question this ADR answers is therefore not "should WRITE be
implemented" but: **what, precisely, must be true before this project adds
a second WRITE capability, or materially changes the first one's
architecture** — the exact bar Milestone 9 already sets, made concrete.

A full source-first reconstruction of the existing Tier1 execution
lifecycle, an ADR-005/006/012–016/020–029 revalidation against current
code, a 451-operation mutation-surface inventory, and an adversarial
concurrency/replay/failure review (all detailed in the companion report)
found the architecture substantially more mature than the commissioning
mission assumed: 11 of 17 reviewed security properties are already fully
enforced by tested, live code (fail-closed TOCTOU preconditions, semantic
postcondition verification beyond HTTP status, atomic burn-on-failure
replay resistance, least-privilege credential derivation that generalizes
automatically to future capabilities, capability-scoped tool registration
that makes a disabled tool genuinely absent from `tools/list`, and an
out-of-band offline-signing confirmation model that is structurally
resistant to prompt-injection-driven self-approval). Four gaps and two
unconfirmed items remain.

## Decision

**No new WRITE capability, endpoint, or tool is authorized by this ADR.**
Before any second WRITE capability is added, or before any change is made
to the first capability's authorization/execution/recovery machinery, the
following four gaps must close (this project's own "W0" stage):

1. **`risk_class` must gate execution behavior.** It is currently computed
   and cryptographically signed as part of the authorization payload
   (`security_authorization.py`) but is absent from `tier1/policy.py`'s
   `MutationPolicy`/`MutationRule` and unreferenced anywhere in
   `execution_coordinator.py`'s or `alias_description_execution.py`'s
   decision logic — nothing currently varies confirmation strength, rate
   limits, or required anchor assurance based on it. At minimum, a future
   HIGH- or CRITICAL-risk-class capability must be prevented from executing
   without `hardware_witness` anchor assurance, enforced in code, not by
   convention.
2. **One canonical authorization-gate implementation, not two.** The
   live `alias_description_execution.py::authorize_and_create()` and the
   unused, generic `tier1/execution_coordinator.py::ExecutionCoordinator`
   independently implement the identical five-gate
   verify→expiry→plan/step→freshness→consume sequence. A future author
   extending this system must not have to guess which is authoritative.
   Pick one; delete or explicitly mark the other as an intentionally
   unused scaffold with a stated reason.
3. **Confirmed, bounded reconciliation cadence.** `reconcile_interrupted()`
   correctly moves any contract stuck in `EXECUTING`/`ROLLING_BACK` to
   manual `RECONCILIATION`, but only runs on the next `MutationExecutor`
   construction. No watchdog, health check, or documented operational
   runbook was found guaranteeing this happens within a bounded time after
   a process crash.
4. **A written, capability-independent semantic-postcondition
   specification.** `adapter.is_semantically_verified(pre, post, intent)`
   is real, adapter-specific code; no document exists describing what any
   future adapter must guarantee (allowed normalization, timeout/retry
   policy, handling of unexpected extra changes).

Two further items are unconfirmed, not proven broken, and should be
resolved (read the relevant code, then either close or reclassify as a
gap) as part of the same W0 pass: the alias-description adapter's own
semantic-verification logic was not read in full by the commissioning
review, and the exact behavior at a "journal finalization failure"
boundary was not located.

**Non-negotiable invariants preserved by this decision, all independently
re-verified against current source as part of the companion review:**
read_only default posture; managed read_only least privilege; explicit,
reviewed endpoints only (`WriteEndpoints`, mechanically enforced to
contain exactly its current entries); no generic API dispatch (the live
upstream `POST /api/v2/graphql` mutation gateway is permanently rejected
from consideration for exactly this reason); no arbitrary HTTP
method/path; plan-before-mutation; explicit, off-host, non-forgeable
authorization; fail-closed ambiguity handling; `write_protected`
isolation from the default profile; Recovery Contract/journal semantics;
optional stronger TPM/witness assurance. None of these are weakened,
extended, or reinterpreted by this ADR.

## Consequences

### Positive

- A concrete, small, achievable gap list replaces an open-ended "design
  the WRITE architecture" mandate — closing four items, not building a
  system from scratch.
- `risk_class` enforcement closes a real defense-in-depth gap without
  touching the already-verified precondition/postcondition/replay
  machinery.
- Resolving the `ExecutionCoordinator` duplication removes a genuine
  source of future-author confusion before it causes an incident.
- The existing capability's live-qualification rigor (privilege-isolated
  LAB evidence, twice) becomes the documented, mandatory template for any
  future capability, rather than an implicit precedent someone might not
  reproduce.

### Negative

- W0 work touches code paths (`tier1/policy.py`, the authorization-gate
  sequence) that the currently-shipped, currently-live capability depends
  on — any change here requires the same rigor as a new capability's own
  qualification, including possibly re-gathering live evidence if the
  change is not purely additive (see the companion report's W1/W3 stages).
- This ADR does not itself decide whether `set_firewall_alias_description_v1`
  should remain live while W0 proceeds — that is an explicit operational
  risk-acceptance call for the owner, not resolved here.

## Alternatives considered

- **Treat the existing capability as a template and immediately design a
  second one:** rejected — `docs/TIER1_ROADMAP.md`'s own Milestone 9
  explicitly requires each capability to satisfy the full milestone
  framework independently, and this review found four gaps in the shared
  machinery a second capability would inherit unchanged.
- **Leave `risk_class` as a display-only field indefinitely:** rejected —
  a signed-but-unenforced field is worse than no field, since its presence
  implies a security property (risk-conditioned behavior) that does not
  actually exist.
- **Consolidate `ExecutionCoordinator` and the inline copy by writing a
  third implementation:** rejected here as a decision this ADR makes in
  advance — the correct resolution (which one becomes canonical) is an
  implementation-time call informed by which one is actually easier to
  extend safely, not something to pre-decide without writing the code.

## References

- `reports-ai/POST_READ_CLOSURE_WRITE_ARCHITECTURE_THREAT_MODEL.md`
  (gitignored, external — the full 33-phase design review this ADR
  summarizes)
- [ADR-005](ADR-005-inert-tier-0-write-infrastructure.md)
- [ADR-006](ADR-006-recovery-contract-philosophy.md)
- [ADR-012](ADR-012-confirmation-authority.md)
- [ADR-014](ADR-014-sealed-executor-interface.md)
- [ADR-022](ADR-022-execution-authorization-boundary.md)
- [ADR-024](ADR-024-execution-authorization-coordination.md)
- [ADR-026](ADR-026-first-write-capability-adapter.md)
- [ADR-028](ADR-028-first-write-product-surface-and-delivery.md)
- [ADR-033](ADR-033-pfsense-least-privilege-bootstrap-architecture.md)
- [Tier 1 roadmap](../TIER1_ROADMAP.md)
