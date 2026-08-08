# ADR-014: Sealed executor interface

- **Status:** Recommended — pending owner decision
- **Date:** 2026-08-08

## Context

No component in this codebase can currently turn a confirmed Recovery
Contract into an actual pfSense mutation. `TIER1_ARCHITECTURE.md`
describes the required containment properties in prose ("a capability
adapter must never receive a general REST client or raw transport"), but
no concrete interface exists. The prior architecture review identified
this as a genuine gap between "sound concept" and "reviewable design."

## Options considered

| Option | Strengths | Costs |
|---|---|---|
| **One `MutationExecutor` class owning all I/O; adapters as pure-function Protocols (recommended)** | Adapter cannot reach transport even by accident; matches the codebase's existing chokepoint discipline (`RestApiClient`, `WriteApiClient`) | Every new capability requires implementing the full Protocol, which is more upfront work per adapter than a looser design |
| Adapters directly hold a scoped/restricted client | Less boilerplate per adapter | "Scoped" access is a policy convention, not a structural guarantee — a careless or malicious adapter could still misuse it; rejected as insufficiently sealed |
| Generic plugin/reflection-based capability loading | Extensible, less manual wiring | Contradicts the existing "explicit registries, not reflection" principle already established for `ToolRegistry`/`Endpoints`/`WriteEndpoints`; rejected for consistency and auditability |
| Executor per capability (N executors) instead of one shared executor | Simpler per-capability reasoning | No safety benefit over one executor with N adapters, and multiplies the amount of security-critical code (contract loading, policy checks, anchor checks) that must be kept consistent across N copies; rejected |

## Recommendation

Exactly one `MutationExecutor` class, constructed once at (future,
activation-gated) application startup, owning the store, `WriteApiClient`,
`PfSenseClient`, policy, and anti-rollback anchor. Capability adapters
implement a narrow `CapabilityAdapter` Protocol of pure functions with no
transport access, enforced by AST-based isolation tests. Full
specification: [sealed_executor.md](../tier1/specs/sealed_executor.md).

### Self-challenge

*"Doesn't 'one shared executor' create a single point of failure — a bug
in the executor breaks every capability at once?"* — Yes, and this is
accepted as the correct tradeoff, not an oversight: concentrating all
security-critical logic (policy enforcement, target re-verification,
send-count control, outcome classification, audit-completeness) in one
reviewed, heavily-tested component is safer than distributing slightly
different copies of that logic across N adapters, each a potential place
for the same class of mistake to reappear independently. A single
well-tested chokepoint is the same reasoning already applied to
`RestApiClient`/`WriteApiClient` at the transport layer — this ADR extends
that reasoning one layer up, deliberately.

*"Should adapters be allowed to perform their own authoritative re-read,
since they know their capability's specific endpoint best?"* — Rejected:
letting adapters read introduces a second path to pfSense reads outside
`PfSenseClient`, duplicating and potentially diverging from the
already-accepted GET path, and removes the executor's ability to
guarantee "exactly one authoritative re-read, always done the same way."
Adapters receive already-fetched `pre`/`post` snapshots as plain data —
this is a deliberate constraint, not an oversight of adapter
convenience.

## Consequences

### Positive

- Every future capability inherits the same tested acquisition/
  verification/audit machinery automatically.
- Adapter code review can focus entirely on domain correctness
  (fingerprint completeness, request shape) since the security-critical
  parts are structurally out of the adapter's reach.

### Negative

- The executor itself is a large, security-critical component that must
  be exceptionally well-tested before any real capability is authorized
  — concentrating risk as well as safety.
- Every capability must fit the executor's fixed verification/rollback
  shape; a capability whose semantics don't fit this shape (e.g.,
  something with no meaningful read-back) cannot be safely added without
  first revisiting this design.

## Future migration path

If a future capability genuinely cannot fit the single-executor model
(e.g., requires a fundamentally different verification flow), that is a
signal to design a second, equally sealed executor variant with its own
ADR — not to weaken this executor's guarantees to accommodate an
exception. No migration is anticipated for the first capability.

## References

- [sealed_executor.md](../tier1/specs/sealed_executor.md)
- [capability_adapter_contract.md](../tier1/specs/capability_adapter_contract.md)
- [adapter_restrictions.md](../tier1/specs/adapter_restrictions.md)
- `src/pfsense_mcp/write_api_client.py` (existing chokepoint precedent)
