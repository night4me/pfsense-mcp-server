# Architecture Decision Records

ADRs record durable architectural decisions and their trade-offs. They describe
the decision at the time it was accepted; later decisions supersede rather than
silently rewrite earlier context.

| ADR | Decision | Status |
|---|---|---|
| [001](ADR-001-read-only-production-architecture.md) | READ-only production architecture | Accepted |
| [002](ADR-002-strongly-typed-boundaries.md) | Strongly typed public boundaries | Accepted |
| [003](ADR-003-get-only-transport.md) | GET-only production transport chokepoint | Accepted |
| [004](ADR-004-capability-profiles.md) | Explicit capability profiles | Accepted |
| [005](ADR-005-inert-tier-0-write-infrastructure.md) | Inert Tier 0 WRITE infrastructure | Accepted |
| [006](ADR-006-recovery-contract-philosophy.md) | Recovery Contract philosophy | Accepted, prerequisites incomplete |
| [007](ADR-007-security-first-public-schemas.md) | Security-first public schemas | Accepted |
| [008](ADR-008-fail-closed-configuration.md) | Fail-closed configuration validation | Accepted |
| [009](ADR-009-protected-artifact-encryption-provider.md) | Protected-artifact encryption provider | Accepted |
| [010](ADR-010-key-lifecycle-and-delivery.md) | Key lifecycle and delivery | Accepted |
| [011](ADR-011-whole-store-anti-rollback-anchor.md) | Whole-store anti-rollback anchor | Recommended — pending owner decision |
| [012](ADR-012-confirmation-authority.md) | Confirmation authority | Accepted |
| [013](ADR-013-reconciliation-authority.md) | Reconciliation authority | Accepted |
| [014](ADR-014-sealed-executor-interface.md) | Sealed executor interface | Accepted |
| [015](ADR-015-rate-and-blast-radius-defaults.md) | Rate and blast-radius defaults | Accepted (mechanism); numeric defaults provisional |
| [016](ADR-016-alias-candidate-lab-authorization.md) | Alias-candidate disposable-lab authorization | Accepted |

New ADRs should use the next sequence number and contain status, context,
decision, consequences, alternatives, and references.

ADRs 009–016 resolve the remaining Tier 1 activation blockers identified in
`reports-ai/reviews/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`. Each pairs with an
implementation-ready specification under
[`docs/tier1/specs/`](../tier1/specs/); see
[`docs/tier1/IMPLEMENTATION_ROADMAP.md`](../tier1/IMPLEMENTATION_ROADMAP.md)
for the sequencing.
