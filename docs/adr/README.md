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

New ADRs should use the next sequence number and contain status, context,
decision, consequences, alternatives, and references.
