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
| [011](ADR-011-whole-store-anti-rollback-anchor.md) | Whole-store anti-rollback anchor | Backend decided (2026-08-10, TPM-backed host witness) — design-ready, not yet provisioned |
| [012](ADR-012-confirmation-authority.md) | Confirmation authority | Accepted |
| [013](ADR-013-reconciliation-authority.md) | Reconciliation authority | Accepted |
| [014](ADR-014-sealed-executor-interface.md) | Sealed executor interface | Accepted |
| [015](ADR-015-rate-and-blast-radius-defaults.md) | Rate and blast-radius defaults | Accepted (mechanism); numeric defaults provisional |
| [016](ADR-016-alias-candidate-lab-authorization.md) | Alias-candidate disposable-lab authorization | Accepted |
| [017](ADR-017-official-guidance-layer.md) | Official pfSense/Netgate documentation guidance layer | Accepted — architecture and inert scaffolding only; no consumer wired |
| [018](ADR-018-version-aware-guidance-resolution.md) | Version-aware Official Guidance resolution | Accepted — architecture and trust boundaries only; live retrieval, guidance exposure, Tier 1/WRITE/Phase 5 activation not authorized by acceptance; nothing implemented yet |
| [019](ADR-019-api-surface-capability-discovery-and-extension-architecture.md) | API Surface, Capability Discovery, and Extension Architecture | Accepted — vocabulary and evaluation only; individual mechanisms remain separately gated, public contract unchanged |
| [020](ADR-020-milestone-0-first-write-capability-candidate.md) | Milestone 0 — first WRITE capability candidate authorization | Accepted — candidate naming only; implementation, live lab run, allow-list population, and WRITE activation all remain separately gated |
| [021](ADR-021-security-posture-provisioning.md) | Guided security-posture provisioning (`pfsense-mcp-security setup`) | Accepted — architecture/design only; no wizard, posture, WRITE, or fail-closed enforcement authorized |
| [022](ADR-022-execution-authorization-boundary.md) | Execution-authorization boundary (Plan → Authorize → Execute → Verify) | Accepted — architecture/design only; no authorization/execution code, no WRITE tool, no schema change authorized |
| [023](ADR-023-authorization-verification-boundary.md) | Authorization-verification boundary (`ADR-022` Phase D) | Proposed (architecture) — owner decisions made and Phase D implemented under them; not a full `ADR-021`/`ADR-022`-style acceptance |
| [024](ADR-024-execution-authorization-coordination.md) | Execution-authorization coordination boundary (`ADR-022` Phase E/F/G territory) | Proposed (architecture) — Slice E1 (freshness primitive) and Slice E2 (coordinator skeleton through one-time consumption) separately authorized and implemented; Slice E3 and full execution wiring still unauthorized, unimplemented |

New ADRs should use the next sequence number and contain status, context,
decision, consequences, alternatives, and references.

ADRs 009–016 resolve the remaining Tier 1 activation blockers identified in
`reports-ai/reviews/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`. Each pairs with an
implementation-ready specification under
[`docs/tier1/specs/`](../tier1/specs/); see
[`docs/tier1/IMPLEMENTATION_ROADMAP.md`](../tier1/IMPLEMENTATION_ROADMAP.md)
for the sequencing.

ADR-017 is not a Tier 1 subsystem — it is orthogonal, applying eventually
to both the active READ path and the still-inert future WRITE path. Its
companion spec is [`docs/OFFICIAL_GUIDANCE_LAYER.md`](../OFFICIAL_GUIDANCE_LAYER.md),
alongside `TIER1_ARCHITECTURE.md` rather than under `docs/tier1/specs/`.

ADR-021 is likewise not a Tier 1 subsystem — its capability-posture
axis (`read_only`/`write_protected`) is not a Tier 1 concept at all,
and its anchor-assurance axis spans Tier 0/Tier 1 WRITE and the
Tier-1-adjacent anti-rollback anchor independently of it. Its
companion spec is
[`docs/SECURITY_POSTURE_PROVISIONING.md`](../SECURITY_POSTURE_PROVISIONING.md),
following the same top-level placement as ADR-017's.

ADR-022 sits above both ADR-021 (the planning layer) and Tier 1's
existing execution architecture (ADR-006/012/013/014/015) — it governs
how an operator's authority reaches that machinery, and covers two
mutation classes (configuration-file changes, physical TPM provisioning)
Tier 1's `RecoveryContract` was never designed to cover at all. Its
companion spec is
[`docs/EXECUTION_AUTHORIZATION_BOUNDARY.md`](../EXECUTION_AUTHORIZATION_BOUNDARY.md),
same top-level placement.
