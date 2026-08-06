# ADR-005: Inert Tier 0 WRITE infrastructure

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

Future mutation requires recovery, rollback, audit, and allow-list primitives
that are difficult to design safely at the same moment as the first production
side effect. Those primitives needed tests without expanding the current MCP or
network surface.

## Decision

Tier 0 WRITE infrastructure exists as tested library code but is inert by
construction:

- production bootstrap does not construct a write client/store/audit path;
- `WriteEndpoints` has zero entries;
- no WRITE capability is active in any profile;
- no WRITE MCP tool registers;
- `tools/write` is never imported by production code;
- static checks independently enforce these properties.

The READ architecture and `RestApiClient` remain unchanged.

## Consequences

### Positive

- Recovery concepts can be tested before activation.
- Current production risk remains READ-only.
- Multiple independent gates must change intentionally for Tier 1.

### Negative

- Dormant code can be mistaken for production-ready functionality.
- Tests may give false confidence if Tier 1 prerequisites are not tracked.
- Future activation must replace zero-entry assertions with precise manifests,
  not simply delete safety checks.

## Alternatives considered

- **Implement first WRITE tool immediately:** rejected because recovery/crash
  behavior was unresolved.
- **Keep all WRITE design only in prose:** rejected because primitives and
  architectural chokepoints benefit from executable tests.
- **Wire the client but hide tools:** rejected because construction would make
  dormant code unnecessarily reachable.

## References

- [Tier 0 specification](../WRITE_TIER0_SPEC.md)
- [Tier 1 roadmap](../TIER1_ROADMAP.md)
- [ADR-006](ADR-006-recovery-contract-philosophy.md)
