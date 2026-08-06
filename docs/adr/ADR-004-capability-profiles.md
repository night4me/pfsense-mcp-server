# ADR-004: Explicit capability profiles

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

Registering every available tool by import discovery makes exposure difficult
to audit and makes least-privilege profiles ambiguous. The server needs an
authoritative mapping from deployment role to registered MCP surface.

## Decision

Capabilities are explicit enum values. Profiles contain immutable capability
sets. `ToolRegistry.register_all()` uses explicit branches to register each
tool only when its capability is present.

The `auditor` profile contains the accepted READ capability set. The `engineer`
placeholder currently contains no capabilities. Naming, module presence, or a
future endpoint entry never activates a tool automatically.

## Consequences

### Positive

- Tool exposure is deterministic and statically reviewable.
- Tests can assert profile and registration counts.
- Future roles can be designed without reflection or import side effects.

### Negative

- Registry code is verbose.
- Adding a tool requires coordinated capability, profile, registry, and test
  changes.
- Profile names can be misunderstood unless zero-capability placeholders are
  documented clearly.

## Alternatives considered

- **Decorator/module discovery:** rejected because imports could change the
  security surface implicitly.
- **Endpoint-driven registration:** rejected because upstream availability is
  not authorization.
- **One global tool set:** rejected because it prevents role separation.

## References

- [Architecture diagrams](../ARCHITECTURE_DIAGRAMS.md)
- [ADR-007](ADR-007-security-first-public-schemas.md)
