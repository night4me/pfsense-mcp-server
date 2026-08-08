# ADR-006: Recovery Contract philosophy

- **Status:** Accepted; inert domain implementation, activation prerequisites incomplete
- **Date:** 2026-08-06

## Context

A successful mutating HTTP response is not sufficient evidence that an
appliance can be recovered. Mutation can target the wrong object, race external
changes, time out after applying, or crash between side effect and state
persistence. Rollback must be designed before execution, not improvised after a
failure.

## Decision

Every future mutation requires a short-lived Recovery Contract created from
verified pre-state. The authoritative contract must be loaded by ID from a
store and be immutably bound to capability, endpoint, method, canonical target,
mutation intent, snapshot, rollback plan, and legal state transition.

Execution and rollback use atomic transitions. HTTP outcome plus semantic
read-back is required before commitment/restoration. Ambiguous outcomes enter an
operator-reconciliation state and are never blindly replayed.

No Tier 1 activation occurs until persistence and crash behavior are explicitly
accepted.

The v0.3.0 development framework implements the pure contract,
canonicalization, closed transitions, authenticated atomic store, exact empty
policy, fault classification, and value-free event model in an isolated
package. This is an implementation of the safety philosophy, not activation:
there is no executor, endpoint, capability, transport wiring, or MCP tool.
Encryption/key management, whole-store anti-rollback, authenticated owner
confirmation, and capability-specific outcome/rollback semantics remain
explicit prerequisites.

## Consequences

### Positive

- Recovery becomes a precondition rather than a best-effort feature.
- Contract substitution/replay and wrong-target risks have explicit controls.
- Crash/timeout ambiguity is represented honestly.

### Negative

- Tier 1 requires durable state, canonicalization, concurrency, and operational
  runbooks before one tool can ship.
- Snapshots create sensitive-data storage and lifecycle obligations.
- Some pfSense mutations may prove unsuitable as an initial capability.

## Alternatives considered

- **Caller-supplied contract object:** rejected because caller state is not
  authoritative.
- **In-memory snapshot only:** rejected for production crash recovery.
- **Rollback after any error without read-back:** rejected because outcome may
  already be unknown and replay may compound damage.
- **Confirmation boolean only:** rejected because consent is not recovery.

## References

- [Tier 1 roadmap](../TIER1_ROADMAP.md)
- [Threat model](../THREAT_MODEL.md)
