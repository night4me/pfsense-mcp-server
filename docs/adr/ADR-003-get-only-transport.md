# ADR-003: GET-only production transport chokepoint

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

Tool naming and operator intent are insufficient to prove that a request cannot
mutate an appliance. HTTP method enforcement must occur at the lowest practical
production boundary and be mechanically testable.

## Decision

`RestApiClient` is the only production client allowed to call the transport and
it rejects every method other than GET. Domain clients call its `get()` method
with explicit `EndpointInfo` records. Static analysis checks permitted transport
call sites.

Tier 0 has a separate `WriteApiClient` chokepoint, but production bootstrap does
not construct it and its endpoint allow-list is empty. The READ client will not
be generalized to accept mutation methods.

## Consequences

### Positive

- A tool/domain bug cannot switch the production READ client to POST/PUT/PATCH/
  DELETE.
- The method boundary is small and obvious in review.
- MockTransport tests can assert exact method and path.

### Negative

- READ and future WRITE transports have some duplicated concerns.
- GET endpoints with upstream side effects still require endpoint-level review.
- Static allow-lists must be updated carefully when architecture changes.

## Alternatives considered

- **Method parameter on one general client:** rejected because it weakens the
  primary safety invariant.
- **Enforce GET only in tool functions:** rejected because lower layers could
  bypass it.
- **Rely solely on upstream read-only credentials:** rejected as insufficient
  defense in depth and environment-dependent.

## References

- [Threat model](../THREAT_MODEL.md)
- [ADR-001](ADR-001-read-only-production-architecture.md)
