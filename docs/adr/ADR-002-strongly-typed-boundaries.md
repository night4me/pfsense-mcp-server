# ADR-002: Strongly typed public boundaries

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

pfSense returns endpoint-specific JSON whose shape can vary by API version,
package, and appliance state. Passing arbitrary dictionaries to MCP callers
would make schemas vague, leak unexpected upstream fields, and defer validation
to consumers.

## Decision

Each public tool returns explicit Pydantic models or bounded lists of those
models. `PfSenseClient` performs shape checks and maps raw JSON through
endpoint-specific factories. Malformed data becomes a typed, sanitized
`PfSenseResponseShapeError`.

Models enumerate allowed public fields. Extra upstream data does not become
public merely because the appliance returns it.

## Consequences

### Positive

- MCP schemas are discoverable and stable enough to review.
- Credential fields can be excluded structurally.
- Callers receive consistent types rather than endpoint-specific raw data.
- Tests can prove both mapping and non-disclosure.

### Negative

- Model and mapping code is repetitive.
- Upstream schema evolution requires deliberate model changes.
- Large client/model test modules accumulate over time.

## Alternatives considered

- **Return raw JSON:** rejected for disclosure and compatibility risk.
- **One generic response model:** rejected because it hides endpoint semantics.
- **Generate models directly from live OpenAPI at runtime:** rejected because
  runtime discovery is unreviewed, variable, and can expose unintended fields.

## References

- [API reference](../API.md)
- [ADR-007](ADR-007-security-first-public-schemas.md)
