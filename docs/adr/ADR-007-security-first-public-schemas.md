# ADR-007: Security-first public schemas

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

pfSense READ endpoints may return credential material and identifying metadata.
Optional/deprecated model fields still appear in Pydantic and MCP schemas and
can be populated accidentally. A “hidden by default” credential field is still
an unsafe public contract.

## Decision

Credential material is absent from public model definitions entirely. Upstream
credential keys are ignored unconditionally. Optional disclosure flags may
reveal only explicitly classified sensitive operational metadata, never
passwords, PSKs, private keys, plaintext API keys, or stored credential hashes.

Negative tests scan Pydantic schemas, every registered MCP schema, serialized
outputs, logs, errors, and fixtures. Fixture approval hard-fails on prohibited
credential keys even when values are empty or null.

## Consequences

### Positive

- Credentials cannot appear through ordinary model serialization or schema
  discovery.
- Disclosure choices have a clear semantic boundary and audit representation.
- Upstream API expansion cannot automatically expand the public schema.

### Negative

- Removing an unsafe field can require a security-breaking compatibility
  change.
- Security classification must be maintained across models, fixtures, docs,
  and tools.
- Public certificate material needs separate treatment from private keys.

## Alternatives considered

- **Deprecated optional secret fields:** rejected because they remain public and
  populate-able.
- **Return then redact:** rejected because one missed serialization path leaks.
- **Trust upstream read-only endpoints not to return credentials:** rejected
  because observed/declared schemas can contain them.

## References

- [Security model](../SECURITY_MODEL.md)
- [API reference](../API.md)
- [ADR-002](ADR-002-strongly-typed-boundaries.md)
