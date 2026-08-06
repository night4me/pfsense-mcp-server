# ADR-008: Fail-closed configuration validation

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

The server depends on an upstream origin, shared API identity, credential file,
TLS trust choice, profile, API version, and bounded logging. Permissive parsing
can permit credential-bearing URLs, insecure file access, log injection,
unbounded disk use, or silent fallback to the wrong trust model.

## Decision

Configuration is explicit and environment-driven. Startup fails before MCP or
network operation when required state is missing or invalid.

Validation requires:

- an HTTPS origin with no user info, path, query, fragment, whitespace, or
  control characters;
- a bounded non-empty upstream identity;
- explicit TLS modes with CA-file validation;
- a bounded regular non-symlink API-key file owned by the process user with no
  group/other permission bits;
- a bounded, non-empty, control-free first key line;
- bounded log size and backup count;
- recognized API version and capability profile.

Errors may name the setting/path but never include key contents.

## Consequences

### Positive

- Unsafe deployment state is rejected consistently at startup.
- Credential and log-injection risks are reduced.
- Operators receive typed/sanitized diagnostics.

### Negative

- Previously tolerated configurations can stop working after a security
  hardening release.
- Cross-platform file ownership/mode behavior requires care.
- Path metadata validation and later opening remain separate operations.

## Alternatives considered

- **Best-effort defaults/discovery:** rejected because they can select the wrong
  credential or trust mode.
- **Credential environment variable:** rejected because a dedicated protected
  file has clearer ownership and accidental-output controls.
- **Warn on unsafe key permissions:** used temporarily for compatibility, then
  superseded after production metadata preflight confirmed mode 0600.

## References

- [Security model](../SECURITY_MODEL.md)
- [Threat model](../THREAT_MODEL.md)
