# Acceptance — v0.2.1

## Release scope

v0.2.1 is a security-hardening release for the accepted v0.2.0 READ-only server and dormant Tier 0 WRITE infrastructure. It does not activate Tier 1, register a WRITE tool, add a WRITE endpoint to the allow-list, or authorize mutation of pfSense.

## Accepted security changes

The release permanently removes `PfSenseUser.ipsecpsk`, `EmailNotificationSettings.password`, and `AuthKey.key` from public models, Pydantic schemas, MCP schemas, and serialized output. Upstream values are ignored unconditionally. The auth-key tool no longer exposes an identifying-metadata argument. Non-secret optional metadata remains available.

Tool audit records contain upstream identity, whether optional sensitive metadata is supported/requested, failure class, and sanitized exception class. Argument values, responses, exception messages, and credentials are never logged. Typed and unexpected `Exception` failures are audited and re-raised unchanged; `BaseException` is not caught.

`get_system_status()` follows the singleton response contract and translates malformed data into sanitized `PfSenseResponseShapeError`. MCP-facing authentication failures do not disclose upstream identity.

Configuration requires an HTTPS origin URL, bounded valid identity and logging settings, valid TLS CA configuration, and a readable bounded regular non-symlink key file owned by the effective user with no group/other permissions.

Approved fixtures may not contain `ipsecpsk`, `password`, or `key`, including null or empty values.

## Production preflight

Metadata-only inspection confirmed both private parent directories are 0700 and the configured key is a regular non-symlink file owned by the effective launching user, mode 0600, within the size bound. No credential contents were displayed. (The specific username/UID recorded during that inspection has been redacted from this public record for maintainer-identity protection; the acceptance conclusion — correct ownership, correct mode — is unaffected.)

## Verification evidence

- Targeted tests: 66 passed.
- Full offline pytest: 1,109 passed; 42 live skips outside the live invocation.
- Live-safe READ suite: 42 passed; live REST API `read_only=true`.
- MCP enumeration: 41 READ, 0 WRITE, zero prohibited schema properties, no auth-key disclosure argument.
- `make quick`: 9/9; `make validate`: 16/16.
- Fixture safety, repository security, typing, lint, formatting, and diff checks passed.
- No pfSense mutation occurred.

## WRITE status

Tier 0 WRITE infrastructure remains dormant. The allow-list is empty, all WRITE capabilities are inactive, and no WRITE tools register. Tier 1 remains outside this release and requires separate approval after all Recovery Contract and persistence prerequisites are resolved.

## Compatibility

Removal of the credential fields and auth-key disclosure argument is an intentional security-breaking schema change. Configuration violating the fail-closed contract no longer starts. Production configuration satisfies the ownership/mode requirements.

## Residual provenance note

The public-certificate fixture's external provenance cannot be independently established from Git history. It passes safety scans; wholly synthetic replacement may be handled separately without rewriting history.

## Acceptance

v0.2.1 is accepted as the security-hardening baseline. This does not authorize Tier 1, WRITE activation, history rewriting, tagging, pushing, or GitHub release publication except through a separately approved operation.
