# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Inert v0.3.0 Tier 1 domain framework: canonical Recovery Contracts, closed
  legal state transitions, authenticated atomic persistence, exact mutation
  policy bindings, fault classification, and value-free audit events.
- Full Tier 1 subsystem implementation, each independently reviewed, tested,
  and still entirely unreachable from production: protected-artifact
  encryption and key lifecycle, a whole-store anti-rollback protocol,
  Ed25519 confirmation and reconciliation authorities, rate/blast-radius
  containment, and a sealed mutation executor composing all of them behind
  exactly one (still-empty) send chokepoint.
- An offline-only disposable-lab fault-injection harness (`lab/`, not
  packaged, not part of the default test run) for exercising Tier 1's fault
  scenarios against `MockTransport` before any real capability adapter or
  live lab VM exists.
- Adversarial offline tests for replay, tampering, stale state, target
  concurrency, restart reconciliation, and injected persistence failures.
- Implementation-ready Tier 1 architecture, an accepted 6-phase
  implementation roadmap, 16 Architecture Decision Records, 10 subsystem
  specifications, a disposable-lab plan, and a conservative inventory of
  writable upstream endpoint classes.
- A build-only MkDocs documentation site organizing the full `docs/`
  reference into a browsable nav (not yet publicly deployed).
- CI hardening: a bandit static-security stage in both `make quick` and
  `make validate` (previously CI-only), a documentation-site build check,
  and a dependency-review check on pull requests.
- Expanded `CONTRIBUTING.md` (local-setup troubleshooting, git/PR workflow,
  a full documentation map) and `SECURITY.md` (explicit security
  guarantees, non-goals, and vulnerability-report scope).

### Security

- Production mutation remains unreachable: the Engineer profile is empty, the
  WRITE endpoint allow-list is empty, no WRITE tool registers, and the entire
  Tier 1 package remains absent from production bootstrap — verified by
  dedicated tests after every change, not only documented as intent.
- Stored Tier 1 records are integrity-authenticated; protected payloads use
  AES-256-GCM with domain-separated associated data. Two design flaws were
  found and fixed by tests before any code shipped: an anti-rollback
  comparison that checked the wrong direction for the primary rollback
  threat, and a confirmation-signature scheme that was circular as
  originally specified. Both are documented in their governing
  specifications with the original design and the fix.
- Production activation remains blocked on genuine owner/infrastructure
  decisions (an anti-rollback hardware backend selection; a live
  disposable-lab evidence run) and an explicit capability/endpoint
  authorization — none of which this release grants.

## [0.2.2] - 2026-08-07

### Added

- Public CI across Python 3.11, 3.12, and 3.13.
- Branch coverage reporting, Bandit, and CodeQL configuration.
- Sdist/wheel inspection and clean installed-entry-point verification.
- Security, contribution, release-workflow, and project-agent guidance.
- Threat model, architecture diagrams and decisions, public roadmap, benchmark
  methodology, and MCP client setup guides.
- GitHub issue and pull-request templates.
- Public API, type-quality, documentation, and final repository reviews.
- MCP ToolAnnotations on every production READ tool.
- Deterministic public MCP contract snapshot and offline release-candidate,
  reproducible-build, documentation-consistency, and artifact-manifest checks.
- Implementation-independent Recovery Contract field, canonicalization, state,
  fault, and reconciliation specification for future Tier 1 review.

### Changed

- Package version prepared for v0.2.2 project hardening.
- README expanded for first-time installation and operation.
- Optional exact-name `PFSENSE_ALLOWED_TOOLS` restriction intersects with the
  selected capability profile and fails closed on unknown names.
- Tier 1 roadmap strengthened for canonical target fingerprints, unstable IDs,
  config-history conflicts, atomic rate/concurrency policy, and compensation
  failure reconciliation; Tier 1 remains blocked.
- Auditor profile now derives directly from the supported READ capability set,
  removing a duplicated activation list without changing the capability surface.

### Security

- Tool annotations remain untrusted client hints; capability, endpoint,
  GET-only, credential, audit, and WRITE-inactivity controls remain
  authoritative.
- Bound API-key metadata validation and bounded reading to one non-following
  file descriptor, eliminating path replacement between check and use.
- Replaced certificate inventory fixtures prospectively with wholly synthetic
  `.invalid` certificate identities. No private key is committed; historical
  public certificate material remains in Git history and contained no secret.
- Reject all non-2xx upstream statuses, including redirects, and normalize
  remaining HTTP transport failures without exposing upstream exception text.
- Reject encoded and Unicode control/format characters at configuration
  boundaries that can reach URLs, tool restrictions, or logs.
- Distribution inspection rejects private-key content and additional private,
  generated, database, backup, and SSH artifact paths.

## [0.2.1] - 2026-08-06

### Security

- Removed IPsec PSKs, SMTP passwords, and API-key plaintext from public models
  and MCP schemas.
- Removed the auth-key identifying-metadata disclosure argument.
- Hardened audit records without logging arguments, responses, or exception
  messages.
- Sanitized authentication and malformed-response errors.
- Added fail-closed URL, identity, TLS, key-file, and logging validation.
- Prohibited credential fields in approved fixtures and added negative
  disclosure tests.

## [0.2.0] - 2026-08-06

### Added

- Tier 0 WRITE infrastructure, including recovery, rollback, audit, and write
  client primitives.
- Independent checks for an empty WRITE endpoint allow-list and inactive WRITE
  capabilities.

### Security

- Kept all Tier 0 WRITE infrastructure inert and unreachable from production
  bootstrap. No WRITE tool or endpoint was activated.

## [0.1.0] - 2026-08-06

### Added

- Initial production-ready READ-only MCP server.
- Strongly typed pfSense REST API models and capability-gated tools.
- GET-only transport enforcement, sanitized fixtures, and offline tests.

[Unreleased]: https://github.com/night4me/pfsense-mcp-server/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.2
[0.2.1]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.1
[0.2.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.0
[0.1.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.1.0
