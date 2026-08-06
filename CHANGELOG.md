# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- Package version prepared for v0.2.2 project hardening.
- README expanded for first-time installation and operation.
- Optional exact-name `PFSENSE_ALLOWED_TOOLS` restriction intersects with the
  selected capability profile and fails closed on unknown names.
- Tier 1 roadmap strengthened for canonical target fingerprints, unstable IDs,
  config-history conflicts, atomic rate/concurrency policy, and compensation
  failure reconciliation; Tier 1 remains blocked.

### Security

- Tool annotations remain untrusted client hints; capability, endpoint,
  GET-only, credential, audit, and WRITE-inactivity controls remain
  authoritative.

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

[Unreleased]: https://github.com/night4me/pfsense-mcp-server/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.1
[0.2.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.0
[0.1.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.1.0
