# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pfsense-mcp-security`: a new, separately-installed CLI (`ADR-021`,
  Accepted; Phase B of `docs/SECURITY_POSTURE_PROVISIONING.md`) offering
  one subcommand, `discover`, which reports the current capability-posture
  (`read_only`/`write_protected`) and anchor-assurance
  (`none`/`software`/`hardware_witness`) axis state, read-only, with
  human-readable and deterministic `--json` output. Correctly recognizes
  `read_only` + `hardware_witness` (this project's own real production
  state) as a valid, representable combination. Never calls
  `provision_anchor_baseline()`, `advance()`, or anything else that
  mutates the Tier 1 store, the TPM, or pfSense — proven by dedicated
  structural (AST) and behavioral tests. **Does not change the public
  MCP contract** — still 42 READ tools, 0 WRITE tools; this is a
  standalone CLI (`src/pfsense_mcp/security_cli.py`,
  `src/pfsense_mcp/security_discovery.py`), not an MCP tool. No
  provisioning/setup subcommand exists yet — that is Phase C onward,
  each its own future, separately-authorized work.
- `pfsense-mcp-security plan --capability-posture <value> --anchor-assurance
  <value>`: a second, equally read-only/mutation-free subcommand
  (`src/pfsense_mcp/security_plan.py`) that bridges `discover`'s "what
  state do I have?" to "what would need to happen to reach a selected
  target?" — `DISCOVER → SELECT TARGET → EVALUATE VALIDITY → ASSESS
  PREREQUISITES → GENERATE PLAN`, then stops, before `PROVISIONING`.
  Enforces `ADR-021`'s validity constraint (`write_protected` requires
  anchor assurance `≠ none`), distinguishes a valid-but-unimplemented
  target (`anchor_assurance=software`, and — a finding made by reading
  the actual code — WRITE activation itself, since
  `src/pfsense_mcp/tools/write/` is still an empty placeholder) from an
  invalid one, orders anchor-assurance provisioning before
  capability-posture activation on upgrade and the reverse on a joint
  downgrade (never passing through the disallowed `write_protected` +
  `none` combination even momentarily), and represents downgrades as
  DEACTIVATE only, never DEPROVISION. **A generated plan is never
  authorization to execute it** — every plan states this in its own
  machine-readable `notes` field; no `select`/`apply`/`provision`
  subcommand exists in this build. Never imports `pfsense_mcp.tier1`
  (its only evidence source is `discover_security_posture()` itself) —
  proven structurally and behaviorally, including a test that fails if
  plan generation ever touches `sqlite3.connect`/`open`. An adversarial
  self-review before this was committed found and fixed two real
  defects: (1) a raw string target could bypass the validity constraint
  via an `is`-vs-`==` mismatch on the `(str, Enum)` axis types, now
  closed by coercing both targets through their `Enum` constructor; (2)
  an indeterminate current anchor-assurance state (a malformed/foreign
  file already at the configured store path) was being silently treated
  as a clean slate safe to provision on top of, now surfaced as
  `PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE` instead. **Does
  not change the public MCP contract** — still 42 READ tools, 0 WRITE
  tools.
- ADR-022 (execution-authorization boundary — `Plan → Authorize →
  Execute → Verify`) Accepted, and its own Phase B implemented:
  `security_plan_digest.py`'s `compute_plan_digest()`/`verify_plan_digest()`
  give every `SecurityPosturePlan` a canonical, deterministic
  `PlanDigest` (SHA-256, `tier1.canonical.digest_value()` reused, new
  `DigestPurpose.PLAN` domain separator) — plan identity only, never
  authorization, a secret, a bearer token, or proof of operator consent.
  Third, narrow `pfsense_mcp.tier1` isolation exemption, importing only
  `canonical` (pure hashing, zero I/O), never the store/witness/anchor
  machinery. `pfsense-mcp-security plan` now shows the digest in both
  human output and `--json` (`plan_digest`/`plan_digest_schema_version`
  keys). 54 new tests (46 regression + 8 AST-based isolation), including
  exact per-field participation proofs matching ADR-022's own
  participates/does-not-participate list, duplicate/reordered-step
  handling, schema-version safety, and a no-I/O behavioral proof. No
  authorization artifact, verification, or execution code exists —
  still 42 READ tools, 0 WRITE tools, `WriteEndpoints` empty, WRITE 0/3.

### Changed

- `SecurityPosturePlan.safe_to_proceed`'s meaning clarified (documentation
  only — behavior, computation, and published JSON schema unchanged): a
  class docstring, an inline CLI caveat, and a `plan --help` epilog
  sentence now state explicitly that `True` means only that the target
  is architecturally valid and current evidence shows no detected
  anomaly — never authorized, approved, executable, or that every step
  is unblocked.

### Fixed

- The declared `mcp>=1.0.0` minimum dependency version was false: every
  `mcp` SDK release from `1.0.0` through `1.21.0` either fails to import
  (`mcp.server.fastmcp`/`mcp.types.ToolAnnotations` did not exist yet in
  earlier releases) or crashes during tool registration
  (`TypeError: issubclass() arg 1 must be a class`, inside `mcp`'s own
  code). `mcp>=1.21.1` is the first release confirmed, by installing at
  exactly that floor and running the full test suite, to actually work.
  The floor is now `mcp>=1.21.1,<2.0.0`. A new CI job and
  `make min-deps-check` (wired into `make release-check`) install at
  `--resolution=lowest-direct` going forward so a regression of this kind
  fails CI instead of only surfacing for someone who happens to pin an
  old `mcp` release.

## [0.3.1] - 2026-08-09

### Added

- `pfsense_mcp_info`: a new READ-only server-introspection tool. Reports this
  server's own version, active capability profile, registered tool counts,
  active WRITE capabilities/endpoints (always empty in this build), and
  Tier 1/ADR-017 presence — deterministic local process facts only, no
  pfSense API call. Production contract: **42 READ tools, 0 WRITE tools**
  (up from 41; this is the only functional change in this release). Gated
  by a new `SERVER_INFO_READ` capability, following the same per-capability
  registration pattern as every other tool — an empty capability set still
  registers nothing. `openWorldHint=false` for this tool specifically,
  since it never contacts pfSense (every other tool remains
  `openWorldHint=true`). See `docs/API.md`'s "Server introspection" section.

### Security

- `pfsense_mcp.tier1` and `pfsense_mcp.guidance` presence/import status is
  now independently, mechanically observable at runtime via
  `pfsense_mcp_info` (`tier1_package_present`, `tier1_imported_this_process`,
  `guidance_package_present`, `guidance_imported_this_process`), in addition
  to the existing CI-enforced isolation tests — not a replacement for them.

## [0.3.0] - 2026-08-09

Production contract is unchanged from v0.2.2: **41 READ tools, 0 WRITE
tools.** This release ships the inert v0.3.0 Tier 1 safety architecture
and the inert ADR-017 documentation-guidance layer as implemented,
tested, structurally isolated code — neither is reachable from
production, neither registers an MCP tool, and no mutating capability,
endpoint, or transport path is active.

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
- An MkDocs documentation site organizing the full `docs/` reference into
  a browsable nav, published at
  [night4me.github.io/pfsense-mcp-server](https://night4me.github.io/pfsense-mcp-server/).
- CI hardening: a bandit static-security stage in both `make quick` and
  `make validate` (previously CI-only), a documentation-site build check,
  and a dependency-review check on pull requests.
- Expanded `CONTRIBUTING.md` (local-setup troubleshooting, git/PR workflow,
  a full documentation map) and `SECURITY.md` (explicit security
  guarantees, non-goals, and vulnerability-report scope).
- `make sbom`: generates a CycloneDX JSON Software Bill of Materials from
  a clean, isolated install of a freshly built wheel (never the developer
  host), using a pinned `cyclonedx-bom` version in a separate throwaway
  venv, then verifies the result offline (`scripts/verify_sbom.py`)
  before writing it to the git-ignored `dist/sbom/`. Deliberately outside
  `quick`/`validate`/`release-check` (requires network access to install
  the pinned generator tool); generating the SBOM is not the same as
  publishing it — attaching it to a release remains a separate, explicit
  owner decision (`docs/DEPENDENCY_POLICY.md`).
- ADR-017 and its companion spec (`docs/OFFICIAL_GUIDANCE_LAYER.md`):
  architecture for an official pfSense/Netgate documentation guidance
  layer — a deterministic, capability-keyed registry over a curated
  bundled/offline snapshot corpus, returning structurally non-authorizing,
  provenance-preserved references. Documentation is explicitly treated as
  untrusted content even from a trusted source and can never become
  authorization, enforced by isolation from every safety-authority code
  path, not just by policy. Architecture and inert scaffolding only — no
  READ tool output or Tier 1 PREPARE path consumes it yet; live retrieval
  and semantic search are named and deferred, not built.

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
- New `make quick`/`make validate` stage (`scripts/git_identity_check.py`):
  checks configured Git identity and recent commit metadata against a
  small blocklist of known-leaked identity values, stored as SHA-256
  hashes rather than plaintext. Added after a real personal email
  briefly reappeared in two commits following an earlier remediation,
  undetected by any existing check (none inspect commit metadata).

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

[Unreleased]: https://github.com/night4me/pfsense-mcp-server/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.3.1
[0.3.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.3.0
[0.2.2]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.2
[0.2.1]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.1
[0.2.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.0
[0.1.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.1.0
