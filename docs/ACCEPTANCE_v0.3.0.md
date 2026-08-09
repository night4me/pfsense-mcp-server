# Acceptance — v0.3.0

## Release scope

v0.3.0 is an architecture-and-safety-framework release built on the
accepted v0.2.2 READ-platform baseline. **The production contract is
unchanged: 41 READ tools, 0 WRITE tools, same names, inputs, outputs,
schemas, and semantics.** It adds no MCP tool, no WRITE endpoint, no
active mutation path, and no capability activation. What it ships is
new, isolated, structurally unreachable code:

- The inert Tier 1 safety architecture (`pfsense_mcp.tier1`): canonical
  Recovery Contracts, a closed legal state machine, authenticated atomic
  persistence, protected-artifact encryption and key lifecycle, a
  whole-store anti-rollback protocol, Ed25519 confirmation and
  reconciliation authorities, rate/blast-radius containment, and a
  sealed mutation executor composing all of it behind one still-empty
  send chokepoint — implemented and tested through Phase 4
  (disposable-lab harness, offline), entirely absent from production
  bootstrap.
- The inert ADR-017 official pfSense/Netgate documentation guidance
  layer (`pfsense_mcp.guidance`): a deterministic, capability-keyed
  registry over a curated bundled/offline snapshot corpus, structurally
  incapable of supplying a capability, endpoint, method, or confirmation
  token. No READ tool output or Tier 1 PREPARE path consumes it.
- Supporting release/CI/documentation infrastructure: an SBOM generation
  target, a git-identity-leak safeguard, a published documentation site,
  and the repository's public-launch preparation.

Neither Tier 1 nor the guidance layer registers an MCP tool, imports into
`Application`/`factory`/`server`/`ToolRegistry`, or is reachable by any
code path from a running server. Both are verified unreachable by
dedicated AST isolation tests, not only documented as intent.

## Accepted changes

- Tier 1 domain package: Recovery Contract model, canonical digests,
  closed state machine, authenticated atomic SQLite store (schema v4),
  value-free audit events, fault classification, protected-artifact
  AES-256-GCM encryption with domain-separated AAD, a durable key
  lifecycle, a whole-store anti-rollback protocol, Ed25519 confirmation
  and reconciliation authorities sharing pinned-key mechanics, atomic
  rate/blast-radius policy, and a sealed executor
  (`MutationExecutor`/`CapabilityAdapter`) composing all of it — Phases
  1–3 of the accepted six-phase roadmap complete and tested.
- An offline-only disposable-lab fault-injection harness (`lab/`, not
  packaged, not part of default test collection) implementing Phase 4,
  covering all ten `TIER1_LAB_PLAN.md` fault-scenario classes against
  `MockTransport` with a synthetic test-only adapter — never a real
  capability adapter, since none exists.
- 16 Architecture Decision Records (`ADR-001`–`ADR-016`) and 10
  implementation-ready Tier 1 subsystem specifications under
  `docs/tier1/specs/`, plus a conservative 240-class writable-endpoint
  risk inventory and a first-capability candidate study (not
  authorized).
- `ADR-017` and its companion spec (`docs/OFFICIAL_GUIDANCE_LAYER.md`):
  the official-guidance-layer architecture, red-teamed by a separate
  adversarial review before any code was written, plus inert scaffolding
  (`src/pfsense_mcp/guidance/`) with one real, verified seed registry
  entry.
- `make sbom`: CycloneDX JSON Software Bill of Materials generation from
  a clean, isolated wheel install (never the developer host), offline
  verification via `scripts/verify_sbom.py`. Deliberately outside
  `quick`/`validate`/`release-check`; generating it is not the same as
  publishing it.
- `scripts/git_identity_check.py`: a new `make quick`/`make validate`
  stage checking configured Git identity and recent commit metadata
  against a small blocklist of known-leaked identity values, stored as
  SHA-256 hashes, never plaintext.
- A published MkDocs documentation site
  ([night4me.github.io/pfsense-mcp-server](https://night4me.github.io/pfsense-mcp-server/)),
  CI hardening (bandit in `make quick`/`make validate`, a documentation
  build check, dependency-review on pull requests), and expanded
  `CONTRIBUTING.md`/`SECURITY.md`.
- The repository transitioned from private to public, with the exact
  About description and topics recorded in
  `docs/PUBLIC_LAUNCH_CHECKLIST.md` applied, following a dedicated
  Public Exposure Audit (full history and current-content review; one
  real historical-commit-only finding — synthetic-replacement-era
  certificate PII in a superseded fixture, never a credential — remediated
  via a targeted, owner-approved history rewrite before any public
  exposure) and a git-identity leak found and fully remediated in the
  same way before it ever reached the public internet. A publication-
  awareness policy (`AGENTS.md`) now gates pushes that change
  public-facing content.

## CI evidence

GitHub Actions completed successfully on the release-candidate base
commit `eaa074faf4feb2b438d4e3bb02a43046fe6f5dd5`:

- [CI run 31303501026](https://github.com/night4me/pfsense-mcp-server/actions/runs/31303501026):
  Python 3.11/3.12/3.13, package, coverage, docs, and Bandit jobs passed.
- [CodeQL run 31303501025](https://github.com/night4me/pfsense-mcp-server/actions/runs/31303501025):
  Python analysis completed successfully.

The final release-state documentation commit (this one) must receive the
same successful CI and CodeQL results before tagging.

## Package verification

- Version metadata: `0.3.0`; Python 3.11+; supported production platform
  Linux; MIT `License-Expression`; Markdown README; typed-package marker.
- Hatchling builds one wheel and one sdist with the expected console
  entry point.
- Distribution verification requires the license, README, PyPI
  procedure, v0.3.0 acceptance document, package source, metadata, and
  entry point.
- Clean wheel installation/import and configuration-absent fail-closed
  startup pass through `make package-check`.
- Strict Twine checks pass for both artifact types.
- `make reproducible-build` confirms two isolated builds from the same
  commit produce byte-identical artifacts.
- `make sbom` generates and independently verifies a CycloneDX SBOM
  (structure, component name, non-empty dependency list, no local-path
  leakage) from a clean, isolated wheel install.
- Artifacts exclude credentials, key/private-key files, `.env`, AI
  reports (`reports-ai/`), local configuration, caches, fixtures, and
  temporary state — confirmed by direct member-listing inspection of
  both the wheel and sdist, not only by the automated check.

## Security invariants

- Credential values and prohibited credential fields remain absent from
  MCP schemas, outputs, logs, errors, fixtures, documentation, and
  distributions.
- Production READ transport remains GET-only and independently
  endpoint-gated.
- Redirects and every other non-2xx response fail closed; transport
  exception details and upstream bodies remain sanitized.
- Capability profiles remain authoritative; annotations and tool
  restrictions cannot grant access.
- The Auditor profile contains 34 READ capabilities and registers
  exactly 41 READ tools without restriction. **Engineer contains zero
  capabilities.**
- **The WRITE endpoint allow-list is empty, all WRITE capabilities are
  inactive, no WRITE module enters production bootstrap, and zero WRITE
  tools register** — independently confirmed this release by direct
  inspection (`EngineerProfile.capabilities == frozenset()`) in addition
  to the existing automated checks.
- **Tier 1 is implemented, tested architecture — not planning-only — but
  remains completely unreachable from production**: absent from
  `Application`/`factory`/`server`/`ToolRegistry` imports, verified by
  dedicated AST isolation tests every commit.
- **ADR-017's guidance layer is inert with no production consumer**:
  same isolation-test discipline; its only output type
  (`GuidanceReference`) has no field of type capability, endpoint,
  method, or confirmation token, by construction.
- Public CI uses no production configuration, credential, or live
  pfSense call.

## Verification evidence

- Full offline pytest (1583+ passed, 42 live-skipped), branch coverage,
  Ruff, mypy, `make quick` (11 stages), `make validate` (20 stages),
  `make package-check`, and `make release-check` pass on the
  release-state tree.
- Bandit, fixture safety, repository security, GET-only, WRITE
  import-absence, empty WRITE allow-list, WRITE-capability inactivity,
  and git-identity-leak checks pass.
- Fresh offline MCP enumeration confirms 41 READ tools, zero
  Engineer/WRITE tools, annotation parity, and zero prohibited
  credential schema properties.
- Tier 1 and ADR-017 guidance isolation tests confirm both packages are
  unimported by any production module.
- No live pfSense call, production credential access, or mutation was
  performed while preparing this release state.

## Compatibility

Public MCP tool names, inputs, outputs, schemas, endpoint set,
capability set, and semantics are **unchanged from v0.2.2**. No breaking
change, no additive tool, no capability expansion. The public contract
snapshot (`tests/contracts/mcp_public_contract_v0.3.0.json`, renamed from
the v0.2.2-era file it is byte-identical to in content) continues to
gate any future drift via `make validate`.

## Known limitations

- The supported trust boundary is a local stdio MCP process controlled
  by a trusted launcher; there is no network MCP transport or
  per-message caller authentication.
- Linux is the supported production platform for descriptor-bound
  credential loading. Unsupported platforms fail closed rather than
  weakening guarantees.
- CodeQL SARIF is not uploaded to GitHub Code Scanning (`upload: never`
  by explicit configuration). This was originally justified by the
  repository being private; the repository is now public, so uploading
  is a legitimate available option that has not yet been decided —
  distinct from the earlier "unavailable for this private repository"
  situation.
- PyPI publication and Trusted Publisher configuration are separate
  external operations and are not completed by this acceptance document.
- Private live-safe READ acceptance was not repeated for this release;
  the most recent recorded live appliance baseline predates this
  release. No production credentials or live pfSense access were used
  in preparing v0.3.0.
- A targeted Git history rewrite was performed under explicit,
  one-time owner authorization to remove real, non-synthetic
  certificate PII (geographic/organization identity, not a credential)
  found only in a historical, pre-synthetic-replacement commit, and
  separately to remove real personal Git author/committer identity that
  briefly reappeared after that rewrite. Both are fully remediated and
  independently re-verified; a durable safeguard
  (`scripts/git_identity_check.py`) now guards against recurrence of the
  latter.
- Tier 1's architecture is implemented and tested through Phase 4
  (offline disposable-lab harness); live execution against a real lab
  VM, a first concrete capability adapter (Phase 5), and production
  activation (Phase 6) all remain not started, each gated by its own
  explicit owner/infrastructure decision — none of which this release
  grants. `ADR-011`'s anti-rollback anchor backend selection (TPM2 vs.
  remote witness) remains the one open Architecture Decision Record,
  pending confirmation of production host TPM availability.
- GitHub Pages redeployment is currently a manual step
  (`mkdocs gh-deploy`); no CI/CD workflow automates it. `dependabot.yml`'s
  cadence for a now-public repository remains an open, deliberately
  deferred judgment call.

## Acceptance boundary

This document accepts the v0.3.0 release state after its exact commit
passes the required local and remote gates. It does not authorize a tag,
push, GitHub Release, TestPyPI/PyPI upload, live pfSense access,
credential use, WRITE activation, or Phase 5 work. Each external
operation requires separate approval.
