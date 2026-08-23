# Acceptance — v0.7.1

**Status: published — the `v0.7.1` tag and PyPI release point at this
commit.** The annotated git tag `v0.7.1` was created and pushed pointing
at commit `65201dc2385f0fe1b926ff52b28011b9ab8bcb5c`; the GitHub Release
was published from that tag
(<https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.7.1>),
which triggered the `publish.yml` OIDC trusted-publishing workflow (run
completed `success`). PyPI's JSON API and Simple Index both
independently confirm `0.7.1` is live, neither artifact is yanked, and
both the wheel and sdist carry `data-provenance` (PEP 740 attestation)
links, matching every prior release. A clean installation of
`pfsense-mcp-server==0.7.1` from the real PyPI index (not the local
build) was independently verified: reports version `0.7.1`, both CLI
entry points work, a real `FastMCP.list_tools()` call shows exactly 95
pfSense READ tools + 1 guidance tool
(`pfsense_get_official_guidance`) + 0 WRITE tools registered, and an
offline `lookup_guidance()` call against the installed package returned
a real entry (`retrieval_mode: BUNDLED_SNAPSHOT`). **The real, live
PyPI 0.7.1 project page's rendered Quick start now shows
`pip install --upgrade pfsense-mcp-server` and does not contain the
stale `==0.5.1` pin** — fetched and inspected directly from
`https://pypi.org/pypi/pfsense-mcp-server/0.7.1/json`, confirming the
correction this release exists to publish actually took effect. The
description still contains 4 legitimate historical references to
`0.5.1` (explaining the fix and naming past releases), individually
inspected and confirmed none are inside the Quick start block. This
status line was only written after that independent post-publication
verification succeeded. `v0.7.0`'s own tag, GitHub Release, and PyPI
artifact remain unmoved as an accurate historical record.

## Release scope

v0.7.1 is a **documentation/packaging presentation correction only —
no functional MCP/API/security change.** Public MCP contract:
byte-identical to `v0.7.0` — **95 pfSense READ tools + 1
official-guidance tool, 94 distinct READ privileges, 1 implemented
WRITE tool, 0 default-reachable WRITE.** Confirmed by a new
`tests/contracts/mcp_public_contract_v0.7.1.json` snapshot that diffs
to **zero bytes of difference** against `v0.7.0`'s own snapshot.

Full detail is in `CHANGELOG.md`'s `[0.7.1]` entry — this document
summarizes the independently verified evidence a reviewer needs to
accept the release.

## Why this release exists

After `v0.7.0` published, README.md's Quick start section was found
still instructing `pip install 'pfsense-mcp-server==0.5.1'` — stale
across two releases (v0.6.0, v0.7.0). Because `pyproject.toml` declares
`readme = "README.md"`, hatchling embeds that file's content verbatim
as the wheel/sdist's `long_description` at build time — the stale line
was baked into the already-published, immutable `v0.7.0` PyPI artifact,
and PyPI cannot re-render an already-published project's description in
place. The only way to correct what PyPI shows is to publish a new
version built from the corrected README — this release.

## Independently verified release evidence

### Public contract unchanged

- `tests/contracts/mcp_public_contract_v0.7.1.json` vs.
  `mcp_public_contract_v0.7.0.json`: `diff` reports **zero differences**.
- `KNOWN_READ_TOOL_NAMES`: 95 (unchanged). `KNOWN_GUIDANCE_TOOL_NAMES`: 1
  (unchanged). `KNOWN_WRITE_TOOL_NAMES`: 1, still default-unreachable
  (unchanged). Distinct READ privileges: 94 (unchanged).
- No capability, privilege, profile, endpoint, or WRITE-reachability
  file was touched by this release.

### What changed

- `README.md`'s Quick start install command: unpinned to
  `pip install --upgrade pfsense-mcp-server` (was
  `pip install 'pfsense-mcp-server==0.5.1'`).
- `docs/ROADMAP.md`'s "Current baseline" section, `docs/index.md`'s two
  tool-count lines, and three spots in `docs/THREAT_MODEL.md` — stale
  current-state references found during a repository-wide sweep, fixed
  narrowly. Historical CHANGELOG/`ACCEPTANCE_v0.*.md`/dated
  compatibility-evidence records were left untouched.
- New regression protection: `tests/test_readme_install_version.py`
  asserts any pinned version in README.md's install line matches
  `pyproject.toml`'s current version.

### Built-artifact proof (long_description correction)

The wheel and sdist built from this release's exact commit were
inspected directly: the embedded `long_description` (`METADATA`'s body,
identical to README.md) contains
`pip install --upgrade pfsense-mcp-server` and does **not** contain the
literal string `pfsense-mcp-server==0.5.1`. See `CHANGELOG.md`'s
`[0.7.1]` entry and the release-preparation report
(`reports-ai/V0_7_1_RELEASE_PREPARATION_2026-08-23.md`) for the exact
verification commands and output.

## What this release does NOT do

- Does not add, remove, or modify any MCP tool, capability, privilege,
  or profile.
- Does not change READ or WRITE reachability in any way.
- Does not touch Tier 1, security-bootstrap, Nexus, or the guidance
  corpus.
- Does not rewrite `v0.7.0`'s or any earlier release's immutable
  historical acceptance/release record.
- Does not begin ADR-033 CLI work or any other feature/architecture
  track.

## Full validation (re-run at v0.7.1)

- `pytest`: full suite passing, 0 failed (both at normal deps and at
  verified minimum dependency versions) — exact counts in
  `reports-ai/V0_7_1_RELEASE_PREPARATION_2026-08-23.md`.
- `ruff format --check` / `ruff check`: clean.
- `mypy` (`src/pfsense_mcp scripts lab witness_daemon signing`): clean.
- `bandit`: no issues identified.
- `fixture_safety`, `validate_docs.py`, `mkdocs build --strict`: all
  clean.
- `make quick`: PASSED (11/11). `make validate`: PASSED (20/20).
- `public_contract.py`: OK (95 pfSense READ tools, 1 guidance tool, 96
  total) — unchanged from `v0.7.0`.
- `make package-check`: wheel + sdist built, `verify_distribution` OK.
- `twine check --strict`: passed.
- `make reproducible-build`: OK, byte-identical artifacts across two
  independent builds.
- `make min-deps-check`: OK, install + full suite pass at lowest-direct
  resolution.
- `make release-check`: OK, clean tree.
- Genuine upgrade test: real published PyPI `0.7.0` installed fresh,
  then upgraded in place to the exact locally-built `v0.7.1` candidate
  artifact.

## Acceptance boundary

This document accepts the v0.7.1 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further action. Each of those remains a separate, explicit owner
decision, taken only after this document and the exact commit SHA it
corresponds to have been reviewed.
