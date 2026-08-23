# Acceptance — v0.7.2

**Status: published — the `v0.7.2` tag and PyPI release point at this
commit.** The annotated git tag `v0.7.2` was created and pushed pointing
at commit `a1e4877d81e35df1e18e4e828bcaecb13338dbbd`; the GitHub Release
was published from that tag
(<https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.7.2>),
which triggered the `publish.yml` OIDC trusted-publishing workflow (run
completed `success`, including PEP 740 attestation generation). PyPI's
JSON API confirms `0.7.2` is `info.version` and the latest entry in
`releases`, neither artifact yanked. A clean installation of
`pfsense-mcp-server==0.7.2` from the real PyPI index (not the local
build) was independently verified in a fresh, isolated environment:
reports version `0.7.2`, `import pfsense_mcp.server` succeeds, the
`pfsense-mcp-server` CLI entry point fails closed with a clean
"configuration error" message (no traceback) when required environment
variables are absent, the `pfsense-mcp-security` CLI entry point works
and lists the `bootstrap` subcommand, a real
`FastMCP.list_tools()`-equivalent call (constructing `ToolRegistry`
exactly as `scripts/public_contract.py` does, against the installed
package) shows exactly 96 registered tools with the guidance tool
present and zero WRITE-shaped tool names registered, and
`pfsense_mcp.guidance.registry.lookup_guidance` imports and is callable
offline. This status line was only written after that independent
post-publication verification succeeded. `v0.7.1`'s own tag, GitHub
Release, and PyPI artifact remain unmoved as an accurate historical
record.

## Release scope

v0.7.2 is a **Tier 1 correctness fix and validation-pipeline
improvement — no MCP capability change.** Public MCP contract:
byte-identical to `v0.7.1` — **95 pfSense READ tools + 1
official-guidance tool, 94 distinct READ privileges, 1 implemented
WRITE tool, 0 default-reachable WRITE.** Confirmed by a new
`tests/contracts/mcp_public_contract_v0.7.2.json` snapshot that diffs
to **zero bytes of difference** against `v0.7.1`'s own snapshot.

Full detail is in `CHANGELOG.md`'s `[0.7.2]` entry — this document
summarizes the independently verified evidence a reviewer needs to
accept the release.

## Why this release exists

Three independent defects were found and fixed after `v0.7.1`
published:

1. **A real-wall-clock timing gap in `MutationExecutor`** —
   `execute()` never passed an explicit `now=` value into
   `RecoveryContract.is_expired()`, so it silently read real wall-clock
   time regardless of the deterministic clock already used elsewhere.
   Under a long-running suite this occasionally caused a false
   `ContractConflictError` unrelated to any real authorization problem.
2. **README.md's Mermaid diagrams rendered as raw source text on the
   live PyPI project page** — GitHub renders `` ```mermaid `` fences
   natively; PyPI's renderer does not.
3. **The published documentation site was 92 commits stale**, still
   describing a `v0.3.x`-era, 42-tool state.

Alongside these fixes, a validation/release-pipeline performance audit
cut the full offline pytest suite's wall-clock time by roughly half via
`pytest-xdist`, and ADR-033 CLI Integration Slice 3 added a new
operator-facing `pfsense-mcp-security bootstrap` CLI subcommand (no MCP
surface change).

## Independently verified release evidence

### Public contract unchanged

- `tests/contracts/mcp_public_contract_v0.7.2.json` vs.
  `mcp_public_contract_v0.7.1.json`: `diff` reports **zero differences**.
- `KNOWN_READ_TOOL_NAMES`: 95 (unchanged). `KNOWN_GUIDANCE_TOOL_NAMES`: 1
  (unchanged). `KNOWN_WRITE_TOOL_NAMES`: 1, still default-unreachable
  (unchanged). Distinct READ privileges: 94 (unchanged).
- No capability, privilege, profile, endpoint, or WRITE-reachability
  file was touched by this release.
- The new `pfsense-mcp-security bootstrap` CLI subcommand is
  administrative tooling invoked outside the MCP server process — it
  registers no MCP tool and is not part of the public contract counted
  above.

### What changed

- `src/pfsense_mcp/tier1/executor.py`: `MutationExecutor` gained a
  constructor-injectable `clock: Clock = _utc_now` parameter (the same
  pattern already used by `SqliteRecoveryContractStore` and
  `SqliteAuthorizationConsumptionStore`), defaulting to real UTC
  wall-clock time exactly as before — the only production construction
  site does not inject a clock. `execute()`'s expiry check now passes
  `now=self._now()`, which fails closed on a naive or non-UTC value.
- `README.md`: both Mermaid diagrams replaced with pre-rendered SVG
  images (`assets/diagrams/*.svg`); Mermaid source
  preserved in `assets/diagrams/*.mmd`.
- Documentation site redeployed from current `main`; added a read-only
  staleness detector (`scripts/docs_pages_freshness_check.py` + weekly/
  on-push CI check) that cannot itself deploy.
- New: `src/pfsense_mcp/security_bootstrap_orchestration.py` and the
  `pfsense-mcp-security bootstrap` CLI subcommand (ADR-033 CLI
  Integration Slice 3).
- `pytest-xdist>=3.8,<4.0` added as a dev dependency; `Makefile`'s
  `test`/`quick` targets now run the bulk of the suite in parallel
  (`-n 6 --dist=loadscope`) plus a small serial pass for two tests that
  cannot safely collect under xdist; a redundant duplicate full-suite
  run was removed from `ci.yml`.

### Built-artifact proof

The wheel and sdist built from this release's exact commit were
inspected directly: `verify_distribution.py` and `twine check --strict`
both passed, and the embedded `long_description` (identical to
README.md) contains zero `` ```mermaid `` fences and both diagram
`<img>` references. See `CHANGELOG.md`'s `[0.7.2]` entry and the
release-preparation report
(`reports-ai/V0_7_2_RELEASE_PREPARATION_2026-08-23.md`) for exact
verification commands and output.

## What this release does NOT do

- Does not add, remove, or modify any MCP tool, capability, privilege,
  or profile.
- Does not change READ or WRITE reachability in any way.
- Does not weaken, skip, or delete any security test.
- Does not touch live pfSense systems.
- Does not begin v0.8.0 or any other new feature/architecture track.

## Full validation (re-run at v0.7.2)

- `pytest`: full suite passing, 0 failed (both at normal deps, under
  `pytest-xdist`, and at verified minimum dependency versions) — exact
  counts in `reports-ai/V0_7_2_RELEASE_PREPARATION_2026-08-23.md`.
- `ruff format --check` / `ruff check`: clean.
- `mypy` (`src/pfsense_mcp scripts lab witness_daemon signing`): clean.
- `bandit`: no issues identified.
- `fixture_safety`, `validate_docs.py`, `mkdocs build --strict`: all
  clean.
- `make quick`: PASSED (11/11). `make validate`: PASSED (20/20).
- `public_contract.py`: OK (95 pfSense READ tools, 1 guidance tool, 96
  total) — unchanged from `v0.7.1`.
- `make package-check`: wheel + sdist built, `verify_distribution` OK.
- `twine check --strict`: passed.
- `make reproducible-build`: OK, byte-identical artifacts across two
  independent builds.
- `make min-deps-check`: OK, install + full suite pass at lowest-direct
  resolution.
- `make release-check`: OK, clean tree.
- Genuine upgrade test: real published PyPI `0.7.1` installed fresh,
  then upgraded in place to the exact locally-built `v0.7.2` candidate
  artifact.

## Acceptance boundary

This document accepts the v0.7.2 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further action. Each of those remains a separate, explicit owner
decision, taken only after this document and the exact commit SHA it
corresponds to have been reviewed.
