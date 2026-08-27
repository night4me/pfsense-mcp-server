# Acceptance — v0.8.0

**Status: published — the `v0.8.0` tag and PyPI release point at this
commit.** The annotated git tag `v0.8.0` was created and pushed pointing
at commit `90e6cb15079c0b6bf8a78221d6ac022d0127715a`; the GitHub Release
was published from that tag
(<https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.8.0>),
which triggered the `publish.yml` OIDC trusted-publishing workflow (run
`33027545829`, `build` and `publish` jobs both `success`, including
Sigstore attestation generation for both artifacts). PyPI's JSON API
confirms `0.8.0` is `info.version` and the latest entry in `releases`;
neither artifact is yanked. PyPI's own provenance API
(`/integrity/pfsense-mcp-server/0.8.0/.../provenance`) returns a valid
attestation bundle whose certificate SAN references this exact
workflow file and the `refs/tags/v0.8.0` ref. A clean installation of
`pfsense-mcp-server==0.8.0` from the real PyPI index (not the local
build) was independently verified in a fresh, isolated environment:
reports version `0.8.0`, `import pfsense_mcp` resolves from
`site-packages`, the `pfsense-mcp-server` CLI entry point fails closed
with a clean "configuration error" message (no traceback) when required
environment variables are absent, `pfsense-mcp-security
{--help, setup --help, recover --help, bootstrap --help}` all succeed, a
non-interactive `setup` plan-only smoke reaches
`overall_status: already_satisfied`, and a fresh
`public_contract.build_contract()` call against the installed package
shows exactly 96 registered tools (95 READ + 1 guidance, 0 WRITE). This
status line was only written after that independent post-publication
verification succeeded. `v0.7.2`'s own tag, GitHub Release, and PyPI
artifact remain unmoved as an accurate historical record.

## Release scope

v0.8.0 is a **CLI-only expansion of the `pfsense-mcp-security` operator
tooling (ADR-021/ADR-033) — no MCP capability change.** Public MCP
contract: byte-identical to `v0.7.2` — **95 pfSense READ tools + 1
official-guidance tool, 0 default-reachable WRITE.** Confirmed by a new
`tests/contracts/mcp_public_contract_v0.8.0.json` snapshot that diffs
to **zero bytes of difference** against `v0.7.2`'s own snapshot.

Full detail is in `CHANGELOG.md`'s `[Unreleased]` entry (kept
`[Unreleased]` rather than dated/renamed, since this exact document is
the record of the not-yet-tagged state) — this document summarizes the
independently verified evidence a reviewer needs to accept the release.

## Why this release exists

Two feature slices and one correctness fix landed since `v0.7.2`
published:

1. **`pfsense-mcp-security recover`** — standalone ADR-033
   recovery-execution orchestration (read-only inspection by default;
   `--execute` requires both an exact action and an incident-bound
   confirmation token).
2. **`pfsense-mcp-security setup`** — the full guided, non-mutating
   discovery/plan wizard plus `setup apply` (`read_only`/
   `write_protected`), inline `RECOVERY_REQUIRED` delegation, and
   `setup write-client-config` (merge-only MCP client config writing,
   gated behind its own explicit confirmation).
3. **`bootstrap`/`setup apply --capability-posture write_protected`
   restart-classification fix** — a prior journal for the same
   target/account/profile is no longer unconditionally treated as
   requiring recovery attention; one fresh, read-only, GET-only live
   observation is attempted first, and only an exact match against
   every expected binding field resolves to a clean restart. Strictly
   fail-closed-preserving: no new mutating call, no relaxed invariant.

None of this is reachable from, or wired into, `pfsense_mcp.server`/the
MCP tool registry/normal application startup — it is exclusively the
separate `pfsense-mcp-security` CLI entry point.

## Independently verified release evidence

### Public contract unchanged

- `tests/contracts/mcp_public_contract_v0.8.0.json` vs.
  `mcp_public_contract_v0.7.2.json`: `diff` reports **zero
  differences**.
- 95 READ tools, 1 guidance tool, 0 WRITE tools registered by default —
  unchanged.
- `tests/test_public_contract.py`: 3 passed, fresh.

### What changed

- New: `src/pfsense_mcp/security_recovery_orchestration.py`,
  `security_setup_plan.py`, `security_setup_apply.py`,
  `security_setup_apply_confirmation.py`,
  `security_client_config_write.py`, `security_setup_plan_digest.py`,
  and the corresponding `pfsense-mcp-security recover`/`setup`/`setup
  apply`/`setup write-client-config` CLI wiring in `security_cli.py`.
- `src/pfsense_mcp/security_bootstrap_engine.py`: new
  `AccountProvisioningObservation`/`observe_account_provisioning_state`.
- `src/pfsense_mcp/security_admin_composition.py`: new
  `observe_restart_state_call` closure on `_FixedMutationComponents`.
- `src/pfsense_mcp/security_bootstrap_orchestration.py`: new
  `build_authoritative_restart_observation()`;
  `run_bootstrap_from_environment()` now calls it automatically when a
  prior journal exists.
- `pyproject.toml`: version `0.7.2` → `0.8.0`.
- `scripts/public_contract.py`: `SNAPSHOT` path updated to
  `mcp_public_contract_v0.8.0.json`.

### Built-artifact proof

The wheel and sdist built from this release's exact commit were
inspected directly: `verify_distribution.py` and `twine check --strict`
both passed; member lists were grepped for secrets/LAB files/reports-ai
leakage (none found); METADATA/entry_points.txt/WHEEL confirmed correct
package name, version `0.8.0`, both console-script entry points,
`Requires-Python: >=3.11`, and MIT license metadata. Both artifacts were
installed into fresh, isolated environments (via `uv venv`, since the
system Python's `ensurepip` is unavailable in this environment) and
exercised from outside the repository working directory: import
resolves from `site-packages` (not the source tree),
`importlib.metadata.version("pfsense-mcp-server") == "0.8.0"`, the
`pfsense-mcp-server` entry point fails closed with a clean
"configuration error" message (no traceback) with no environment
configured, and `pfsense-mcp-security {--help, setup --help, recover
--help, bootstrap --help, setup write-client-config --help, setup apply
--help}` all succeed, including a full non-interactive
`setup --non-interactive --capability-posture read_only
--anchor-assurance none --json` plan-only smoke that reaches
`overall_status: already_satisfied` with zero pfSense network activity.
See `reports-ai/V0_8_0_RELEASE_PREPARATION_2026-08-27.md` for exact
verification commands, output, and hashes.

## What this release does NOT do

- Does not add, remove, or modify any MCP tool, capability, privilege,
  or profile.
- Does not change READ or WRITE reachability in any way.
- Does not weaken, skip, or delete any security test, or relax any
  authorization/recovery/witness invariant.
- Does not touch live pfSense systems, the TPM/witness anchor, or any
  real MCP client configuration file.
- Does not tag, release, or publish anything — that remains a separate,
  explicit owner decision.

## Full validation (re-run at v0.8.0's release-candidate commit)

**Update (2026-08-27, published):** `scripts/release_state_check.py`
was made phase-aware (candidate vs. published) in a narrow follow-up
commit before tagging — `determine_release_phase()` derives the phase
from one objective, offline git fact (a `v{version}` tag reachable from
`HEAD`) rather than any document's own status text, so a stale claim
can never silently downgrade a real publication. At the actual tagged
commit, `90e6cb15079c0b6bf8a78221d6ac022d0127715a`, every check below
passed with **zero failures**: `make quick` and `make validate` both
PASSED with `4653 passed, 0 failed, 42 skipped`; `make release-check`
(the full monolithic chain) PASSED for the first time in this release
cycle, including `release_state_check: OK (v0.8.0, phase=candidate,
clean tree)` at that pre-tag commit. This is the commit the `v0.8.0`
tag actually points at. The paragraph below is preserved as the
historical record of validation performed *before* that gate fix
landed, at an earlier, superseded candidate commit
(`261c1a2399c293eaf6ce8c3b63f758f1ea3776e3`) — not rewritten, per this
project's own "historical evidence stays as written" convention.

- `pytest` (full suite, `pytest-xdist`, normal deps): 4636 passed, **1
  known/expected failure**, 42 skipped. The one failure
  (`tests/test_release_state_check.py::test_current_release_state_documentation_is_consistent`)
  is intentional and by design: `scripts/release_state_check.py` exists
  specifically to prove the *current* `pyproject.toml` version has
  *already been published* (this document's own existence satisfies
  one of its three version-dependent checks; the other two —
  `CHANGELOG.md`'s dated `## [0.8.0] -` heading and README's "v0.8.0 is
  the immutable production baseline, published on PyPI" claim — are
  deliberately **not** written yet, since v0.8.0 has not actually been
  tagged/published). Forcing all three to pass now would require
  writing exactly the false "already published" claim this
  release-preparation task is explicitly forbidden from making. This is
  the *sole* source of every CI job failure on this commit (`test`
  ×3 Python versions, `coverage`, `min-deps` — verified job-by-job, each
  failing for this one identical reason and no other).
- `pytest` at verified minimum dependency versions
  (`mcp==1.21.1`/`httpx==0.27.1`/`pydantic==2.11.0`/
  `cryptography==43.0.0`, Python 3.11.15): same single known/expected
  failure, otherwise 4636 passed, 42 skipped.
- `ruff format --check` / `ruff check`: clean.
- `mypy` (`src/pfsense_mcp scripts lab witness_daemon signing`): clean.
- `bandit`: no issues identified.
- `validate_docs.py`, `mkdocs build --strict`: clean.
- `public_contract.py`: OK (95 pfSense READ tools, 1 guidance tool, 96
  total) — unchanged from `v0.7.2`.
- `make package-check`: wheel + sdist built, `verify_distribution` OK.
- `twine check --strict`: passed.
- `make reproducible-build`: OK, byte-identical artifacts across two
  independent same-epoch builds.
- GitHub Pages: redeployed from this exact commit
  (`mkdocs gh-deploy --strict`); `docs_pages_freshness_check.py` and the
  `Docs Pages freshness` CI workflow (re-triggered via
  `workflow_dispatch`) both independently confirm `success`.

## Acceptance boundary

**Update (2026-08-27): publication complete.** The owner explicitly
authorized "Publish v0.8.0 from
90e6cb15079c0b6bf8a78221d6ac022d0127715a." Tag `v0.8.0`, the GitHub
Release, and the PyPI upload were each performed following exactly the
sequence this document originally described as pending, and each was
independently re-verified after the fact (see the "Status" paragraph
above). No version other than `v0.8.0` was published; the public MCP
contract was not altered; no pfSense LAB or production mutation was
performed as part of release.
