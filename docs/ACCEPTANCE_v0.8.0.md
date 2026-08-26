# Acceptance — v0.8.0

**Status: release-candidate, ready for the Owner Approval Gate. Not yet
tagged, not yet released, not yet published to PyPI.** This document
accepts the `v0.8.0` release-candidate state at its preparation commit,
once that commit passes the required local and remote gates (CI,
CodeQL, and the release-check constituent commands not tied to
already-being-published — see "Full validation" below) — all confirmed
there. Creating the `v0.8.0` tag, publishing the GitHub Release, and
uploading to PyPI each remain a separate, explicit owner decision, taken
only after this document and the exact commit SHA it corresponds to
have been reviewed. `v0.7.2`'s own tag, GitHub Release, and PyPI
artifact remain unmoved as an accurate historical record and, until
`v0.8.0` is actually published, remain the current immutable production
baseline (see `README.md`'s "Release status" section).

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

This document accepts the v0.8.0 **release-candidate** state at its
preparation commit. It does **not** authorize a tag, push of a tag,
GitHub Release, TestPyPI/PyPI upload, or any further action. Each of
those remains a separate, explicit owner decision, taken only after
this document and the exact commit SHA it corresponds to have been
reviewed.
