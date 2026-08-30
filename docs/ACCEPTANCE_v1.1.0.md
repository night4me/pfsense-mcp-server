# Acceptance — v1.1.0

**Status: published — the `v1.1.0` tag, GitHub Release, and PyPI
release all point at this commit.** The annotated git tag `v1.1.0` was
created and pushed pointing at commit
`c731430887d09403e956dcb1c6bf35a99190fa5a`; the tag's dereferenced
commit (`refs/tags/v1.1.0^{}`) resolves to exactly that SHA. The
GitHub Release was published from that tag
(<https://github.com/night4me/pfsense-mcp-server/releases/tag/v1.1.0>),
which triggered the established trusted-publishing workflow
(`.github/workflows/publish.yml`) to PyPI. The published wheel and
sdist were independently downloaded and their extracted contents
diffed byte-for-byte against a local build from this same commit —
zero differences across all files (326 wheel entries, 350 sdist
entries) — and a Sigstore attestation (verified via PyPI's Integrity
API) cryptographically binds the published wheel to this exact commit,
`refs/tags/v1.1.0`, and the `publish.yml` workflow. (The outer archive
container bytes of the published artifacts differ from the ones built
locally during RC preparation — a build-environment nondeterminism
between this project's dev machine and the GitHub Actions runner, not
a content or source difference; see
`reports-ai/V1_1_0_PUBLICATION_2026-08-30.md` for the full forensic
detail.) See that same report for the complete publication-ceremony
evidence.

## Release scope

`v1.1.0` is a **defense-in-depth and onboarding release**, not a
capability expansion. **Public MCP contract is unchanged from `v1.0.0`:
95 pfSense READ tools + 2 documentation guidance tools, 0
default-reachable WRITE = 97 total.**

The headline addition is **managed READ-only credential provisioning**:
a dedicated, project-provisioned `pfsense-mcp-readonly` pfSense service
account holding exactly the 94 READ privileges this project documents —
live-LAB-verified (POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH mission,
2026-08-29) to receive `HTTP 403 AUTH_AUTHORIZATION_FAILED` when used
directly against this project's own reviewed WRITE endpoint, i.e.
rejected by pfSense itself, not only by this server's tool surface. This
is the recommended path for new `read_only` setups via the setup wizard;
bring-your-own-key remains fully supported, unchanged by default, for
existing installations.

Full detail is in `CHANGELOG.md`'s `[Unreleased]` entry.

## Why this release exists

Three arcs landed since `v1.0.0` published, all owner-directed:

1. **POST-v1.0 managed READ-only defense-in-depth** — designed and
   live-LAB-verified a dedicated, least-privilege `pfsense-mcp-readonly`
   pfSense service account, independently proving pfSense-side rejection
   of WRITE for that account (not merely MCP-side).
2. **Managed READ-only setup-wizard integration** — composed the
   live-verified managed provisioning into the existing setup wizard as
   the recommended `read_only` path, security-binding the managed-vs-BYOK
   choice into the plan digest and confirmation token, and fixing a real
   cross-profile recovery-isolation gap found during that work.
3. **Tool-surface efficiency benchmark** — empirically evaluated whether
   the 97-tool explicit MCP surface creates a measurable
   selection-accuracy or context-cost problem. Found no such problem;
   retained the current architecture. No production change resulted.
4. **This release-readiness audit** (this document's own arc) —
   independently re-derived the public contract and every relevant
   security invariant from current source (not prior reports), re-proved
   the managed-account privilege derivation (94 READ, source-cross-checked,
   zero overlap with the 1 WRITE privilege), re-audited the pfREST
   `v2.10.2` version-range extension, verified backward compatibility for
   existing BYOK installations, performed a fresh clean-room UX rehearsal
   of both the managed and BYOK setup journeys, and swept documentation
   for staleness.

## Security invariant re-derivation (source-first, this audit)

- **Public MCP contract**: `scripts/public_contract.py` run directly
  against current source confirms 95 pfSense READ tools + 2 guidance
  tools = 97 total; `scripts/write_capability_check.py` confirms 0 of 3
  `*_WRITE` capabilities are default-reachable; `scripts/write_allow_list_check.py`
  confirms `WriteEndpoints` has exactly one entry
  (`FIREWALL_ALIAS_DESCRIPTION`).
- **Managed account privilege derivation**: `read_profile_requirements()`
  enumerates all 97 files under `src/pfsense_mcp/tools/read/`; exactly 3
  (`mcp_info`, `official_guidance`, `api_guidance`) have no direct
  pfSense endpoint call and are excluded; the remaining 94 resolve to 94
  distinct, source-cross-checked pfSense privilege strings against a real
  captured schema fixture (`tests/test_security_privileges.py::
  test_read_profile_resolves_to_the_currently_verified_94_privileges`,
  passing). Zero overlap confirmed at both the endpoint (URL, method) and
  privilege-string level against the 1 `write_protected` WRITE
  requirement (94 READ + 1 WRITE = 95 distinct, matching the existing
  `write_protected` regression test).
- **Bootstrap/runtime credential separation**: the managed provisioning
  path (`security_readonly_admin_composition.py`,
  `security_bootstrap_engine.py`'s shared, unchanged
  `provision_service_account()`) creates a new dedicated account and
  generates its own API key via that new account's own self-service
  transport — the operator's administrator credential
  (`PFSENSE_ADMIN_*`) is never used as, or written to, the runtime
  credential path (`PFSENSE_READONLY_SERVICE_API_KEY_FILE`, distinct from
  `PFSENSE_SERVICE_API_KEY_FILE`).
- **Managed/BYOK plan-digest binding**: `ReadOnlyAccountMode` participates
  in `PrivilegePlan`, `compute_setup_plan_digest()` (schema version bumped
  1→2), and `ApplyConfirmationBinding` (bumped independently as its own
  sixth bound fact). A digest or confirmation token computed for one
  account mode structurally cannot validate against the other.
- **Recovery cross-profile isolation**: `run_recovery_from_environment()`
  and `security_setup_apply.py`'s inline recovery delegation now thread
  `target_profile` explicitly, never inferred; `build_readonly_admin_context()`
  and `build_admin_context()` produce entirely separate
  namespace/journal/lock paths (hash includes `account_identity` +
  `approved_profile`); the operation-journal allowlist is a closed,
  two-entry hardcoded set, each entry still requiring both fields to
  match together.
- **Bare `setup` non-mutation**: confirmed by direct control-flow trace —
  the CLI dispatch for bare `setup` (no `setup_action`) reaches only
  `_run_setup()`, whose own docstring and body never call
  `run_setup_apply_from_environment()` or any bootstrap/provisioning
  function; the interactive wizard only reads stdin and writes stdout.
- **Secret handling**: custody-file validation
  (`_validate_custody_path`, `_validate_owner_directory`,
  `_validate_owner_controlled_material`, all pre-existing, reused
  unchanged by the new read_only path) rejects symlinks and any
  group/other-permission file or directory; no plan/digest/confirmation
  field carries secret material — verified by direct field enumeration.
- **Targeted regression suite**: 466/466 tests passed across the full
  managed-read-only/setup/recovery/journal/privilege test files in a
  single run (`tests/test_security_readonly_admin_composition.py`,
  `test_security_bootstrap_orchestration.py`, `test_security_setup_plan.py`,
  `test_security_setup_plan_digest.py`, `test_security_setup_plan_isolation.py`,
  `test_security_setup_apply.py`, `test_security_setup_apply_confirmation.py`,
  `test_security_setup_apply_inline_recovery.py`,
  `test_security_recovery_orchestration.py`,
  `test_security_recovery_orchestration_readonly.py`,
  `test_security_operation_journal.py`, `test_security_cli_setup_apply.py`,
  `test_security_cli_recover.py`, `test_security_cli_setup.py`,
  `test_security_privileges.py`, `test_security_privileges_isolation.py`).

## pfSense-pkg-RESTAPI v2.10.2 version-range extension

`VERIFIED_PACKAGE_VERSION_MAX` extended from `(2, 10, 0)` to `(2, 10, 2)`.
Re-verified directly against pinned source at both `v2.10.1` and
`v2.10.2`: `Core/Endpoint.inc::get_method_priv_name()`'s slug-generation
algorithm is byte-identical to the already-verified `v2.7.7`-`v2.10.0`
range; `Core/Auth.inc`'s `authorize()` retains the same unconditional
`array_intersect()` ANY-match with no `page-all` special-case bypass.
`tests/test_security_privileges.py`'s parametrized boundary tests confirm
`(2, 10, 2)` produces no finding and `(2, 10, 3)` does — the exact
boundary, not an approximation. This is evidence for these two specific
tags, not a guarantee for any future one.

## Backward compatibility

No file outside `src/pfsense_mcp/security_*.py` (9 modified files) and
two new files in the same directory, plus `scripts/public_contract.py`,
changed since `v1.0.0` — the MCP server runtime, tool registry, and all
95 READ + 2 guidance tool implementations are byte-identical.
`ReadOnlyAccountMode` defaults to `byo` (bring-your-own-key) everywhere
it appears (`generate_setup_plan()`, `run_setup_apply_from_environment()`,
every new CLI flag); `--target-profile` defaults to `write_protected`
everywhere it appears. No existing CLI invocation requires a new flag.
Directly verified: a `setup --non-interactive` invocation using only
`v1.0.0`-era flags (no `--read-only-account-mode`, no `--target-profile`)
produces the identical `byo`/plan-only behavior as before, with zero
pfSense contact.

## Clean-room UX rehearsal (this audit, offline, no LAB mutation)

Interactive wizard exercised end-to-end in a scratch `$HOME` via real
piped stdin against the actual installed console script: read-only →
managed account (Step 2 "Account", option 1, `[Recommended]`) →
firewall address/name → TLS verify → review → plan generated, correctly
printing `--read-only-account-mode managed` and the fixed
`PFSENSE_IDENTITY=pfsense-mcp-readonly` in the generated MCP client
config; read-only → BYOK (option 2) completed the same way with the
existing credential-guidance text. Back navigation (`b`) and Quit (`q`)
both produce clean, non-crashing exits with "No changes were made."
Narrow (40-column) and wide (120-column) terminal widths both wrap the
credential-guidance paragraph correctly with no truncation or broken
lines. Apply-time failure paths exercised with the real plan digest:
missing `PFSENSE_SETUP_CONFIRM_KEY_FILE` → `blocked_configuration_error`,
exit 5; confirm-key file with `0644` permissions →
`blocked_configuration_error` (explicit "must not grant permissions to
group or other users"), exit 5 — both before any pfSense contact. Zero
live network calls were made throughout this rehearsal.

## Documentation audit

Confirmed current across `README.md`, `docs/SECURITY_MODEL.md`,
`docs/CONFIGURATION.md`, `docs/MCP_CLIENT_CONFIGURATION.md`: 95 READ / 2
guidance / 97 total / 0 default-WRITE / 94 managed-account privileges,
with the managed-vs-BYOK distinction already correctly worded (managed =
project-provisioned least privilege; BYOK = operator-controlled scope).
No stale claims found that managed provisioning does not exist, that
BYOK is the recommended path, or that progressive discovery is
production behavior. One genuine staleness gap found and fixed:
`docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md` still cited `v2.10.0` as the
current latest verified tag; updated to record the `v2.10.2` extension.

## Test/quality gate results

`make validate` (20/20 stages, includes full pytest via xdist+serial,
ruff format+lint, mypy, bandit via `security-static-check`,
`public_contract`/`write_capability_check`/`write_allow_list_check`,
docs consistency, git report): **PASSED**, full pytest totals **5115
passed, 42 skipped**. `make min-deps-check` (fresh venv at the
lowest-direct dependency resolution, full pytest): **PASSED**, **5115
passed, 42 skipped** (xdist) + **6 passed** (serial tail) — identical
pass/skip totals to the normal-dependency run. `mkdocs build --strict`:
**PASSED** (only the pre-existing, unrelated `CODEX_TAKEOVER.md` nav
gap remains; the new `ACCEPTANCE_v1.1.0.md` nav gap this document
itself introduced was found and fixed). `make quick`'s 11 stages are
each an exact subset of stages already covered and passing inside the
`make validate` run above (ruff format/lint, mypy, full pytest,
get-only-check, tools-write-check, security-scan, git-identity-check,
bandit, write-allow-list-check, write-capability-check) — not
separately re-run, since it would duplicate the same full pytest pass
with zero additional coverage. `make release-check` deferred to the
final RC commit step (Phase 13), since `release_state_check.py`
requires a clean committed tree. Full itemized results in
`reports-ai/V1_1_0_RELEASE_READINESS_2026-08-29.md`.

## Build artifacts

Built from this exact RC tree via `python -m build`:

- `pfsense_mcp_server-1.1.0-py3-none-any.whl` — 632767 bytes —
  SHA-256 `700bf0e95481feea0e315afa640090f35ca83c2467d984fcee82ef45e1ea186e`
- `pfsense_mcp_server-1.1.0.tar.gz` — 563694 bytes —
  SHA-256 `5a87d5accd11aa06014aab126ff0f67c773a08f54d05dd8c918a831606c4a219`

Both inspected (via `zipfile`/`tar tzf` listings): wheel contains only
`src/pfsense_mcp/*` code plus standard `dist-info` metadata (326
entries); sdist contains only the declared `include` list (source,
docs subset, top-level project files) — no `reports-ai/`, no local
state, no LAB credentials, no journals/custody files, no benchmark
output, no caches. Each installed into its own fresh, isolated venv:
both report `version: 1.1.0`, correct `--version`/`--help` output for
both console scripts, `--read-only-account-mode {byo,managed}`
correctly visible in `setup --help`, and an independently-rebuilt tool
registry snapshot of exactly **95 READ / 2 guidance / 97 total / 0
write-like** tools. The wheel install was further verified to start
the MCP server correctly over stdio (`initialize` handshake returns
`serverInfo.version: "1.1.0"`) and, separately, was pipx-installed into
an isolated `PIPX_HOME` (pipx not present on this machine; installed
into its own throwaway venv rather than via system apt, to avoid any
system-level change) — the pipx-installed binaries were then used to
regenerate the scratch-HOME managed `read_only` setup plan and to
exercise the missing-confirm-key apply-time failure path
(`blocked_configuration_error`, exit 5), reproducing the Phase 5
clean-room rehearsal's result from the actual built-and-installed
artifact, not just the dev checkout.

## Final RC commit

_Filled in after Phase 13 — see
`reports-ai/V1_1_0_RELEASE_READINESS_2026-08-29.md` for the exact final
RC SHA and CI/CodeQL/Pages verification results._
