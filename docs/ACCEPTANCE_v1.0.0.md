# Acceptance — v1.0.0

**Status: release-candidate — not yet tagged, released, or published.**
This commit (`15146ff3cb3b2cdecbc8d4010d929f6387378cec`) is the prepared
`1.0.0` candidate on `main`. Tagging, the GitHub Release, and PyPI
publication remain a separate, explicitly owner-authorized step this
document does not perform. See `reports-ai/V1_0_FINAL_AUDIT_2026-08-29.md`
for the complete, itemized audit evidence this summarizes.

## Release scope

`v1.0.0` is a product-maturity and correctness release, not a capability
expansion. **Public MCP contract is unchanged from `v0.9.0`: 95 pfSense
READ tools + 2 documentation guidance tools, 0 default-reachable WRITE =
97 total.** `tests/contracts/mcp_public_contract_v0.9.0.json` remains the
accurate, current snapshot — its content did not change, only the
package version around it.

Full detail is in `CHANGELOG.md`'s `[Unreleased]` entry (kept
`[Unreleased]` rather than dated/renamed, since this exact document is
the record of the not-yet-tagged state).

## Why this release exists

Two arcs landed since `v0.9.0` published, both owner-directed:

1. **Clean-room defect closure** — four defects found by a real human
   clean-room acceptance journey on a separate Ubuntu 24.04.4 VM
   (`frigate`) against a real LAB pfSense appliance: `setup
   write-client-config` failing on a genuinely clean `$HOME`; CLI
   wrapper whitespace loss at narrow-terminal wrap boundaries; TLS
   error classification too generic to distinguish a hostname/IP
   mismatch from a CA-trust failure; a misleading `Doctor ready: False`
   after a successful `read_only` apply. All four fixed, tested, and
   independently re-verified end to end (including a second full
   clean-room simulation: fresh pipx install, genuinely empty `$HOME`,
   mock private-CA pfSense target, full setup→apply→write-client-config→
   MCP round trip).
2. **Final source-first v1.0 product/security/release audit** (this
   document's own arc) — re-proved 20 security invariants against
   current source with exact citations, audited public-contract
   stability, verified the `0.9.0` → `1.0.0` upgrade path end to end
   with real state, re-verified every client-compatibility claim
   against current vendor documentation (not memory), swept
   documentation for staleness, audited supply-chain/release hygiene,
   measured performance/resource sanity, and ran the complete
   adversarial validation matrix. Found and fixed three further genuine
   defects along the way (below).

## Human clean-room acceptance evidence

Two independent real-agent runs against a real LAB pfSense appliance on
the `frigate` VM, using a wheel built from this arc's candidate:

1. **Python MCP SDK harness**: full `setup` → `apply` → confirmed →
   `write-client-config` on a genuinely clean `$HOME` → MCP `initialize`
   → `tools/list` (97 tools) → real READ call, all succeeding, zero
   pfSense mutation, zero secret leakage.
2. **Real OpenAI Codex CLI v0.151.0**: automatically consumed the
   generated `~/.codex/config.toml`; reported server version `0.9.0`
   (pre-bump), active profile `auditor`, 97 tools (95 read / 2 guidance
   / 0 write); performed multiple real READ-only pfSense inspections
   (`pfsense_get_system_status`, `pfsense_get_interfaces`,
   `pfsense_get_dns_resolver_settings`, `pfsense_get_system_console`,
   `pfsense_get_system_certificates`, others) through the real MCP
   connection with private-CA TLS verification and hostname/SAN
   matching. **Negative test**: the human asked Codex whether it could
   change pfSense settings; Codex correctly refused, since the
   connection exposes 0 WRITE tools under the read-only `auditor`
   profile — real-agent evidence that underlying pfSense account
   privilege does not by itself make mutation reachable through the
   default MCP surface.

## serverInfo.version — traced and fixed, not inferred

The Python harness above showed `server=pfsense-mcp-server
version=1.29.1`; the real Codex CLI run showed the correct `0.9.0`. This
was independently source-traced (not assumed from the discrepancy
alone): `FastMCP.__init__` never accepts or forwards a `version=` to the
internal low-level `mcp.server.lowlevel.Server` it constructs; an unset
`.version` there falls back to `pkg_version("mcp")` — the installed `mcp`
SDK package's own version, not this project's. Confirmed directly in the
installed SDK source (`mcp/server/lowlevel/server.py`), not inferred.
`1.29.0` was installed in this repository's own dev environment;
`1.29.1` in the Python harness's separate environment — consistent with
two environments resolving different patch releases of the same
`mcp>=1.21.1,<2.0.0` dependency, both hitting the identical fallback.
Fixed by having `Application.__init__` set that attribute explicitly
from one shared `resolve_package_version()` helper (also consolidating
a second, independent call site in `pfsense_mcp_info`). Verified live via
a real MCP client session against a fresh pipx install: `serverInfo.version`
now reports the installed package version, matching the real Codex CLI's
own (correct) observation.

## Security invariant re-proof (20/20 HOLD)

Every invariant in the mission's checklist was re-proved against current
source with an exact citation — full detail in
`reports-ai/V1_0_FINAL_AUDIT_2026-08-29.md`. Highlights: `KNOWN_READ_TOOL_NAMES`
= 95, `KNOWN_WRITE_TOOL_NAMES` = 1 (`set_firewall_alias_description_v1`,
not default-reachable), `KNOWN_GUIDANCE_TOOL_NAMES` = 2, live-verified
`tool_count=97`/`write_shaped_tool_names=[]`; no tool builder accepts a
caller-supplied HTTP method/path; `PFSENSE_TLS_MODE` defaults to
`strict`; confirm-key never appears in generated client config (direct
source read of `_mcp_client_env_vars()`); `load_api_key()` rejects any
key file with group/other permission bits at actual server startup
(`secure_file.py`'s `validate_descriptor()`); `pfsense_mcp.tier1` is not
imported by `application.py`/`factory.py`/`tools/registry.py` (exactly
two named, tested exceptions: `tier1_write_bridge.py`,
`tier1_anchor_check.py`); `AnchorAssurance.SOFTWARE` is a real enum value
"never resolved by this module today" (own docstring) — no
remote-witness backend exists, so `software`/`none` never masquerade as
hardware-backed; `pfsense_mcp.backends.nexus` is imported by nothing
outside itself. Zero P0/P1 findings.

## Further genuine defects found and fixed this arc

- **SECURITY.md frozen at the `v0.2.x`/`v0.3.0` era** — several releases
  stale for a `v1.0.0` candidate. Replaced with a version-independent
  policy.
- **Two stale client-integration claims**, found by live-fetching each
  linked vendor doc rather than trusting prior claims: Claude Code's
  `claude mcp add` default scope was documented as `user`, but Claude
  Code's own current docs state the default is `local` (a materially
  narrower scope); a dead `docs.cursor.com` link.
- One test-only finding: a Defect-3 regression test embedded the real
  LAB IP address from this arc's own human clean-room evidence,
  correctly flagged by `make security-scan`; replaced with an RFC5737
  documentation address.

## 0.9.0 → candidate upgrade path (verified end to end)

Published `pfsense-mcp-server==0.9.0` installed via `pipx` in an
isolated environment; realistic prior state created (env vars,
manually-created confirm-key — `0.9.0` predates `setup
init-confirm-key`, so this mirrors how any real `0.9.0` user would have
had to create one; a generated `~/.codex/config.toml` with an unrelated
`model` key and an unrelated second MCP server entry). Independently
reproduced the `Doctor ready: False` defect under real `0.9.0` before
upgrading, confirming it was real. Upgraded the same `pipx` install
in-place to this candidate: identical plan-digest/confirmation-token
computed for identical inputs (proving the confirm-key and digest
derivation are byte-compatible across the upgrade); confirmed apply no
longer prints `Doctor ready:`; `write-client-config` preserved the
unrelated `model` key and second server entry untouched (merge-only);
real MCP round trip succeeded post-upgrade. No defects found in the
upgrade path itself; several genuinely additive improvements confirmed
(`--version`/`--help` no longer require configuration; `setup
init-confirm-key`; `--tls-mode verify_private_ca`; the `Doctor ready`
fix itself).

## Full validation stack (this candidate, commit `15146ff`)

- Full pytest: 5076 passed, 42 skipped.
- `make quick`: 11/11 stages PASSED.
- `make release-check`: PASSED — `validate` (syntax/lint/typecheck/test),
  `package-check`, `twine check --strict`, `reproducible-build`,
  `min-deps-check` (Python 3.11, full suite at lowest-direct
  resolution), `artifact-manifest`.
- `mkdocs build --strict`: clean.
- `make docs-check`: OK (122 Markdown files).
- `make security-scan`: OK (no real IPs, MACs, or credential paths).
- ruff/mypy/bandit: clean.
- Cold import: ~540ms (dominated by the upstream `mcp` SDK's own type
  system, not this project's code); `Application()` construction:
  ~4ms; peak RSS at idle: ~69MB; real MCP round trip (spawn → initialize
  → `tools/list` → one READ call → `pfsense_mcp_info`): ~770ms total,
  no pathological cost, no unexpected network access at import.

## Branch protection — owner/repository-admin gate

`main` has no GitHub branch-protection rule configured
(`GET /repos/.../branches/main/protection` → 404 "Branch not
protected"). This is a repository setting, not something this audit can
change from source, and is reported here as an explicit owner decision
gate rather than a source-level failure per this audit's own
instructions.

## Not performed by this document

Tagging, GitHub Release creation, and PyPI publication remain separate,
explicitly owner-authorized steps. No real pfSense mutation was
performed or required by this arc.
