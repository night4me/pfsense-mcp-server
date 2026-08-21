# Acceptance — v0.5.0

**Status: release-candidate — prepared, not yet tagged or published.**
The `v0.5.0` git tag, GitHub Release, and PyPI upload do not yet exist as
of this document. This document records the release-preparation state
as of the exact commit it ships with; tag/Release/PyPI publication
remain separate, explicit owner actions taken only after this document
and that commit SHA have been reviewed. (Learn from `v0.4.0`'s own
history: an earlier acceptance record in this project once prematurely
said "published" before a real publish attempt had actually succeeded
— this document deliberately avoids repeating that mistake.)

## Release scope

v0.5.0 is a **major READ-capability expansion**. Its public MCP
contract grows from **42 READ tools (the `v0.4.2` published baseline)
to 84 READ tools — exactly a 100% increase** — with 0 WRITE tools
exposed under the default profile, unchanged. No WRITE capability was
added, changed, or newly exposed by this release; the Tier 1
architecture, `verified=True` gating discipline, and the scoped pfSense
credential model are all unchanged in kind, only extended in scope to
84 tools' worth of least-privilege mappings.

Coverage against this project's own capability discovery audit (267
OpenAPI paths / 243 GET operations reviewed, every GET given exactly
one disposition) grows from roughly 40% (42/105) to roughly **80%
(84/105)** of the identified useful READ capability universe.

Full tool-by-tool detail, every security-relevant finding, and the
release-readiness audit's own findings are in `CHANGELOG.md`'s
`[0.5.0]` entry — this document summarizes the independently verified
evidence a reviewer needs to accept the release, not the complete
change list.

## Independently verified release evidence

### Public contract

- `KNOWN_READ_TOOL_NAMES` (live registry, re-derived from source, not
  trusted from documentation): **84**, all unique names, all with a
  valid `Capability` mapping.
- Default (`auditor`) profile: 0 `*_WRITE` capabilities grantable.
  `write_protected` profile: 84 READ + 1 WRITE = 85.
- Generated public-contract snapshot (`tests/contracts/
  mcp_public_contract_v0.5.0.json`) matches runtime registration
  exactly (`public_contract: OK (84 tools)`).
- No implemented-but-unverified endpoint is registered; no
  REJECT/deferred/package-conditional capability has leaked into the
  public surface (87 total `Endpoints` entries exist; exactly 3 remain
  `verified=False` — FreeRADIUS interfaces/macs, Service Watchdog — all
  correctly unregistered with zero tool files and zero capability
  wiring).

### Security

- Independently scanned all 84 registered tools' full input/output MCP
  schemas for the seven secret-bearing field names this project has
  ever identified and excluded at the model layer
  (`auth_pass`/`proxy_passwd`/`password`/`prv`/`presharedkey`/
  `preshared_key`/`privatekey`): zero hits.
- Manually re-verified every named risk model has no such field in its
  Pydantic definition, not merely in its docstring.
- Swept every model file for raw-dict-passthrough or blind `**data`
  unpacking; found none. The one legitimate raw
  `list[dict[str, Any]]` field (`FirewallSchedule.timerange`) was
  independently re-verified against the live schema to carry zero
  secret/address material in its nested type.
- `tests/test_credential_non_disclosure.py`'s automated
  `PROHIBITED_FIELDS` regression scan was found to only check 3 of
  those 7 names by exact match and was widened to all 7 — see
  `CHANGELOG.md`.

### CE 2.9.0 compatibility

- `DhcpServer`/`DnsResolverSettings`'s CE-2.9.0 nullability widenings
  are strictly additive; both the old (CE 2.8.1, non-null) and new
  (CE 2.9.0, null) response shapes are independently exercised by the
  test suite.
- No LAB mutation and no additional LAB package installed during the
  release-readiness audit.

### pfSense platform compatibility matrix

| Platform | Version | Status | Evidence |
|---|---|---|---|
| pfSense CE | 2.9.0 (FreeBSD 16.0-CURRENT, pfREST 2.10) | **LAB VERIFIED** | Current LAB baseline; full public contract exercised against a disposable, isolated appliance. |
| pfSense CE | 2.8.1 (pfREST 2.10) | **LAB VERIFIED** | Prior LAB baseline, superseded. |
| pfSense Plus | 26.07-RELEASE | **LIVE VERIFIED** | Owner-authorized, READ-only production compatibility pass: identity verified first (platform = "Netgate pfSense Plus", version = 26.07-RELEASE exact match); 82/84 public tools invoked successfully with real data (30 valid-empty results); the remaining 2 (WireGuard status) correctly and automatically classified package-absent, not a compatibility failure; live OpenAPI schema matched the pinned v2.10 reference exactly — 267/267 paths, 186/186 components, zero type/nullability differences (only 5 instance-specific runtime default values differed); targeted secret-safety re-check against the seven highest-risk live responses found zero prohibited field names; zero production mutation of any kind performed. |
| pfSense Plus | 25.11 | **SUPPORTED / COMPATIBLE** (not live-verified) | No live or LAB access was available or authorized for this version. Classified from converging evidence: shares the same FreeBSD 16-CURRENT base OS as both the CE 2.9.0 LAB baseline and the live-verified Plus 26.07 instance; one platform-version step from a build already proven to have zero schema drift from the pinned v2.10 reference; the same pfREST v2.10 package this project pins against already spans CE 2.8.1, CE 2.9.0, and Plus 26.07 without incident. An inference from strong adjacent evidence, not a test result. |

### Packaging

- Built via the canonical `python -m build --no-isolation --sdist
  --wheel`. `scripts/verify_distribution.py`: OK.
  `twine check --strict`: PASSED for both artifacts.
- No `reports-ai`, secrets, private keys, machine-specific paths,
  symlinks, or dev-only caches in either artifact.
- `reproducible_build.py`: OK (byte-identical rebuild).
- `verify_min_dependencies.py`: OK — full test suite passes against the
  lowest allowed version of every direct dependency.

### Fresh install and upgrade path

- A wheel built from this exact commit installs cleanly into a fully
  isolated environment, imports successfully, both console entry
  points (`pfsense-mcp-server`, `pfsense-mcp-security`) work, and the
  registry exposes exactly 84 READ / 0 default-WRITE tools.
- Upgrading from the real, published `pfsense-mcp-server==0.4.2` (PyPI)
  leaves zero stale files and introduces no configuration
  incompatibilities or entry-point changes; the only source difference
  found was one new, purely additive, currently-dormant function
  unrelated to this release's scope.

## What this release does NOT do

- Does not add, change, or newly expose any WRITE capability. The one
  WRITE tool this repository has ever built
  (`set_firewall_alias_description_v1`) remains unreachable under the
  default profile, exactly as in `v0.4.2`.
- Does not touch the TPM witness or the Tier 1 architecture in any way.
- Does not move, delete, or reuse any prior git tag or GitHub Release.
  All remain permanent, accurate historical records.
- Does not install, remove, or change any package, configuration, or
  privilege on the production appliance used for the Plus 26.07
  compatibility pass — that access was strictly READ-only and scoped to
  compatibility verification.
- Does not claim pfSense Plus 25.11 is live-verified — it is explicitly
  labeled an inference, not a test result.

## Acceptance boundary

This document accepts the v0.5.0 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further pfSense/witness/credential action. Each of those remains a
separate, explicit owner decision, taken only after this document and
the exact commit SHA it corresponds to have been reviewed.
