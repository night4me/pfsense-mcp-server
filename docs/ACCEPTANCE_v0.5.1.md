# Acceptance — v0.5.1

**Status: published — the `v0.5.1` tag and PyPI release point at this
commit.** The annotated git tag `v0.5.1` was created and pushed pointing
at commit `2209bdd7ed230555653812f74a1c511db1a584b4`; the GitHub Release
was published from that tag, which triggered the `publish.yml` OIDC
trusted-publishing workflow (build + publish jobs both succeeded,
including PEP 740 digital attestations). PyPI's JSON API and Simple
Index both independently confirm `0.5.1` is live (Simple Index shows
`/provenance` links for both the wheel and sdist). A clean installation
of `pfsense-mcp-server==0.5.1` from the real PyPI index (not the local
build) was independently verified after publication: reports version
`0.5.1`, imports cleanly, exposes exactly 84 READ tools and 0 default
WRITE tools, and both console entry points (`pfsense-mcp-server`,
`pfsense-mcp-security`) work correctly. This status line was only
written after that independent post-publication verification succeeded.

## Release scope

v0.5.1 is a **documentation-accuracy and security-communication patch
only**. **No MCP tool was added or removed. No capability, privilege,
or READ/WRITE reachability semantic changed. No production runtime code
was opportunistically refactored.** The public MCP contract is
byte-identical to `v0.5.0`: 84 READ tools, 0 default WRITE tools,
confirmed by an unchanged `tests/contracts/mcp_public_contract_v0.5.1.json`
snapshot relative to `v0.5.0`'s own snapshot.

Full detail is in `CHANGELOG.md`'s `[0.5.1]` entry — this document
summarizes the independently verified evidence a reviewer needs to
accept the release.

## Independently verified release evidence

### Public contract (unchanged from v0.5.0)

- `KNOWN_READ_TOOL_NAMES`: **84**, re-derived from source, unchanged in
  membership from `v0.5.0`.
- Default (`auditor`) profile: 0 `*_WRITE` capabilities grantable,
  unchanged.
- Generated public-contract snapshot for this release matches runtime
  registration exactly and is identical in tool membership to `v0.5.0`'s
  own snapshot.

### Documentation-accuracy findings, each independently re-investigated
with direct evidence rather than preserved or guessed

1. **pfSense Plus REST API packaging claim, corrected.** A prior
   README statement claimed the REST API "ships as a built-in platform
   component" on pfSense Plus. Direct evidence
   (`pfsense_get_system_restapi_version`'s `current_version` field,
   called against both the CE 2.9.0 LAB and Plus 26.07 production)
   confirms the REST API package is a real, versioned package
   (`v2.10`) on **both** editions; its absence from the general
   installed-package listing (`pfsense_get_system_packages`) was
   re-confirmed to be identical behavior on the CE 2.9.0 LAB itself
   (not merely assumed), so this was never a CE-vs-Plus difference.
2. **Package-dependency documentation, completed.** Re-derived every
   one of the 84 endpoints' schema-declared package requirements
   directly. Two tools (WireGuard status) are package-conditional in
   practice (404 `MODEL_MISSING_REQUIRED_PACKAGE` when absent, directly
   confirmed). Four more (ACME settings, BIND settings, Cron jobs,
   FreeRADIUS EAP settings) reference a package in schema metadata but
   were directly confirmed to succeed regardless, on systems genuinely
   lacking those packages.
3. **Evidence-tier terminology, made mutually exclusive.** `LIVE
   VERIFIED` (previously meaning "LAB or production") replaced with
   `PRODUCTION VERIFIED` (production only), alongside the unchanged
   `LAB VERIFIED`, `SUPPORTED / COMPATIBLE`, and
   `EXPECTED COMPATIBLE / UNVERIFIED` tiers.
4. **pfSense Plus 25.11 classification, downgraded.** Re-evaluated
   against the newly precise tier definitions rather than preserved:
   the evidence is entirely adjacent (FreeBSD-generation similarity,
   cross-release pfREST version behavior) with nothing directly
   exercised against a 25.11 instance. Reclassified from
   `SUPPORTED / COMPATIBLE` to `EXPECTED COMPATIBLE / UNVERIFIED`.
5. **"Verified before promotion" claim, precision-qualified.** No
   longer implies uniform depth of verification across all 84 tools;
   now distinguishes endpoint/shape confirmation (true for all 84) from
   populated-field confirmation (true only where real data was
   observed).
6. **`docs/TIER1_ARCHITECTURE.md` and `docs/ARCHITECTURE_DIAGRAMS.md`,
   corrected for staleness.** Both described the pre-`ADR-026` v0.3.0
   era ("no mutation executor exists yet," "inert framework") despite
   the first WRITE capability having been built and independently
   live-verified since 2026-08-16. `TIER1_ARCHITECTURE.md` received a
   dated historical note (matching `SECURITY_MODEL.md`'s own
   established pattern); `ARCHITECTURE_DIAGRAMS.md`'s stale framing and
   diagram were replaced with the current, accurate architecture.

None of these six findings changed pfSense CE 2.9.0's `LAB VERIFIED` or
pfSense Plus 26.07's `PRODUCTION VERIFIED` classification, the
underlying schema-match evidence, or the tool-count regression results
— only inference, terminology precision, and documentation currency.

### New architecture diagrams

Three new Mermaid diagrams, each derived directly from current source
and accepted architecture rather than from aspirational design intent:

| Diagram | Source grounding | Where |
|---|---|---|
| READ security path | `tools/registry.py`, `capabilities.py`, `profiles.py`, `pfsense_client.py` | README ("Why this server," compact) + `docs/ARCHITECTURE_DIAGRAMS.md` (full) |
| Protected WRITE authorization path | `tier1/execution_coordinator.py`, `tier1/alias_description_execution.py`, `tier1/executor.py`, `tier1/state_machine.py`, `SECURITY_MODEL.md`, `ADR-026` | README ("Protected WRITE architecture," compact) + `docs/ARCHITECTURE_DIAGRAMS.md` (full, all six gates named) |
| Defense in depth / trust boundaries | Same as above, synthesized | `docs/ARCHITECTURE_DIAGRAMS.md` only |

All four diagrams (the three new ones plus the existing "Overall
architecture" set) were independently validated with `mermaid`'s own
parser (`mermaid.parse()`, via a headless DOM shim in Node) before
commit. Full visual/browser rendering (`mermaid-cli` with
`chrome-headless-shell`) was attempted but not available in this
environment — the required system dependency (`unzip`, needed to
extract the headless-shell archive) could not be installed without
root access. Parser-level syntax validation is therefore this release's
evidence tier for "renders correctly," not a rendered-image comparison;
both GitHub and MkDocs use compatible Mermaid parser versions for
rendering, so this is a meaningful (if not maximal) validation tier.

**Adversarial self-review before commit** (Phase 7 of this release's
own process) caught one real drafting error: the TPM witness was
initially labeled "optional" in both new diagrams, which directly
contradicts `SECURITY_MODEL.md`'s own statement that production WRITE
activation requires the witness to be reachable and resolved to
`PROVISIONED_VERIFIED` (a software-only anchor alternative is modeled
in the type system but has no implemented backend). Corrected before
either diagram was ever committed, not after.

## What this release does NOT do

- Does not add, remove, or change any MCP tool, capability, privilege,
  or endpoint.
- Does not change WRITE reachability in any way — the one WRITE tool
  remains exactly as unreachable under the default profile as in
  `v0.5.0`.
- Does not refactor any production runtime code opportunistically —
  every change in this release is to Markdown documentation
  (`README.md`, `docs/*.md`, `CHANGELOG.md`) plus the mechanical
  version-bump/test-fixture updates that accompany any version bump.
- Does not rewrite or move `v0.5.0`'s immutable tag, GitHub Release, or
  PyPI artifacts — those retain the original (corrected-on-`main`-only)
  pfREST packaging text as an accurate historical record, per this
  project's release-immutability policy.
- Does not claim pfSense Plus 25.11 is live-verified — explicitly
  downgraded, not merely left ambiguous.

## Acceptance boundary

This document accepts the v0.5.1 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further pfSense/witness/credential action. Each of those remains a
separate, explicit owner decision, taken only after this document and
the exact commit SHA it corresponds to have been reviewed.
