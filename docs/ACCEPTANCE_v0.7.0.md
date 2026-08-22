# Acceptance — v0.7.0

**Status: release-candidate, ready for the Owner Approval Gate
(`docs/PYPI_RELEASE.md`). Not yet tagged, not yet released, not yet
published to PyPI.** This document accepts the `v0.7.0` release-candidate
state at its preparation commit, once that commit passes the required
local and remote gates (CI, CodeQL, `make release-check`) — all
confirmed below. Creating the `v0.7.0` tag, publishing the GitHub
Release, and uploading to PyPI each remain a separate, explicit owner
decision, taken only after this document and the exact commit SHA it
corresponds to have been reviewed. `v0.6.0`'s own tag, GitHub Release,
and PyPI artifact remain unmoved as an accurate historical record.

## Release scope

v0.7.0 adds **one new tool**: `pfsense_get_official_guidance`. It is a
**guidance-class tool, not a pfSense READ capability** — the public MCP
contract's pfSense appliance surface is otherwise byte-identical to
`v0.6.0`: **95 READ tools, 94 distinct READ privileges, 1 implemented
WRITE tool, 0 default-reachable WRITE.** Confirmed by a new
`tests/contracts/mcp_public_contract_v0.7.0.json` snapshot, diffed
directly against `v0.6.0`'s own snapshot — the *only* difference between
the two files is the one new guidance-tool entry (`"tool_class":
"guidance"`, `"capability": null`).

Full detail is in `CHANGELOG.md`'s `[0.7.0]` entry — this document
summarizes the independently verified evidence a reviewer needs to accept
the release. It also serves as the final report for the release-readiness
audit conducted at commit `c674af0150b1403df9cedb96ae27e0480c2e6e3d`
(see `reports-ai/V0_7_0_RELEASE_READINESS_AUDIT_2026-08-22.md` for that
audit's own full 22-item report).

## Independently verified release evidence

### Public contract change

- `KNOWN_READ_TOOL_NAMES`: **95** — unchanged from `v0.6.0`.
- `KNOWN_GUIDANCE_TOOL_NAMES`: **1** (`pfsense_get_official_guidance`) —
  new this release. Structurally distinct from
  `KNOWN_READ_TOOL_NAMES`/`KNOWN_WRITE_TOOL_NAMES` (three disjoint
  frozensets); registered via its own `_register_guidance_tool()` path,
  gated only on the active profile granting any capability at all (not
  on any specific `Capability`), so it follows the same all-or-nothing
  profile behavior as the READ tools (the `engineer` profile, with zero
  capabilities, registers zero tools of any kind — no READ, no guidance,
  no WRITE).
- `KNOWN_WRITE_TOOL_NAMES`: 1 (`set_firewall_alias_description_v1`),
  unreachable under the default `auditor` profile — unchanged from
  `v0.6.0`.
- Distinct READ privileges: **94** — unchanged. The guidance tool's one
  dependency, `api-v2-system-version-get`, is already a member of this
  set; no new privilege was added or required.

### The new tool: `pfsense_get_official_guidance`

- **What it returns**: project-authored summaries of official
  Netgate/pfSense documentation for a requested pfsense-mcp-server
  capability, from a deterministic, Git-tracked, PR-reviewed bundled
  registry (28 entries, ADR-017/ADR-018). Each `GuidanceReference`
  carries a canonical Netgate source URL, a `summary_hash`, a
  `pfsense_edition`/`observed_edition_used`/`observed_version_used`, an
  `evidence_level`, and an `applicability` state
  (`APPLICABLE`/`PARTIALLY_APPLICABLE`/`VERSION_UNCONFIRMED`/
  `EDITION_MISMATCH`/`STALE`/`NO_OFFICIAL_GUIDANCE_FOUND`) — never a
  field of type capability, endpoint, method, or confirmation token
  (structural, isolation-test-enforced, not convention alone). A fixed
  `disclaimer` field (a `Literal`, not free text) states plainly that
  this is documentation guidance, not observed live appliance state, and
  confers no authorization.
- **No runtime documentation retrieval**: `lookup_guidance()` is a pure,
  deterministic, offline function over the bundled registry. The module
  never imports `urllib`/`requests`/`httpx` and never fetches
  `docs.netgate.com` or any URL — confirmed both statically (AST scan,
  no forbidden imports) and behaviorally (`transport.calls` assertions
  and a real `FastMCP.call_tool()` wire-level test showing exactly one
  upstream HTTP call per lookup).
- **Identity resolution reuses the existing READ path**: the tool
  resolves the appliance's observed edition/version itself, via
  `resolve_appliance_identity()`, which calls the *same*
  already-authenticated `PfSenseClient.get_system_version()` every READ
  tool already uses (`GET /api/v2/system/version`) — no new endpoint, no
  new privilege. The model is never asked for, and the tool never
  accepts, an edition/version/identity parameter. On any failure
  (network, auth, malformed response), this fails closed to
  `ObservedEdition.UNKNOWN`/`observed_version=None`, verified across a
  14-scenario adversarial matrix (401/403/404/500/502/503, connection
  failure, timeout, malformed JSON, missing/null/non-numeric version
  fields, unexpected future version scheme) — all fall back cleanly,
  none raise past the tool's own boundary.
- **Guidance is separate from live state and from WRITE authority**:
  proved end-to-end, via a real tool call with a monkeypatched malicious
  registry entry, that adversarial content in a guidance summary is
  returned as inert, typed data with zero side effects on WRITE/Tier
  1/capability state. No path exists for corpus content to invoke a
  tool, alter a capability, grant a privilege, authorize WRITE, or
  supply an arbitrary URL beyond the pinned `canonical_url` field.
  `GuidanceReference` field descriptions were added this release to
  state explicitly that a `summary` is not the appliance's current
  configuration or live state (a documentation/wording fix only — no
  schema, validation, or required-ness change).
- **Applicability cannot be inflated by identity alone**: confirmed at
  actual MCP JSON-serialization level (not just Python attribute access)
  that `applicability` can never reach `"applicable"` for the current,
  entirely `INFERRED_FROM_CURRENT_DOCS` corpus, regardless of whether the
  observed identity is CE, Plus, or unknown.

### Security finding and fix from this release's own process

**Server-startup failure-coupling**, found during this release's
release-readiness audit. An eager import in
`pfsense_mcp/guidance/__init__.py` (`from .registry import
lookup_guidance`) meant that merely importing `GuidanceReference` at
`official_guidance.py`'s module level — needed for the tool's own
Pydantic schema — triggered `registry.py`'s import and its load-time
`_check_registry_integrity()` self-check on the *server-startup* path for
every profile granting any capability. A corrupted guidance registry
entry could have crashed the entire MCP server, taking all 95 READ tools
down with it. Fixed via a PEP 562 lazy `__getattr__` in
`guidance/__init__.py`; verified by a fresh-subprocess test
(`test_guidance_registry_import_is_deferred_past_server_startup`). A
corrupted single-capability registry entry now fails only that one
tool's calls for that capability, never other capabilities, other
tools, or server startup.

## What this release does NOT do

- Does not add, widen, or reinterpret the 95-tool pfSense READ surface,
  the 94 distinct READ privileges, or WRITE reachability in any way —
  all three are byte-identical to `v0.6.0`.
- Does not describe the guidance tool as a 96th pfSense READ capability
  anywhere in its own schema, description, or this document.
- Does not perform any runtime documentation/web retrieval. `RetrievalMode`
  has no `LIVE_FETCH` member; the maintainer-only corpus-drift audit
  script (`scripts/guidance_corpus_audit.py`) is never imported by
  production.
- Does not expand the guidance corpus, implement a second guidance tool,
  or redesign ADR-017/ADR-018 — feature scope was frozen for this
  release and its preceding audit.
- Does not touch Nexus/Tier 1/security-bootstrap/protected-WRITE
  production semantics.
- Does not require a new mandatory environment variable or external
  dependency.

## Full validation (re-run at v0.7.0)

- `pytest`: 4091 passed, 42 skipped, 0 failed (both at normal deps and at
  verified minimum dependency versions).
- `ruff format --check` / `ruff check`: clean.
- `mypy` (`src/pfsense_mcp scripts lab witness_daemon signing`): clean,
  377 source files.
- `bandit`: no issues identified (30,810 lines scanned).
- `fixture_safety`, `validate_docs.py` (107 files), `mkdocs build
  --strict`: all clean.
- `make quick`: PASSED (11/11). `make validate`: PASSED (20/20).
- `public_contract.py`: OK (95 pfSense READ tools, 1 guidance tool, 96
  total).
- `guidance_corpus_audit.py`: 28/28 entries verified present.
- `make package-check`: wheel + sdist built, `verify_distribution` OK,
  fresh isolated install confirmed (version, tool counts, both CLI entry
points).
- `make reproducible-build`: OK, byte-identical artifacts across two
  independent builds.
- `make min-deps-check`: OK, install + full suite pass at lowest-direct
  resolution.
- `make release-check`: OK, clean tree.
- Genuine upgrade test: real published PyPI `0.6.0` installed fresh,
  then upgraded in place to the exact locally-built `v0.7.0` candidate
  artifact.

## Acceptance boundary

This document accepts the v0.7.0 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further pfSense/witness/credential action. Each of those remains a
separate, explicit owner decision, taken only after this document and
the exact commit SHA it corresponds to have been reviewed.
