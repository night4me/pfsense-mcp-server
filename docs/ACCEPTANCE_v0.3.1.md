# Acceptance — v0.3.1

## Release scope

v0.3.1 is a single-tool, backward-compatible READ-surface addition built
on the accepted v0.3.0 baseline. **The only functional change is one new
READ tool: `pfsense_mcp_info`.** All 41 tools shipped in v0.3.0 are
unchanged — same names, inputs, outputs, schemas, and semantics. No
WRITE endpoint, no active mutation path, and no capability expansion
beyond the one new READ capability gating the new tool.

`pfsense_mcp_info` reports this server's own version, active capability
profile, registered tool counts, active WRITE capabilities/endpoints
(always empty in this build), and Tier 1/ADR-017 presence — deterministic
local process facts only, derived from the same objects (`self._capabilities`,
`WriteEndpoints`, `importlib.metadata`, `sys.modules`) that already drive
registration and are already independently checked elsewhere. It makes no
pfSense API call, and unlike every other tool advertises
`openWorldHint=false` for that reason. It cannot itself grant or change
any capability — it only reports already-enforced state.

This addition was informed by a competitive architecture review of a
comparable OPNsense MCP server (`reports-ai/reviews/
OPNSENSE_MCP_COMPETITIVE_REVIEW.md`), which identified server/capability
introspection as a design idea worth adopting on its own merits — not
copied from that project's implementation, and explicitly not paired with
any of that project's WRITE-safety simplifications (global switch,
endpoint blocklist), which were separately and permanently rejected for
this project's trust model.

## Accepted changes

- New `Capability.SERVER_INFO_READ`, added to `SUPPORTED_CAPABILITIES_THIS_BUILD`
  and gating `pfsense_mcp_info` through the same per-capability
  `register_all()` dispatch pattern every other tool already uses — an
  empty capability set (Engineer profile) still registers nothing.
- New `ServerIntrospection` pydantic model
  (`src/pfsense_mcp/models/server_introspection.py`) and tool module
  (`src/pfsense_mcp/tools/read/mcp_info.py`), following the existing
  `build(dependency) -> Callable` tool pattern, with a snapshot-provider
  callback in place of a `PfSenseClient` (this tool has none).
- `ToolRegistry` now tracks actually-registered tool names (post
  capability- and `PFSENSE_ALLOWED_TOOLS`-filtering) so
  `pfsense_mcp_info`'s tool-count fields can never drift from what was
  really registered on the live MCP instance, and gained an optional
  `profile_name` constructor parameter (defaults to `"unknown"` for
  existing call sites that don't need it) so the tool can report the
  active profile by name.
- `WriteEndpoints.active_entries()`: a new classmethod moving the
  allow-list entry scan that `scripts/write_allow_list_check.py` already
  performed into the production package itself, so the CI check and
  `pfsense_mcp_info`'s `active_write_endpoint_count` field read the exact
  same function rather than each keeping an independent copy of the same
  `vars()` scan.
- `scripts/public_contract.py` updated to support a tool with no
  `PfSenseClient` dependency (`LOCAL_ONLY_TOOL_NAMES`): its contract
  entry carries `client_method: null` and `endpoint: null` instead of a
  GET endpoint reference. The public contract snapshot was renamed
  `mcp_public_contract_v0.3.0.json` → `mcp_public_contract_v0.3.1.json`
  (41 unchanged tool entries plus the one new entry).
- `docs/API.md` gained a "Server introspection" section documenting the
  new tool, and its blanket "every tool advertises `openWorldHint=true`"
  statement was corrected to name the one exception.

## CI evidence

GitHub Actions completed successfully on the release-candidate base
commit `a273d3b4de651f196ea311f0f7a015051320189c` (the most recent commit
before this release-state documentation commit):

- [CI run 31309462883](https://github.com/night4me/pfsense-mcp-server/actions/runs/31309462883):
  Python 3.11/3.12/3.13, package, coverage, docs, and Bandit jobs passed.
- [CodeQL run 31309462882](https://github.com/night4me/pfsense-mcp-server/actions/runs/31309462882):
  Python analysis completed successfully.

The final release-state documentation commit (this one) must receive the
same successful CI and CodeQL results before tagging.

## Package verification

- Version metadata: `0.3.1`; Python 3.11+; supported production platform
  Linux; MIT `License-Expression`; Markdown README; typed-package marker.
- Hatchling builds one wheel and one sdist with the expected console
  entry point.
- Distribution verification requires the license, README, PyPI
  procedure, v0.3.1 acceptance document, package source, metadata, and
  entry point.
- Clean wheel installation/import and configuration-absent fail-closed
  startup pass through `make package-check`.
- Strict Twine checks pass for both artifact types.
- Artifacts exclude credentials, key/private-key files, `.env`, AI
  reports (`reports-ai/`), local configuration, caches, fixtures, and
  temporary state — confirmed by direct member-listing inspection of
  both the wheel and sdist, not only by the automated check.

## Security invariants

- Credential values and prohibited credential fields remain absent from
  MCP schemas, outputs, logs, errors, fixtures, documentation, and
  distributions.
- Production READ transport remains GET-only and independently
  endpoint-gated; `pfsense_mcp_info` makes no transport call at all.
- Capability profiles remain authoritative; annotations and tool
  restrictions cannot grant access.
- The Auditor profile contains 35 READ capabilities and registers
  exactly 42 READ tools without restriction. **Engineer contains zero
  capabilities and registers zero tools, including `pfsense_mcp_info`**
  — verified directly, not merely by construction: the new capability
  follows the exact same `if Capability.X in self._capabilities` gate as
  every existing capability, with no unconditional-registration
  exception.
- **The WRITE endpoint allow-list is empty, all WRITE capabilities are
  inactive, no WRITE module enters production bootstrap, and zero WRITE
  tools register** — independently confirmed this release by direct
  inspection (`EngineerProfile.capabilities == frozenset()`,
  `WriteEndpoints.active_entries() == []`) in addition to the existing
  automated checks. `pfsense_mcp_info`'s own
  `active_write_capabilities`/`active_write_endpoint_count`/
  `registered_write_tool_count` fields report this same state live, at
  runtime, from the same source objects — not a second, potentially
  divergent count.
- **Tier 1 is implemented, tested architecture — not planning-only — but
  remains completely unreachable from production**: absent from
  `Application`/`factory`/`server`/`ToolRegistry` imports, verified by
  dedicated AST isolation tests every commit. `pfsense_mcp_info`'s
  `tier1_package_present`/`tier1_imported_this_process` fields make this
  observable at runtime as well, explicitly documented (in the model's
  own field descriptions) as supporting evidence, not a substitute for
  the CI-enforced structural guarantee.
- **ADR-017's guidance layer is inert with no production consumer**:
  same isolation-test discipline; same runtime-observable fields
  (`guidance_package_present`/`guidance_imported_this_process`) with the
  same non-overclaiming documentation.
- Public CI uses no production configuration, credential, or live
  pfSense call.

## Verification evidence

- Full offline pytest (1583 passed, 42 live-skipped), branch coverage,
  Ruff, mypy, `make quick` (11 stages), `make validate` (20 stages), and
  `make package-check` pass on the release-state tree.
- Bandit, fixture safety, repository security, GET-only, WRITE
  import-absence, empty WRITE allow-list, WRITE-capability inactivity,
  and git-identity-leak checks pass.
- Fresh offline MCP enumeration confirms 42 READ tools (41 unchanged +
  `pfsense_mcp_info`), zero Engineer/WRITE tools, annotation parity
  (`readOnlyHint=true` on all 42; `openWorldHint=true` on 41,
  `openWorldHint=false` on `pfsense_mcp_info` specifically), and zero
  prohibited credential schema properties.
- Tier 1 and ADR-017 guidance isolation tests confirm both packages are
  unimported by any production module.
- `pfsense_mcp_info` was directly invoked in tests against both profiles:
  reports `registered_tool_count=42` for Auditor (including itself), and
  is entirely absent — not merely empty-valued — for Engineer, since
  Engineer's empty capability set means it never registers at all.
- No live pfSense call, production credential access, or mutation was
  performed while preparing this release state.

## Compatibility

All 41 tool names, inputs, outputs, schemas, and semantics from v0.3.0
are **unchanged**. This is a strictly additive, backward-compatible
change: one new tool, one new capability, no removal, no behavior change
to any existing tool. The public contract snapshot
(`tests/contracts/mcp_public_contract_v0.3.1.json`, renamed from the
v0.3.0-era file, all 41 pre-existing entries byte-identical, one new
entry added) continues to gate any future drift via `make validate`.

## Known limitations

Unchanged from v0.3.0 (see `docs/ACCEPTANCE_v0.3.0.md` for full detail),
carried forward without re-verification of items this release did not
touch: the supported trust boundary remains a local stdio MCP process
controlled by a trusted launcher; Linux remains the supported production
platform for descriptor-bound credential loading; CodeQL SARIF upload
remains an open, undecided option; Tier 1's Phase 5 (first capability
adapter) and Phase 6 (production activation) remain not started, each
gated by its own explicit owner/infrastructure decision — none of which
this release grants; `ADR-011`'s anti-rollback anchor backend selection
remains the one open Architecture Decision Record; GitHub Pages
redeployment remains a manual step; `dependabot.yml`'s cadence remains a
deferred judgment call.

New to this release, not yet acted on:

- The competitive review that motivated `pfsense_mcp_info` identified
  several further ADAPT-classified design ideas (session-scoped inventory
  caching with explicit freshness signaling; an observability/limitations
  vocabulary for a future Tier 1 PREPARE phase; the community pfSense
  REST API package's `dry_run` parameter as a future PREPARE-phase input;
  a config-test-before-apply discipline) — none implemented in this
  release, each requiring its own future design/authorization.
- A stale-wording finding from the v0.3.0 evidence packet (`README.md`'s
  "development tree" phrasing) has since been corrected in a separate,
  already-shipped commit; this release's own documentation sweep found
  no comparable new staleness.

## Acceptance boundary

This document accepts the v0.3.1 release state after its exact commit
passes the required local and remote gates. It does not authorize a tag,
push, GitHub Release, TestPyPI/PyPI upload, live pfSense access,
credential use, WRITE activation, or Phase 5 work. Each external
operation requires separate approval.
