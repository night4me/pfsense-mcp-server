# Acceptance — v0.9.0

**Status: published — the `v0.9.0` tag and PyPI release point at this
commit.** The annotated git tag `v0.9.0` was created and pushed pointing
at commit `1a9378c8d961b8bcf5dc5b743da39b7451248947`; the GitHub Release
was published from that tag
(<https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.9.0>),
which triggered the `publish.yml` OIDC trusted-publishing workflow (run
`33190942299`, `build` and `publish` jobs both `success`). PyPI's JSON
API confirms `0.9.0` is `info.version` and the latest entry in
`releases`; neither artifact is yanked. PyPI's own provenance API
(`/integrity/pfsense-mcp-server/0.9.0/.../provenance`) returns a valid
Sigstore attestation bundle for both the wheel and sdist whose
certificate SAN references this exact workflow file
(`.github/workflows/publish.yml`), the `refs/tags/v0.9.0` ref, this
exact commit, and this exact GitHub Actions run. Both public artifacts
were downloaded directly from `files.pythonhosted.org` and their
member-by-member content (267 wheel files; 346 sdist files) confirmed
byte-identical to the locally-built RC artifacts — the outer-archive
SHA256 differs only because of non-reproducible container timestamps
between separate build invocations, not any content difference. A
clean installation of `pfsense-mcp-server==0.9.0` from the real PyPI
index (not the local build) was independently verified in a fresh,
isolated environment outside the repository: reports version `0.9.0`,
`import pfsense_mcp` resolves from `site-packages`, the
`pfsense-mcp-server` CLI entry point fails closed with a clean
"configuration error" message (no traceback) when required environment
variables are absent, `pfsense-mcp-security --help` succeeds, zero
network attempted at import across every guidance-related module, and
a fresh `public_contract.build_contract()` call against the installed
package shows exactly 97 registered tools (95 READ + 2 guidance —
`pfsense_get_official_guidance` and `pfsense_get_api_guidance` both
present — 0 WRITE). This status line was only written after that
independent post-publication verification succeeded. `v0.8.0`'s own
tag, GitHub Release, and PyPI artifact remain unmoved as an accurate
historical record. See
`reports-ai/V0_9_0_PUBLICATION_2026-08-28.md` for the complete,
itemized publication evidence.

## Release scope

`v0.9.0` adds one new MCP tool and two offline maintainer scripts, all
strictly READ-only / advisory. Public MCP contract: **95 pfSense READ
tools + 2 documentation guidance tools (was 1), 0 default-reachable
WRITE = 97 total (was 96).** Confirmed by a new
`tests/contracts/mcp_public_contract_v0.9.0.json` snapshot, independently
re-derived from source this arc (not trusted from any prior report),
whose only tool-list difference from the restored, byte-accurate
`v0.8.0` snapshot is the addition of `pfsense_get_api_guidance`.

Full detail is in `CHANGELOG.md`'s `[Unreleased]` entry (kept
`[Unreleased]` rather than dated/renamed, since this exact document is
the record of the not-yet-tagged state) — this document summarizes the
independently verified evidence a reviewer needs to accept the release.

## Why this release exists

Two owner-authorized arcs landed since `v0.8.0` published:

1. **pfREST live documentation guidance layer** — a new,
   separately-isolated `pfsense_mcp.pfrest_docs` package and
   `pfsense_get_api_guidance` MCP tool, covering the community-maintained
   pfREST package (`pfSense-pkg-RESTAPI`, documented at `pfrest.org`) —
   structurally distinct from `pfsense_get_official_guidance` (Netgate
   product documentation), never blended. Four bounded query modes
   (`tool`/`endpoint`/`model`/`topic`); evidence is explicitly labeled
   by provenance (`PROJECT_AUTHORED` / `PFREST_UPSTREAM` /
   `LIVE_APPLIANCE_SCHEMA`), never silently merged. See
   [ADR-035](adr/ADR-035-pfrest-live-guidance-layer.md).
2. **Semantic OpenAPI schema-diff tooling** — an offline,
   maintainer-facing privilege drift check
   (`make pfrest-privilege-crosscheck`) and a twelve-dimension semantic
   schema comparison (`make pfrest-schema-diff`), both strictly
   advisory and outside the public MCP surface.

None of this is reachable from, or wired into, `pfsense_mcp.server`
at import time or ordinary startup — every network-capable code path
in the new package is deferred to inside the tool function itself, and
the two maintainer scripts are separate CLI entry points, never part
of `make quick`/`make validate`/`make release-check` (both require
live network access).

## Independently verified release evidence (this RC audit, 2026-08-28)

### Public contract, re-derived from source

- `scripts/public_contract.py` re-run fresh (not read from a prior
  report): **95 pfSense READ tools, 2 guidance tools, 97 total**,
  registered by the default `auditor` profile (`READ_CAPABILITIES`
  only — confirmed from `profiles.py` directly, not assumed).
- WRITE reachability independently re-traced through
  `ToolRegistry.register_all()`/`register_all_write()`: zero WRITE
  tools registered under any profile except an explicit
  `write_protected` opt-in, which still requires
  `WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION` to exist and a
  successfully constructed write runtime (ADR-028's three-condition
  gate) before `set_firewall_alias_description_v1` becomes reachable.
- **Contract snapshot integrity finding and fix**: the checked-in
  `tests/contracts/mcp_public_contract_v0.8.0.json` had been silently
  overwritten in place by the pfREST arc (commit `77823ea`) to hold the
  new 97-tool contract, contradicting this exact document's own
  historical predecessor's claim that the file was "byte-identical to
  v0.7.2" (96 tools). Restored to its original, actually-published
  v0.8.0 content (from commit `771fb85`) as an accurate historical
  record; the current 97-tool contract now lives in its own correctly
  versioned `tests/contracts/mcp_public_contract_v0.9.0.json`, and
  `scripts/public_contract.py`'s `SNAPSHOT` now points there.

### Security re-audit — falsification, not assertion

All of the following were actively checked against current source
(2026-08-28), not assumed from prior reports:

- `pfsense_mcp.pfrest_docs` has zero import path to
  `tier1`/`write_endpoints`/`write_api_client`/`write_types`/
  `rest_api_client`/`transport`/`tools` outside the one reviewed
  `api_guidance.py` crossing (`tests/pfrest_docs/test_isolation.py`,
  re-run fresh: 6 passed).
- Network I/O is confined to exactly one module (`fetch.py`); `httpx`
  is imported by no other module in the package.
- `fetch._validate_url()` rejects non-HTTPS and any hostname outside
  the fixed `frozenset({"pfrest.org"})` allowlist, applied to both the
  original URL and any redirect target before it is followed (at most
  one redirect tolerated); `httpx.Client(follow_redirects=False, ...)`
  confirmed directly in source.
- `fetch.py`'s `httpx.Client` construction sends only a fixed
  `User-Agent`; no pfSense credential, cookie, or caller-supplied
  header ever reaches it — confirmed by direct source read, not
  inferred from design intent.
- `GuidanceEvidence`/`CrossSourceGuidance`/`ApiGuidanceResult`
  (`extra="forbid"`, `frozen=True`) carry no field shaped like a
  capability, endpoint, method, or confirmation token — confirmed by
  introspecting the live Pydantic models' `model_fields`, not by
  reading the source and assuming.
- `src/pfsense_mcp/server.py` contains zero references to
  `pfrest_docs` or `api_guidance` — no eager call at import or
  ordinary MCP startup.
- `pfsense_get_api_guidance` exposes only four bounded query modes and
  the provider/appliance-cache classes expose only three bounded
  lookup methods total — no code path can return a raw, full OpenAPI
  document through MCP.
- `tests/test_api_guidance_tool.py::test_module_import_triggers_no_network`
  and `test_bare_build_call_triggers_no_network` re-run fresh: both
  pass (monkeypatch `httpx.Client.send` to raise if ever invoked).
- **Privilege finding, verified live against real LAB**: the
  `pfsense-mcp` service account (provisioned by this project's own
  automated bootstrap flow, which grants exactly the narrow privilege
  set `security_privileges.read_profile_requirements()` derives — never
  broader) does **not** hold the `api-v2-schema-openapi-get` privilege
  that `security_privileges.compute_privilege_from_url()` would derive
  for `GET /api/v2/schema/openapi`. Despite this, a live call against
  LAB with that exact account succeeded (200, full document returned) —
  confirming empirically that pfREST does not privilege-gate its own
  self-describing schema endpoint beyond requiring authentication.
  **No new privilege requirement was introduced**: nothing needs to be
  added to the setup wizard's grant set, and the honest reason is "the
  endpoint doesn't require one," verified live, not assumed.

### Coverage gaps found and closed this RC audit

Branch-coverage analysis (`coverage run` against the new package's own
test suite) found four real, if low-severity, untested branches —
each a structural mirror of an already-tested equivalent — and closed
all four with new tests:

- `api_guidance.py`'s `model`-query-mode + appliance-unavailable path
  (endpoint-mode's equivalent was tested; model-mode's was not).
- `provider.py`'s `lookup_guide_topic()` stale-cache-serve-on-refetch-
  failure and fully-unavailable-with-no-prior-cache paths (a *different*
  code path than `_get_index()`'s own already-tested stale-fallback,
  since `lookup_guide_topic()` has its own inline fallback block).
- `appliance_schema.py`'s `lookup_model()` unavailable-index path
  (`lookup_endpoint()`'s equivalent was tested; `lookup_model()`'s was
  not).

Two remaining minor gaps (a `json.dumps` `TypeError`/`ValueError` guard
in `appliance_schema.py` that is effectively unreachable from any real
`json.loads`-decoded document, and an unrecognized-value fallback in
`openapi_index._parse_bool_detail()`) were left as-is: genuinely
defensive, low-value to force-test, not release blockers.

### Live upstream recheck (2026-08-28, this RC audit)

Fresh live `GET https://pfrest.org/api-docs/openapi.json`: HTTPS, `200`,
`application/json`, `openapi: "3.0.0"`, 267 paths, 186 schemas,
`ETag`/`Last-Modified`/`Cache-Control: max-age=600` all present and
consistent with every earlier check this arc — no drift found.

## What this release does NOT do

- Does not remove, rename, or change the behavior of any existing tool.
- Does not add, widen, or change any WRITE capability or reachability.
- Does not weaken, skip, or delete any security test, or relax any
  authorization/network/redirect/credential-isolation invariant.
- Does not touch production pfSense at any point.
- Does not tag, release, or publish anything — that remains a separate,
  explicit owner decision.

## Full validation (re-run at v0.9.0's release-candidate commit)

Every check below was run fresh at commit `b850548aa308471d5c6b2a2600169395cac39ea1`
(the exact RC preparation commit), not read from any prior report:

- `pytest` (full suite, `pytest-xdist`, normal deps): **4936 passed, 42
  skipped, 0 failed**.
- `pytest` at verified minimum dependency versions
  (`mcp==1.21.1`/`httpx==0.27.1`/`pydantic==2.11.0`/`cryptography==43.0.0`,
  Python 3.11.15): **4936 passed, 42 skipped, 0 failed** — an initial
  run at min-deps versions failed on one test (`test_artifact_manifest.py`
  hardcoded a stale version literal, described above); fixed, then
  re-verified clean.
- `ruff format --check` / `ruff check`: clean (777 files).
- `mypy` (`src/pfsense_mcp scripts lab witness_daemon signing`): `Success:
  no issues found in 403 source files`.
- `bandit -c pyproject.toml -r src/pfsense_mcp scripts witness_daemon
  signing`: no issues identified (0 High/Medium/Low).
- `mkdocs build --strict`: clean (only the same four pre-existing,
  unrelated relative-link notices present since before this arc).
- `public_contract.py`: OK (95 pfSense READ tools, 2 guidance tools, 97
  total) against the new `mcp_public_contract_v0.9.0.json` snapshot.
- `make quick`: **PASSED (11/11 stages)**.
- `make validate`: **PASSED (20/20 stages)**.
- `make release-check` (the full monolithic chain — `release_state_check`
  + `validate` + `package-check` + `twine check --strict` +
  `reproducible-build` + `min-deps-check` + `artifact-manifest`):
  **PASSED**, offline, no tag/upload/credentials/network-appliance
  access.
- `make reproducible-build`: OK, byte-identical artifacts across two
  independent same-epoch builds.
- Built-artifact proof: wheel (`pfsense_mcp_server-0.9.0-py3-none-any.whl`,
  595,189 bytes,
  `sha256:9948101123b95cf6940c5c60c35fd4fac513c890d596e10ce023c6fd2091c266`)
  and sdist (`pfsense_mcp_server-0.9.0.tar.gz`, 526,471 bytes,
  `sha256:1875cb97c1ee6be60438983f1d20ab42b9d84715410c0e35a43cb748ffbacc47`)
  built and inspected directly: member lists grepped for secrets/LAB
  files (none found beyond a benign false-positive on filenames
  containing "available"), METADATA/entry_points.txt/WHEEL confirmed
  correct package name, version `0.9.0`, both console-script entry
  points, `Requires-Python: >=3.11`, and MIT license metadata. Both
  artifacts installed into a fresh, isolated environment (via `uv venv`,
  since the system Python's `ensurepip` is unavailable in this
  environment) and exercised from outside the repository working
  directory: import resolves from `site-packages`,
  `importlib.metadata.version("pfsense-mcp-server") == "0.9.0"`, the
  `pfsense-mcp-server` entry point fails closed with a clean
  "configuration error" message (no traceback) with no environment
  configured, `pfsense-mcp-security --help` succeeds, and a fresh
  `public_contract.build_contract()` call against the *installed*
  package independently confirmed 97 registered tools (95 READ + 2
  guidance, both guidance tool names present, zero WRITE-shaped tool
  names) — matching the source-tree result exactly.
**Update, after push:** GitHub Pages redeployed from this exact commit
(`mkdocs gh-deploy --strict`); `Docs Pages freshness` (re-triggered via
`workflow_dispatch`), `CI`, and `CodeQL` GitHub Actions results are
recorded in `reports-ai/V0_9_0_RELEASE_READINESS_2026-08-28.md` —
not restated here to avoid this document claiming a fact before it
was actually true at commit time.

See `reports-ai/V0_9_0_RELEASE_READINESS_2026-08-28.md` for the
complete, itemized audit this document summarizes.

## Acceptance boundary

**Update (2026-08-28): publication complete.** The owner explicitly
authorized "publication of pfsense-mcp-server v0.9.0" from RC SHA
`1a9378c8d961b8bcf5dc5b743da39b7451248947`. Tag `v0.9.0`, the GitHub
Release, and the PyPI upload were each performed following exactly the
sequence this document originally described as pending, and each was
independently re-verified after the fact (see the "Status" paragraph
above and `reports-ai/V0_9_0_PUBLICATION_2026-08-28.md`). No version
other than `v0.9.0` was published; the tag was never moved from the
authorized RC commit; the public MCP contract published matches
exactly what this document's "Full validation" section already
verified; no pfSense LAB or production mutation was performed as part
of release.
