# ADR-035: pfREST live documentation guidance layer

- **Status:** Accepted and implemented — a new isolated package
  (`pfsense_mcp.pfrest_docs`) and a new public MCP guidance tool
  (`pfsense_get_api_guidance`), owner-authorized 2026-08-28
  (pfREST_LIVE_GUIDANCE_ARC).
- **Date:** 2026-08-28

## Context

`pfsense_get_official_guidance` (ADR-017/018) covers official Netgate
product documentation. It deliberately does not, and structurally
cannot, cover the pfSense REST API package itself
(`pfrest`/`pfSense-pkg-RESTAPI`) — that project is separate and
community-maintained, documented at `pfrest.org`, not `docs.netgate.com`,
and `pfsense_mcp.guidance`'s own `ALLOWED_DOCUMENT_HOSTS` allow-list
structurally forbids it from ever citing that host.

Two further gaps existed alongside this: (1) `pfsense_mcp.guidance.tool_guidance`
(Slice A of the prior arc) classified all 95 READ tools with
PROJECT_AUTHORED interpretation guidance, but had no consumer; (2) this
project has never live-fetched the connected appliance's own OpenAPI
schema (`/api/v2/schema/openapi`) — every existing consumer of appliance
schema evidence (`security_admin_composition.py`, for ADR-033 privilege
derivation) reads it only from a manually-supplied local file.

The owner authorized closing all three gaps in one arc: a narrow,
allowlisted live-fetch backend for `pfrest.org`, a live fetch of the
appliance's own schema for comparison, and wiring both together with the
existing PROJECT_AUTHORED foundation behind one new, clearly-labeled
public MCP tool.

## Decision

### A new, separately-isolated package

`pfsense_mcp.pfrest_docs` is a new top-level package, not a submodule of
`pfsense_mcp.guidance`. `pfsense_mcp.guidance`'s own isolation test
(`tests/guidance/test_isolation.py::test_guidance_package_imports_no_network_module`)
hard-forbids `socket`/`requests`/`httpx`/`urllib.request` — putting a
network-calling backend inside that package would require weakening a
guarantee that test exists specifically to enforce. Mirrors the
`pfsense_mcp.tier1`/`pfsense_mcp.transport` precedent: a distinct trust
domain gets its own package.

### Four provenance classes, dimension-specific authority

`Provenance` (in `pfrest_docs/provenance.py`): `PROJECT_AUTHORED`,
`PFREST_UPSTREAM`, `LIVE_APPLIANCE_SCHEMA`, `OFFICIAL_NETGATE` (the last
reused unchanged from ADR-017/018, never redefined here). No single
class outranks the others on every question — authority is
dimension-specific:

- Endpoint/field/model **existence on the connected appliance**:
  `LIVE_APPLIANCE_SCHEMA` > `PFREST_UPSTREAM`.
- General pfREST **API semantics** (auth modes, query/filter/sort
  syntax, HATEOAS): `PFREST_UPSTREAM`.
- pfSense **operational/product meaning**: `OFFICIAL_NETGATE`
  (unchanged).
- **This project's own tool meaning**: `PROJECT_AUTHORED`.

When two sources disagree on a question neither is authoritative for,
both are surfaced with the disagreement stated explicitly
(`CrossSourceGuidance.conflicts`) — never silently merged or dropped.

### One shared, bounded evidence shape

`GuidanceEvidence` (`pfrest_docs/models.py`) is one Pydantic model used
by every provenance class rather than a bespoke schema per source: each
source's content becomes a short, ordered tuple of bounded fact strings
(`MAX_FACTS_PER_EVIDENCE=24`, `MAX_FACT_LENGTH=400`), individually
attributed to exactly one `provenance`+`source` pair. `content_hash` is
a freshness/cache-key hash of the exact content returned in that
response — never a claim that it equals whatever is live right now (the
same TB-G3 clarification `pfsense_mcp.guidance.models.excerpt_hash`
documents for the unrelated bundled-snapshot case, now resolved for this
new live-retrieval case by never conflating the two).

### The fetch layer: narrow, allowlisted, streamed, bounded

`pfrest_docs/fetch.py` is the only module in the whole codebase (besides
`pfsense_mcp.transport`, a different trust domain) that performs network
I/O to a non-pfSense host, and the only module in `pfrest_docs` allowed
to import `httpx` (enforced by `tests/pfrest_docs/test_isolation.py`).
Deliberately NOT a generic web-fetch primitive:

- HTTPS-only, GET-only.
- Fixed exact-host allowlist (`ALLOWED_HOSTS = {"pfrest.org"}`) — never
  a caller-supplied host, never a suffix/subdomain match (verified live
  2026-08-28: `www.pfrest.org` redirects to `pfrest.org` but is not
  itself allowlisted, so this code never originates a request to it).
- At most one redirect, only to a URL whose host is also in the
  allowlist; an HTTP downgrade redirect is rejected the same as a
  cross-host one.
- Streamed, byte-counted reads with a hard cap (`MAX_RESPONSE_BYTES = 8 MiB`,
  comfortably above the real ~4.2 MiB public document measured live).
- Content-Type allowlist (`application/json`, `text/html` only).
- No credentials, no cookies, no caller-supplied headers — only a fixed
  `Accept` value from a closed set and a fixed, descriptive User-Agent.
- Explicit 5s connect / 15s read timeouts.
- Fails closed: every failure raises one of a small set of narrow
  `FetchError` subclasses with a fixed message, never a partial result.

### Cache: in-memory, bounded, TTL from `Cache-Control`

`pfrest_docs/cache.py` — a small, hard-capped (`MAX_CACHE_ENTRIES=32`)
in-memory dict, since this package only ever caches a handful of
distinct URLs (one OpenAPI document, six guide-topic pages). TTL is
parsed from the upstream's own `Cache-Control: max-age` (pfrest.org sent
`max-age=600` on every response checked live), falling back to a fixed
default if absent/unparseable. A `STALE_BUT_USABLE` grace window serves
the last-known-good copy if a refresh fails, rather than failing the
whole tool call over one transient network error — reliability over
strict freshness for read-only documentation content. Deliberately not
persistent (see the module's own docstring for why that's an acceptable
first-version simplification, not an oversight).

### Structured OpenAPI index, never the raw document

`pfrest_docs/openapi_index.py` parses an already-fetched document into
`lookup_endpoint(path, method)`/`lookup_model(name)` — never exposes the
complete document. pfREST's own operation descriptions are HTML
fragments with a fixed structured template (verified live 2026-08-28:
`<h3>Description:</h3>...<h3>Details:</h3>**Endpoint type**: ...`); tags
are stripped (never rendered/executed) and the structured
`**Label**: value` lines are parsed into typed fields via a fixed label
set — a label that changes upstream simply stops matching, never raises.
`$ref` resolution is deliberately shallow: a field that references
another model is surfaced as a cross-reference name
(`FieldDoc.ref_model`), never inlined — this keeps every result bounded
regardless of real schema nesting depth and is structurally incapable of
following a `$ref` recursively at all (verified live 2026-08-28: the
current document has zero self-referencing or 2-cycle schemas, but this
code does not rely on that fact remaining true). Field/description
counts are capped (`MAX_FIELDS_PER_MODEL=25`, tightened from an initial
40 after measuring the worst real case, `ACMECertificateDomain` at 297
fields/~90 KB raw, down to ~6.4 KB serialized at the final bounds — an
explicit Phase 14 token-efficiency measurement, not a guess).

### Appliance-schema evidence: the existing authenticated transport, not a new one

`pfrest_docs/appliance_schema.py` fetches `/api/v2/schema/openapi`
through the existing, already-authenticated `PfSenseClient` — the same
trust boundary every READ tool already uses, confirmed against live
upstream guide text (`https://pfrest.org/SWAGGER_AND_OPENAPI/`: "The
full OpenAPI schema is available at the `/api/v2/schema/openapi`
endpoint"). A new `Endpoints.SYSTEM_SCHEMA_OPENAPI` entry and
`PfSenseClient.get_system_schema_openapi()` method were added
specifically for this — internal-only, never exposed as its own public
MCP tool (mirrors `resolve_appliance_identity()`'s reuse pattern: zero
*direct* `client.<method>()` calls inside the guidance tool's own
source). `ApplianceSchemaCache` holds one parsed index per server
process (10-minute TTL, stale-serves on refresh failure) so repeated
guidance queries don't re-fetch a multi-megabyte document every call. A
defense-in-depth size guard (`_MAX_APPLIANCE_SCHEMA_BYTES = 32 MiB`)
refuses to index an implausibly large response even though the source is
already authenticated and trusted.

### Composition: bounded assembly, no semantic merging

`pfrest_docs/composition.py` is deliberately thin: it only truncates an
already-assembled `GuidanceEvidence` list to `MAX_EVIDENCE_ENTRIES=8`
and does not import `pfsense_mcp.guidance` at all (verified by
`tests/pfrest_docs/test_isolation.py::test_pfrest_docs_package_does_not_import_guidance_package`).
The actual per-source semantic comparison (does `PFREST_UPSTREAM`
disagree with `LIVE_APPLIANCE_SCHEMA` about existence?) happens in the
tool file itself, which has full typed access to both retrievals —
never inferred back out of already-flattened fact strings.

### The public tool: separate from `pfsense_get_official_guidance`, by design

`pfsense_get_api_guidance` (`tools/read/api_guidance.py`) is the
**second** deliberate, reviewed crossing of the guidance-package import
boundary (`tests/guidance/test_isolation.py::ALLOWED_GUIDANCE_IMPORTERS`)
and the **only** module allowed to import `pfsense_mcp.pfrest_docs`
outside that package itself
(`tests/pfrest_docs/test_isolation.py::ALLOWED_PFREST_DOCS_IMPORTER`).
Kept separate from `pfsense_get_official_guidance` rather than extending
it: blending `PFREST_UPSTREAM`/`LIVE_APPLIANCE_SCHEMA` into that tool
would corrupt its own settled meaning (its `disclaimer` literal
explicitly says "official Netgate sources") and force
`GuidanceReference`'s Netgate-specific shape onto sources it was never
designed to represent.

Four bounded query modes (`tool`/`endpoint`/`model`/`topic`) — every
input is used exclusively as a lookup key into already-fetched data,
never as a URL; `fetch.fetch()` is only ever called internally with its
own fixed constants, never with caller-supplied `endpoint_path`/
`model_name`/`topic`. Deliberately NOT `fetch_public_openapi()` as a
public method (would invite dumping the whole document) and NOT
`lookup_reference(symbol)` (no structured PHP-reference index exists
upstream to back it). Registered exactly like
`pfsense_get_official_guidance`: gated only on "this profile grants at
least one capability", not on any specific `Capability`, and accounted
for in `KNOWN_GUIDANCE_TOOL_NAMES`/`scripts/public_contract.py`'s
`GUIDANCE_TOOL_NAMES` — never counted as a 96th/97th READ tool.

### Slice A wiring

`query_mode="tool"` is the one place `pfsense_mcp.guidance.tool_guidance.get_tool_guidance()`
(Slice A, previously unwired) is actually consumed — its
`ResultKind`/`interpretation`/`related_tools`/`empty_result_is_meaningful`/
`secrets_intentionally_omitted` fields become one `PROJECT_AUTHORED`
`GuidanceEvidence` entry. `tests/guidance/test_tool_guidance.py`'s prior
"not yet wired into any production module" guard was updated (not
deleted) to "wired into exactly one reviewed production module" —
`_ALLOWED_TOOL_GUIDANCE_CONSUMER`, same discipline as every other
allow-list in this codebase.

### Privilege cross-check: advisory only, offline script, not a public tool

Owner direction extended this arc's scope to add a strictly advisory
cross-check between what PFREST_UPSTREAM and LIVE_APPLIANCE_SCHEMA each
declare as a READ tool's required pfSense privilege, and (supplementarily)
whether that value agrees with this project's own ADR-033 pinned-source
algorithm (`security_privileges.compute_privilege_from_url()`, already
reviewed and verified byte-identical to `pfSense-pkg-RESTAPI`'s own
`Core/Endpoint.inc::get_method_priv_name()` across v2.7.7-v2.10.0).

Reuses `security_privileges.py`'s existing, already-tested
`lookup_schema_privileges()`/`read_profile_requirements()` pure
functions verbatim — `scripts/pfrest_privilege_crosscheck.py` is the one
new place that fetches the two raw schema dicts and hands them to that
existing module, never reimplementing privilege parsing.

**Compares the two sources directly to each other, not only each
independently against the pinned algorithm**: an earlier draft routed
both sides through `security_privileges.resolve_privilege()`'s own
fail-closed gate, which requires a source's privilege to already equal
the pinned-source value before it is considered `ok` — that gate makes
genuine cross-source disagreement structurally unreachable as "DRIFT"
(two sources both `ok` are, by that gate's own construction, both
already equal to the same third value, hence trivially equal to each
other). Caught by this script's own test suite
(`test_run_crosscheck_detects_real_drift`), not assumed — the fix
compares `lookup_schema_privileges()`'s raw, unfiltered privilege lists
between the two sources directly.

**Explicitly out of the public MCP tool surface** (owner instruction:
"MUST NOT... expand the MCP surface"): delivered as an offline script
(`scripts/pfrest_privilege_crosscheck.py`), exit code 1 on any DRIFT
finding, suitable for CI or manual operator use — never a new tool
argument, output field, or query mode on `pfsense_get_api_guidance`.
Never grants a privilege, modifies a service account, modifies ADR-033's
mapping, authorizes an endpoint, or turns an upstream privilege claim
into trusted configuration — it only classifies and reports.

Live-verified 2026-08-28 against the real public document and the real
LAB appliance: 94 of 94 privilege-bearing tool endpoints MATCH across
PFREST_UPSTREAM and LIVE_APPLIANCE_SCHEMA, 0 drift, 0 explained
differences — independent confirmation that ADR-033's pinned-source
algorithm and both live sources currently agree completely.

## Consequences

- Public contract: 95 READ + 2 guidance (was 1) + 0 WRITE = 97 total
  (was 96). `tests/contracts/mcp_public_contract_v0.8.0.json` was
  regenerated after this review (an explicit, deliberate "API approval"
  step, exactly the gate `scripts/public_contract.py --update` exists to
  require) — not a version bump, not a new release.
- No pfSense mutation capability was added anywhere. Every new call this
  arc makes (`pfrest.org` fetches, the appliance schema fetch) is
  GET-only.
- `docs.netgate.com` and `pfrest.org` remain permanently distinct
  provenance domains — nothing in this design lets one project's content
  be relabeled as the other's.

## Related

- [ADR-017](ADR-017-official-guidance-layer.md) / [ADR-018](ADR-018-version-aware-guidance-resolution.md) — the unchanged OFFICIAL_NETGATE layer this design stays decoupled from.
- [Tool & guidance reference](../TOOL_AND_GUIDANCE_REFERENCE.md) — the user-facing explanation of all four provenance labels and the new tool's query modes.
- `reports-ai/PFREST_LIVE_GUIDANCE_ARC_2026-08-28.md` — the full research/implementation/verification record for this arc.
