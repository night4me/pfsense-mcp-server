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

### Schema diff: semantic, dimension-classified, cause-agnostic

A second owner direction (2026-08-28, same day, "make OpenAPI/Swagger
first-class") arrived alongside a real environment fact: LAB
(pfSense CE 2.9.0) and production (pfSense Plus 26.07) now run the
*same* pfREST package version, 2.10.2 — a controlled comparison
opportunity. The immediate, currently-authorized task was narrower
than a CE-vs-Plus comparison (production stays out of scope for
exploratory work): compare LAB's `LIVE_APPLIANCE_SCHEMA` against
current `PFREST_UPSTREAM`, and design — but do not execute — the
general-purpose comparison a future, separately-authorized CE-vs-Plus
run would need.

`pfsense_mcp.pfrest_docs.schema_diff.diff_schemas()` performs a
**semantic**, not byte-level, comparison across twelve dimensions:
`paths_methods`, `operation_ids`, `parameters`, `schemas_models`,
`fields`, `enums`, `default_values`, `required_packages`,
`auth_metadata`, `allowed_privileges`, `applies_immediately`,
`extensions`, `version_metadata`. A raw JSON/hash diff would flag
harmless key-ordering noise and a single instance-specific default
value the same way it would flag a missing endpoint — this module
instead classifies each dimension's differences as ADDED_IN_B /
REMOVED_IN_B / CHANGED, and states only **what** differs, never
**why**: every report carries a fixed disclaimer that a found
difference is not attributed to pfSense edition, release, installed
packages, runtime environment, configuration, pfREST build, or
schema-generation behavior.

`default_values` is deliberately its own dimension, separate from
`fields`' structural type/required/nullable shape — a default is
frequently instance-specific runtime state (a per-install random
secret, a runtime-computed capacity number, a next-available ID)
rather than part of the request/response contract; bundling it into
`fields` would make a harmless instance-specific value look, in shape,
identical to a genuine contract break. This distinction was not
theoretical: it is exactly what the real LAB-vs-upstream comparison
below found.

Endpoint-level structured facts (`required_packages`, `auth_metadata`,
`allowed_privileges`, `applies_immediately`) are extracted by reusing
`openapi_index.parse_openapi()`'s already-reviewed parser verbatim —
same "reuse, don't reimplement" precedent as the privilege
cross-check. Report output is capped at `MAX_ENTRIES_PER_DIMENSION`
(25) per dimension for display, but the underlying comparison is
always exhaustive — `dimension_totals` always reports the true count.
Pure — no I/O, no network, no appliance/upstream knowledge; the caller
supplies both already-fetched documents.

**Designed for today's authorized comparison and tomorrow's, without
executing tomorrow's.** `scripts/pfrest_schema_diff.py` selects each
side independently (`--a`/`--b` ∈ `upstream` / `appliance` / `file`).
`file` mode loads a previously saved OpenAPI JSON document from disk —
this exists specifically so a future, separately-authorized
comparison between two different appliances (does pfREST 2.10.2
expose an identical contract on pfSense CE 2.9.0 vs. pfSense Plus
26.07?) can be performed **offline**, from two independently captured
snapshots, without this script ever configuring itself to talk to two
appliances at once and without initiating a second live appliance
connection on its own. This arc captures only LAB's snapshot;
production was not contacted. Like the privilege cross-check,
explicitly out of the public MCP tool surface — an offline script,
`make pfrest-schema-diff`, not a new tool argument or query mode.

**Live-verified 2026-08-28, LAB only:** independently re-confirmed via
the existing safe READ-only identity path — `pfsense_get_system_version`
returned pfSense CE `2.9.0-RELEASE`, `get_system_restapi_version`
returned `current_version: v2.10.2`, matching the owner-supplied
hypothesis exactly. (Production's reported `pfSense Plus 26.07` /
`pfREST 2.10.2` was **not** independently verified this arc — production
remained out of scope for any exploratory contact per explicit
instruction, so that fact is recorded as owner-reported only.)

A fresh live fetch of both documents found the two 4.2+ MiB documents
were **not** byte-identical (different MD5), which `diff_schemas()`
correctly explained: **every one of the twelve contract dimensions
was fully identical** (all 267 paths/methods, all 186 schemas, every
field, every enum, every operationId, every parameter, every
`required_packages`/`auth_metadata`/`allowed_privileges`/
`applies_immediately` value, every `x-` extension, and top-level
version metadata) — the *only* differences were three `default_values`
entries, each independently explainable as ordinary instance-specific
runtime state, not a contract or edition difference:

| Model.field | PFREST_UPSTREAM default | LIVE_APPLIANCE_SCHEMA (LAB) default | Likely nature |
|---|---|---|---|
| `OutboundNATMapping.source_hash_key` | `0xb94e8d112da08b7b700dc151ab2e245f` | `0x41ae11df6cee557c5594a088f23dc383` | per-install random secret |
| `FirewallStatesSize.maximumstates` | `96000` | `198000` | runtime-computed capacity, dependent on the specific firewall's own sizing |
| `User.uid` | `2000` | `2003` | next-available UID, dependent on how many users already exist on that installation |

This is exactly the honest, unmanufactured result the owner's
instructions required: no version gap existed between LAB's installed
pfREST and the current public document (both 2.10.2), so there was no
drift to demonstrate — and the schema-diff tooling's own dimension
classification correctly distinguished "identical contract" from
"three ordinary instance-specific values," which a byte-level diff
alone would not have been able to explain.

## Consequences

- Public contract: 95 READ + 2 guidance (was 1) + 0 WRITE = 97 total
  (was 96). `tests/contracts/mcp_public_contract_v0.8.0.json` was
  regenerated after this review (an explicit, deliberate "API approval"
  step, exactly the gate `scripts/public_contract.py --update` exists to
  require) — not a version bump, not a new release.
- No pfSense mutation capability was added anywhere. Every new call this
  arc makes (`pfrest.org` fetches, the appliance schema fetch) is
  GET-only. The schema-diff addition does not change the public
  contract at all (offline script only, like the privilege
  cross-check).
- `docs.netgate.com` and `pfrest.org` remain permanently distinct
  provenance domains — nothing in this design lets one project's content
  be relabeled as the other's.

## Related

- [ADR-017](ADR-017-official-guidance-layer.md) / [ADR-018](ADR-018-version-aware-guidance-resolution.md) — the unchanged OFFICIAL_NETGATE layer this design stays decoupled from.
- [Tool & guidance reference](../TOOL_AND_GUIDANCE_REFERENCE.md) — the user-facing explanation of all four provenance labels and the new tool's query modes.
- `reports-ai/PFREST_LIVE_GUIDANCE_ARC_2026-08-28.md` — the full research/implementation/verification record for this arc.
