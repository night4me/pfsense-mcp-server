# Tools and guidance: what you get, and where it comes from

This page explains what the three kinds of tool this server registers
actually are, and — for the two documentation-guidance tools
specifically — exactly whose words you're reading when you use them.

## Public tool counts (current, source-derived)

- **95 pfSense READ tools** — each one calls exactly one fixed pfREST
  `GET` endpoint through one statically checked client method, gated by
  a named `Capability`. See [the full reference](API.md) and
  [Compatibility](COMPATIBILITY.md) for per-tool detail.
- **2 guidance tools** — documentation lookup, not a pfSense appliance
  call. Counted separately, never blended into the 95:
  - `pfsense_get_official_guidance` — official Netgate pfSense product
    documentation.
  - `pfsense_get_api_guidance` — this project's own tool interpretation,
    the community-maintained pfREST package's live API reference, and
    the connected appliance's own OpenAPI schema.
- **0 registered WRITE tools** in the default profile. Exactly one
  WRITE-capable tool exists in this codebase at all
  (`set_firewall_alias_description_v1`) and is reachable only under an
  explicit `write_protected` opt-in — see
  [the security model](SECURITY_MODEL.md).

These counts are enforced mechanically, not just documented: a snapshot
test fails CI if the registered tool set drifts from the reviewed,
approved contract.

## READ tools vs. the guidance tools

A **READ tool** (`pfsense_get_*`) tells you what is true about *your
specific, connected appliance right now* — configuration, live status,
or derived state, depending on the tool (see the per-tool notes in
[the API reference](API.md)).

The **guidance tools** tell you something different: general
documentation, not observed live state. Neither can reflect your
appliance's actual configuration by itself — for that, use the matching
READ tool instead. Every result either guidance tool returns carries a
fixed disclaimer field saying exactly this, structurally, not just in
prose.

## Four provenance labels, never blended

Every piece of guidance content this server can return is labeled with
exactly one of four provenance values. Authority is **dimension-specific**
— no single source outranks the others on every question:

| Label | Authoritative for | Source |
|---|---|---|
| **`OFFICIAL_NETGATE`** | pfSense's general product/operational meaning | `docs.netgate.com`, cited by URL — the guidance tool's own text is project-authored, never a quotation |
| **`PFREST_UPSTREAM`** | General pfREST API semantics (auth modes, query syntax, endpoint/model reference) | The community-maintained pfREST package's own live documentation at [pfrest.org](https://pfrest.org/) — explicitly **not** Netgate documentation |
| **`LIVE_APPLIANCE_SCHEMA`** | Whether a specific endpoint/model exists **on your connected appliance right now** | The appliance's own `/api/v2/schema/openapi` response, fetched through the same authenticated transport every READ tool uses |
| **`PROJECT_AUTHORED`** | What this project's own tool returns and how to interpret it | This codebase, reviewed like source code |

When two sources disagree on a question neither is authoritative for
(e.g. `PFREST_UPSTREAM` describes an endpoint the connected appliance's
own schema doesn't have), both are surfaced side by side with the
disagreement stated explicitly — never silently merged, never silently
dropped, never resolved by picking a "winner" outside the rule above.

Documentation guidance — from any of the four sources above — is
always advisory. It is never observed live state by itself, and it can
never authorize, select, or influence any action this server takes.
See [the security model](SECURITY_MODEL.md) and
[ADR-017](adr/ADR-017-official-guidance-layer.md)/[ADR-018](adr/ADR-018-version-aware-guidance-resolution.md)
for the full architecture and the tests that prove this boundary holds.

## `pfsense_get_official_guidance`

Every entry in the Netgate guidance registry is **project-authored** —
written and reviewed by this project, describing what a
Netgate-documented pfSense feature generally is, never a quotation of
Netgate's own text. Each entry cites its official source page
(`docs.netgate.com`) for provenance, and carries a computed
applicability state (does this appear to match your appliance's
observed edition/version, or not) — resolved automatically from the
appliance's own reported version, never something you supply.

**Current coverage: 28 of 86 distinct READ capabilities** have a
registered guidance entry today. This is an honest, unpadded number,
not a target dressed up as an achievement — a capability with no
registered entry simply returns an empty result (`NO_OFFICIAL_GUIDANCE_FOUND`),
never a fabricated answer.

## `pfsense_get_api_guidance`

Covers the gap `pfsense_get_official_guidance` deliberately does not:
the pfSense REST API package itself (`pfrest`/`pfSense-pkg-RESTAPI`) is
**not** Netgate product documentation — it's a separate,
community-maintained package, documented at
[pfrest.org](https://pfrest.org/), not `docs.netgate.com`.

Four bounded query modes — every input is used only as a lookup key
into already-fetched, cached, parsed documentation; none of them can
make this tool fetch an arbitrary URL:

| `query_mode` | Required arguments | Returns |
|---|---|---|
| `tool` | `tool_name` (a real pfsense-mcp-server tool name) | This project's own `PROJECT_AUTHORED` interpretation of that tool, plus (if it maps to a known pfREST endpoint) `PFREST_UPSTREAM` and `LIVE_APPLIANCE_SCHEMA` evidence for it |
| `endpoint` | `endpoint_path` (e.g. `/api/v2/firewall/alias`), `endpoint_method` (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`) | `PFREST_UPSTREAM` and `LIVE_APPLIANCE_SCHEMA` evidence for that exact path/method |
| `model` | `model_name` (a real pfREST OpenAPI schema name, e.g. `FirewallAlias`) | `PFREST_UPSTREAM` and `LIVE_APPLIANCE_SCHEMA` evidence for that model's fields |
| `topic` | `topic` (one of `AUTHENTICATION_AND_AUTHORIZATION`, `WORKING_WITH_OBJECT_IDS`, `QUERIES_FILTERS_AND_SORTING`, `COMMON_CONTROL_PARAMETERS`, `WORKING_WITH_HATEOAS`, `SWAGGER_AND_OPENAPI`) | A bounded `PFREST_UPSTREAM` excerpt of that guide page |

Example: *"What does `pfsense_get_firewall_aliases` actually call, and
does my appliance have that endpoint?"*

```json
{"name": "pfsense_get_api_guidance", "arguments": {"query_mode": "tool", "tool_name": "pfsense_get_firewall_aliases"}}
```

Returns three independently labeled evidence entries (`PROJECT_AUTHORED`,
`PFREST_UPSTREAM`, `LIVE_APPLIANCE_SCHEMA`) plus, if they disagree on
existence, an explicit `conflicts` entry explaining which source is
authoritative for that question and why.

**How it fetches `PFREST_UPSTREAM` content**: a narrow, allowlisted
(exact host `pfrest.org` only), HTTPS-only, GET-only fetcher with a hard
response-size cap, single-redirect tolerance restricted to the same
allowlisted host, content-type validation, and a bounded in-memory
cache honoring the upstream's own `Cache-Control` headers. No network
call happens at server import or startup — only when this tool is
actually invoked with a query that needs it. Never fetches from any
other host, regardless of what string is passed as `endpoint_path`,
`model_name`, or `topic` — those are always lookup keys against
already-fetched data, never URLs.

**How it fetches `LIVE_APPLIANCE_SCHEMA` content**: through the same
authenticated `PfSenseClient` transport every READ tool already uses —
a single GET to your configured appliance's `/api/v2/schema/openapi`,
cached in memory for the server process's lifetime (falling back to a
stale cached copy if a later refresh fails, never failing the whole
tool call over one transient appliance error).

**When either source is unreachable**, the corresponding evidence entry
says so explicitly (`freshness: upstream_unavailable`) rather than
silently omitting itself or fabricating an answer.

### Privilege drift check (maintainer/operator tool, not part of the MCP surface)

`make pfrest-privilege-crosscheck` (`scripts/pfrest_privilege_crosscheck.py`)
compares what PFREST_UPSTREAM and, if a real appliance is configured,
LIVE_APPLIANCE_SCHEMA each declare as a READ tool's required pfSense
privilege, and reports MATCH / EXPLAINED_DIFFERENCE / DRIFT for every
tool with a real endpoint. Strictly advisory and read-only — it never
grants a privilege, modifies a service account, or changes this
project's own ADR-033 privilege mapping. Deliberately **not** part of
`pfsense_get_api_guidance` or any other MCP tool (it would expand the
public surface for a maintainer-facing check); run it manually or wire
it into your own CI. Requires network access, so it is not part of
`make quick`/`make validate`, matching this project's established
pattern for every other live-network check
(`make docs-freshness-check`, `make guidance-corpus-audit`).

### Schema diff (maintainer/operator tool, not part of the MCP surface)

`make pfrest-schema-diff` (`scripts/pfrest_schema_diff.py`) performs a
semantic, dimension-classified comparison between two OpenAPI
documents — by default, live PFREST_UPSTREAM vs. a configured
appliance's live LIVE_APPLIANCE_SCHEMA. Twelve dimensions are compared
(paths/methods, operationIds, parameters, schemas/models, fields,
enums, field default values, required_packages, auth metadata,
allowed_privileges, applies_immediately, `x-` extensions, top-level
version metadata) and classified as added/removed/changed — never a
raw JSON/byte diff, and never an attributed cause. `--a file`/`--b
file` loads a previously saved snapshot from disk instead of making a
live call, which is how a future, separately-authorized comparison
between two different appliances (e.g. pfSense CE vs. Plus running the
same pfREST version) can be performed offline. Strictly advisory and
read-only; deliberately **not** part of `pfsense_get_api_guidance` or
any other MCP tool, for the same reason as the privilege cross-check
above. Requires network access, so it is not part of `make
quick`/`make validate`. See
[ADR-035](adr/ADR-035-pfrest-live-guidance-layer.md#schema-diff-semantic-dimension-classified-cause-agnostic)
for the real LAB-vs-upstream findings from the arc that introduced it.

## Related

- [MCP tool reference](API.md)
- [Official guidance layer architecture](OFFICIAL_GUIDANCE_LAYER.md)
- [Compatibility](COMPATIBILITY.md)
