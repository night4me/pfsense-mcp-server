# Tools and guidance: what you get, and where it comes from

This page explains what the two different kinds of tool this server
registers actually are, and — for the documentation-guidance tool
specifically — exactly whose words you're reading when you use it.

## Public tool counts (current, source-derived)

- **95 pfSense READ tools** — each one calls exactly one fixed pfREST
  `GET` endpoint through one statically checked client method, gated by
  a named `Capability`. See [the full reference](API.md) and
  [Compatibility](COMPATIBILITY.md) for per-tool detail.
- **1 official-guidance tool** (`pfsense_get_official_guidance`) —
  documentation lookup, not a pfSense appliance call. Counted
  separately, never blended into the 95.
- **0 registered WRITE tools** in the default profile. Exactly one
  WRITE-capable tool exists in this codebase at all
  (`set_firewall_alias_description_v1`) and is reachable only under an
  explicit `write_protected` opt-in — see
  [the security model](SECURITY_MODEL.md).

These counts are enforced mechanically, not just documented: a snapshot
test fails CI if the registered tool set drifts from the reviewed,
approved contract.

## READ tools vs. the guidance tool

A **READ tool** (`pfsense_get_*`) tells you what is true about *your
specific, connected appliance right now* — configuration, live status,
or derived state, depending on the tool (see the per-tool notes in
[the API reference](API.md)).

The **guidance tool** (`pfsense_get_official_guidance`) tells you
something different: what a general pfSense *feature* is and how it
works, independent of any specific appliance. It never reflects your
appliance's actual configuration — for that, use the matching READ tool
instead. Every result it returns carries a fixed disclaimer field
saying exactly this, structurally, not just in prose.

## Where the guidance tool's content comes from

Every entry in the guidance registry is **project-authored** — written
and reviewed by this project, describing what a Netgate-documented
pfSense feature generally is, never a quotation of Netgate's own text.
Each entry cites its official source page
(`docs.netgate.com`) for provenance, and carries a computed
applicability state (does this appear to match your appliance's
observed edition/version, or not) — resolved automatically from the
appliance's own reported version, never something you supply.

**Current coverage: 28 of 86 distinct READ capabilities** have a
registered guidance entry today. This is an honest, unpadded number,
not a target dressed up as an achievement — a capability with no
registered entry simply returns an empty result (`NO_OFFICIAL_GUIDANCE_FOUND`),
never a fabricated answer.

### Why isn't the pfSense REST API itself covered here?

The pfSense REST API package (`pfrest`/`pfSense-pkg-RESTAPI`) that this
entire project is built on is **not** Netgate product documentation —
it's a separate, community-maintained package, documented at
[pfrest.org](https://pfrest.org/), not `docs.netgate.com`. This
project's guidance registry deliberately only cites `docs.netgate.com`
(enforced by an explicit host allow-list, not left to convention), so
REST-API-specific questions (what does this endpoint expect, what does
this field mean, what privilege does it require) are a genuine,
separate gap today — not something `pfsense_get_official_guidance` was
ever designed to answer.

A live-fetch design for exactly that gap — a bounded, cached,
structured lookup against pfrest.org's own public API reference — has
been researched and designed (see
`reports-ai/POST_V0_8_GUIDANCE_AND_DOCS_ARC_RESEARCH_2026-08-27.md` for
the full design and security review) but is **not implemented or
exposed as an MCP tool yet**. If/when it ships, it would be a distinct,
separately-labeled provenance source — never blended with, or mistaken
for, official Netgate guidance.

## Provenance, plainly

| Label | What it means | Where it appears today |
|---|---|---|
| **Official Netgate documentation** | Netgate's own published pfSense docs, cited by URL | Source citation only — the guidance tool's own text is project-authored, never a quotation |
| **Project-authored** | Written by this project, reviewed like source code | Every `pfsense_get_official_guidance` summary; every tool-level interpretation note in this project's own internal guidance foundation |
| **pfREST upstream reference** (designed, not yet public) | The REST API package's own API documentation (`pfrest.org`) | Not yet exposed via any MCP tool — see above |
| **Live appliance state** | What your specific pfSense appliance actually reports right now | Every `pfsense_get_*` READ tool result |

Documentation guidance — from any of the first three sources above — is
always advisory. It is never observed live state, and it can never
authorize, select, or influence any action this server takes. See
[the security model](SECURITY_MODEL.md) and
[ADR-017](adr/ADR-017-official-guidance-layer.md)/[ADR-018](adr/ADR-018-version-aware-guidance-resolution.md)
for the full architecture and the tests that prove this boundary holds.

## Related

- [MCP tool reference](API.md)
- [Official guidance layer architecture](OFFICIAL_GUIDANCE_LAYER.md)
- [Compatibility](COMPATIBILITY.md)
