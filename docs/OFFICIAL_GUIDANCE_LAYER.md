# Official guidance layer

Status: implementation-ready specification for the ADR-017-accepted scope
(deterministic registry, bundled/offline snapshot corpus, typed advisory
references, inert scaffolding). Live retrieval and semantic search are
specified here as explicitly deferred sections — designed enough not to
paint the accepted scope into a corner, not authorized to build.
Activation gate for any consumer (READ-tool output, Tier 1 PREPARE
evidence): see "Activation requirements" below. No consumer is authorized
by this document.

Related: [ADR-017](adr/ADR-017-official-guidance-layer.md) (the decision
and its rationale — read that first), [THREAT_MODEL.md](THREAT_MODEL.md)
(TB9 and the guidance-layer adversarial-paths table),
[capability_adapter_contract.md](tier1/specs/capability_adapter_contract.md)
(the sibling "type system enforces the boundary" discipline this document
follows for a different subsystem).

**Red-team note:** this document already reflects the fixes from
`reports-ai/reviews/ADR_017_RED_TEAM.md`'s adversarial review of the first
draft (seven findings: unbounded free-text fields beyond the excerpt,
an asserted-but-unenforced domain allow-list, an internally inconsistent
deferred hash-comparison design, an undefined version-matching grammar, a
missing excerpt-to-source review step, a false claim of nonexistent
precedent, and no curation bound on entries per capability). See that
review for the failure scenarios each finding describes; this document
states only the fixed result.

## Purpose

Give a capability-scoped, provenance-preserved, structurally
non-authorizing way to surface official pfSense/Netgate documentation
alongside observed appliance state — for a human or model to *read as
context*, never for the system to *act on as permission*.

## Security goals

- **G1 — Advisory by construction, not by convention.** The only object
  type this layer ever returns (`GuidanceReference`) has no field that
  could be interpreted as a capability, endpoint, HTTP method, or
  confirmation token. A caller cannot "extract" authorization from
  guidance output because no such field exists to extract, matching
  `capability_adapter_contract.md`'s G1 discipline applied to a different
  boundary.
- **G2 — Deterministic mapping, not inferred mapping.** Which documents
  are eligible for a given capability is decided by a Git-tracked,
  PR-reviewed static registry keyed on the existing `Capability` enum —
  never by runtime search, never by the model choosing what to fetch.
- **G3 — Fail closed on absence or ambiguity, never fabricate.** No
  registry entry, no snapshot content, no version/edition match, or a
  malformed snapshot each independently produce *no guidance for this
  call*, never a best-guess substitute and never a blocked underlying READ
  result.
- **G4 — Isolation from every existing safety-authority code path,**
  verified by AST test, not by docstring: zero import of
  `pfsense_mcp.tier1`, `pfsense_mcp.write_endpoints`, any WRITE
  `Capability` member's producing code, `RestApiClient`, `WriteApiClient`,
  or `Transport`.

## Invariants

- **I1.** `DocumentSource` and `GuidanceReference` are Pydantic
  `BaseModel` subclasses with `model_config = ConfigDict(extra="forbid")`,
  matching this project's existing strict-typing convention. No dict-typed
  "extra metadata" escape hatch exists anywhere in either model.
- **I2.** The registry is loaded from a Git-tracked, versioned data source
  (module-level Python literal or a bundled JSON/YAML file read at import
  time) — never from a network call, environment variable, or any
  runtime-writable location. There is no code path, in this accepted
  scope, by which the running server changes what the registry contains.
- **I3.** Every `DocumentSource` entry declares, explicitly and without a
  default:
    - `source_id` — a constrained slug, not free text:
      `^[a-z0-9][a-z0-9_-]{2,63}$`. Rejected at construction, not merely
      convention.
    - `title` — free text, bounded (I4).
    - `canonical_url` — **must match an explicit, small, Git-tracked
      hostname allow-list** (starting set: `docs.netgate.com` only),
      validated at registry-load time; import fails loudly on any
      violation, the same failure class as the content-hash self-check
      below. This is a real, enforced invariant, not a description of an
      allow-list defined elsewhere — the first draft of this document
      asserted this without actually specifying it (see
      `reports-ai/reviews/ADR_017_RED_TEAM.md` Finding 2); it is
      load-bearing precisely because `canonical_url` is the provenance
      claim a human/model reads as "official," independent of whether
      anything is ever fetched from it.
    - `pfsense_edition` — `"CE" | "Plus" | "both"`.
    - `version_applicability` — a **closed, unparsed value**, not a
      grammar/expression: either the literal string `"unversioned"`, or
      an exact pfSense version string matched verbatim against the
      observed appliance's `SystemVersion.version`. No ranges, prefixes,
      or operators in this accepted scope — a richer grammar is a
      possible, explicitly future, separately-scoped extension, not
      something to invent now under implementation pressure (the first
      draft referred to an unspecified "expression" that could "fail to
      parse" without ever defining what could be parsed; fixed per
      `ADR_017_RED_TEAM.md` Finding 4).
    - `retrieval_mode` — `"bundled_snapshot"` only, in this accepted scope
      (see Non-goals).
    - `content_hash` — a hash of the exact bundled **excerpt** text, not
      of any live page. This pins what ships; it is not, and cannot be
      used as, a live-page-integrity comparator (see TB-G3 below —
      conflating these two was Finding 3 of the red-team review).
    - `license_note` — free text, bounded (I4), filled in per source (see
      ADR-017's licensing self-challenge); never boilerplate-copied
      across entries.
- **I4.** All free-text fields carried into `GuidanceReference` output are
  independently length-bounded, not only the excerpt — a gap in the first
  draft (`ADR_017_RED_TEAM.md` Finding 1): `content_excerpt` (recommended
  2,000 characters), `title` (recommended 200 characters), `license_note`
  (recommended 500 characters). `content_excerpt` is the *exact* stored
  excerpt text, never an LLM-summarized or otherwise regenerated version
  of it — summarization is its own hallucination surface and this layer
  does not introduce one. Bounds are chosen to keep manual review of the
  bundled corpus tractable and to limit how much an eventually-reviewed-
  but-still-adversarial entry could carry in any one field; revisit only
  with a documented reason, not silently.
- **I5.** Capability→registry lookup is a pure function of
  `(Capability, observed_pfsense_version_or_None, observed_edition_or_None)`
  with no hidden state, no wall-clock dependency beyond an explicit
  `retrieved_at`/`snapshot_version` field carried on the result (not used
  to change *which* entries match, only recorded as provenance) — fully
  deterministic and reproducible in a test, matching
  `capability_adapter_contract.md`'s I3 determinism discipline for a
  different function family.
- **I6 (original text, accepted scope through v0.3.1).** On any of: no
  registry entry for the capability, edition unknown and no
  `both`-applicable entry exists, or the observed version does not
  exactly equal a non-`"unversioned"` `version_applicability` value — the
  lookup returns an empty result. It never raises past the guidance
  layer's own boundary into whatever called it (a guidance-layer failure
  must never fail an otherwise-healthy READ call), and it never returns a
  lower-confidence guess instead of nothing.

  **I6 revision note (2026-08-09, ADR-018 bridge implementation slice
  `3628ce3`).** The exclude-on-ambiguity half of I6 above has been
  superseded by an owner-authorized policy change — the "exclude vs.
  exclude-with-state" question ADR-018 Step 2's Acceptance record already
  flagged as needing its own separate approval, which this slice records
  as granted. Current, accurate behavior: no registry entry for the
  capability at all still returns an empty result
  (`NO_OFFICIAL_GUIDANCE_FOUND`), unchanged. For a capability *with* a
  registered entry, every registered entry is now returned — none is
  silently dropped for a version/edition mismatch — each carrying its own
  deterministically-computed `ApplicabilityState`
  (`APPLICABLE`/`PARTIALLY_APPLICABLE`/`VERSION_UNCONFIRMED`/
  `EDITION_MISMATCH`/`STALE`) via `applicability.compute_entry_applicability()`,
  independently re-capped by the entry's own `EvidenceLevel`
  (`cap_applicability_by_evidence_level()`) so a favorable state can never
  be reached by inference or omission alone. The still-true half of the
  original guarantee is unchanged: it never raises past the guidance
  layer's own boundary, and `APPLICABLE`/`PARTIALLY_APPLICABLE` are only
  ever reached through explicit, matching evidence — never returned as a
  guess. See `src/pfsense_mcp/guidance/registry.py`'s own module and
  `lookup_guidance()` docstrings for the authoritative current behavior;
  this note summarizes it for the spec record. Still entirely unwired —
  no MCP tool, no READ tool, no Tier 1 PREPARE consumer calls
  `lookup_guidance()` in production.

## Trust boundaries

### TB-G1 — Registry authorship to running process

The registry is authored and reviewed exactly like source code (Git
commit, PR review). The running process only ever reads it; it is not a
database, not runtime-appendable, and not derived from any request-time
input. This is the single strongest guarantee this layer makes: the set
of documents any capability can ever surface is fixed at release time, not
request time.

### TB-G2 — Bundled snapshot content to `GuidanceReference` output

Bundled excerpt text is untrusted **content** even though its **source**
(Netgate's official documentation) is comparatively trusted relative to
arbitrary web content — the task framing that motivated this ADR draws
this distinction explicitly, and this design treats it as load-bearing.
Excerpt text flows into a bounded, typed field and nowhere else — never
into a system/instruction-bearing prompt, never interpolated into a
generated request of any kind, never used to select a registry entry for
a *different* capability than the one that was actually looked up.

### TB-G3 (deferred, specified for forward-compatibility only) — Live fetch to bundled-equivalent output

Not active in this accepted scope. If ever built, a live-retrieval fetch
must be A2-class untrusted upstream response handling: HTTPS-only, strict
TLS validation (no `insecure` equivalent), the same hostname allow-list
`canonical_url` is already validated against (no wildcard subdomains), no
redirect-following to a non-allow-listed host, and a hard response-size
bound.

**Explicitly unresolved, flagged rather than quietly implied solved** (red
team Finding 3): `content_hash` (I3) pins the bundled **excerpt**, not any
live page — a hash of a short curated quotation and a hash of a fetched
full page can never be equal, even for an honest, completely unchanged
source. The first draft of this section described comparing a live
fetch's hash "against the registry's last-known-pinned hash for that
source" as if these were the same value; they are not, and a design that
did this would fail on every live fetch regardless of tampering. Building
TB-G3 for real requires its own, separately-pinned full-page or
full-section hash concept distinct from `content_hash` — or a
substring-presence check of the excerpt against the fetched page instead
of hash equality — and that choice is not made here. Whichever future
session designs TB-G3 for real must resolve this before writing any
fetch code, not treat the first draft's wording as already having
resolved it. Until then, an unpinned or not-yet-comparable live fetch
must produce a visibly lower-trust result (`trust_label` field — see
Interfaces), never silent equal trust with a pinned bundled snapshot.

### TB-G4 — Guidance layer to safety authority

Identical boundary to `sealed_executor.md`'s executor/adapter boundary,
restated for this layer: the guidance layer has no import path to
`pfsense_mcp.tier1`, `WriteEndpoints`, or any WRITE-capable transport.
Confirmation evidence signs the contract's own canonical digest, which
never includes guidance content — a compromised or stale document cannot
alter what an owner's confirmation actually authorizes, because there is
no code path from "guidance content" to "digest that gets signed."

## State ownership

The guidance layer owns no mutable state. The registry is immutable,
process-lifetime, load-once data. `GuidanceReference` objects are
freshly-constructed, immutable return values, never cached mutable state
shared across calls beyond ordinary Python object identity. There is no
store, no database, no file the running process writes.

## Interfaces

```python
# Illustrative shape for the accepted (bundled-snapshot-only) scope.
# Mirrors capability_adapter_contract.md's convention of showing the
# shape, not asserting this is final implementation code.

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from pfsense_mcp.capabilities import Capability

_SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
_ALLOWED_DOC_HOSTS = frozenset({"docs.netgate.com"})  # I3; extend only via reviewed diff


class Edition(str, Enum):
    CE = "CE"
    PLUS = "Plus"
    BOTH = "both"


class RetrievalMode(str, Enum):
    BUNDLED_SNAPSHOT = "bundled_snapshot"
    # LIVE_FETCH intentionally not a member yet -- TB-G3 is deferred.


class DocumentSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(pattern=_SOURCE_ID_PATTERN.pattern)
    title: str = Field(max_length=200)
    canonical_url: str  # host checked against _ALLOWED_DOC_HOSTS by a model validator, not by pattern alone
    pfsense_edition: Edition
    version_applicability: str  # "unversioned" or an exact SystemVersion.version string only -- I3
    retrieval_mode: RetrievalMode
    content_excerpt: str = Field(max_length=2000)  # exact stored text, never regenerated -- I4
    content_hash: str  # sha256 of content_excerpt only -- never a live-page comparator, see TB-G3
    license_note: str = Field(max_length=500)


class GuidanceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Capability member name (str), not the enum object: this design's own
    # choice for a JSON-serializable, MCP-schema-safe representation -- not
    # an existing convention this codebase already has (Capability has
    # never appeared in any public schema before this design; see
    # ADR_017_RED_TEAM.md Finding 6).
    capability: str
    source_id: str = Field(pattern=_SOURCE_ID_PATTERN.pattern)
    title: str = Field(max_length=200)
    canonical_url: str
    content_excerpt: str = Field(max_length=2000)
    content_hash: str
    pfsense_edition: Edition
    trust_label: str  # "pinned-snapshot" in this accepted scope; reserved values for TB-G3
    version_mismatch: bool
    snapshot_version: str  # registry release identifier, not a live retrieval timestamp in this scope


def lookup_guidance(
    capability: Capability,
    observed_version: str | None,
    observed_edition: Edition | None,
) -> tuple[GuidanceReference, ...]:
    """Pure, deterministic (I5). Returns () on any absence/ambiguity (I6)."""
```

`lookup_guidance()` is the only public entry point. It is never given a
transport, a client, or any object capable of network I/O — the accepted
scope has no network I/O to give it.

## Failure modes

| Failure | Detection | Result | Automatic retry |
|---|---|---|---|
| No registry entry for the capability | Lookup finds zero matches | Empty tuple; underlying call proceeds unaffected | N/A |
| Edition unknown, no `both`-applicable entry | Explicit `None`-edition check | Empty tuple | N/A |
| `version_applicability` is `"unversioned"` or does not exactly match the observed version string | Explicit closed-set comparison, not a parser (I3) | Empty tuple on non-match; the `"unversioned"` case always matches | N/A |
| A registry entry fails any load-time validation — content-hash mismatch, `canonical_url` host outside the allow-list, `source_id` pattern violation, or a free-text field over its bound | Load-time integrity/schema checks (I3/I4) | Import fails loudly (a build/deploy defect to fix before release, not a runtime condition to hide or silently drop) | N/A |
| A future `GuidanceReference` consumer treats `content_excerpt` as instruction rather than data | Not detectable by this layer at runtime — this is exactly why TB-G2 states the rule at the type/consumption boundary, not merely relies on it being followed | Residual risk, same class as any other tool-output-content risk (see `THREAT_MODEL.md` A1/A2) | N/A |

## Recovery behavior

None required. The layer holds no durable state, performs no mutation,
and every failure mode above resolves to "return no guidance," which is
never itself an error condition for the caller.

## Non-goals

- Does not select, gate, or influence which capability, endpoint, or HTTP
  method any tool or future adapter uses — that remains exclusively
  `capabilities.py`/`WriteEndpoints`/profile-driven, per ADR-017.
- Does not implement live retrieval, semantic search/embeddings, or a
  vector database in this accepted scope — see ADR-017's "Future migration
  path" for why each is deferred rather than rejected outright.
- Does not summarize, translate, or otherwise regenerate excerpt text —
  excerpts are stored and returned verbatim (I4).
- Does not wire into any READ tool's output schema or any Tier 1 PREPARE
  path — both are separate, future, explicitly-approved activations (see
  "Activation requirements").
- Does not attempt to resolve pfSense/Netgate documentation licensing
  terms definitively — see ADR-017's licensing self-challenge for the
  design choice that sidesteps needing that resolution to proceed safely.

## Required tests

- **Isolation test** (new, `tests/guidance/test_isolation.py`-equivalent,
  same AST-scan pattern as `tests/tier1/test_isolation.py`): the guidance
  package imports none of `pfsense_mcp.tier1`, `pfsense_mcp.write_endpoints`,
  `pfsense_mcp.rest_api_client`, `pfsense_mcp.write_api_client`,
  `pfsense_mcp.transport`; and no production module outside the guidance
  package imports it either (symmetric to Tier 1's isolation check —
  this layer is exercised by its own tests only until a future ADR
  authorizes a consumer).
- **Registry integrity test:** every `DocumentSource.content_hash` matches
  a freshly computed hash of its own `content_excerpt` at test time (the
  same check the module performs at load time, re-asserted so a test
  failure is attributable and CI-visible, not just an import-time crash).
- **Deterministic-mapping tests:** for a representative capability with a
  registered entry, `lookup_guidance()` called twice with identical inputs
  returns equal results (I5); an unregistered capability returns `()`;
  edition `None` with only edition-specific entries registered returns
  `()`; a version string that does not exactly equal a non-`"unversioned"`
  `version_applicability` value returns `()` (G3/I6, each as its own
  explicit test case, not inferred from one happy-path test).
- **Excerpt-bound test:** constructing a `DocumentSource`/`GuidanceReference`
  with `content_excerpt`, `title`, or `license_note` over its I4 bound is a
  Pydantic validation failure, not silent truncation — each field tested
  independently, not just `content_excerpt`.
- **Schema-closure test:** constructing either model with an undeclared
  field raises (I1), matching the existing convention of testing
  `extra="forbid"` directly rather than assuming it from the config line.
- **Load-time validation tests:** a `canonical_url` host outside the
  allow-list and a `source_id` violating its pattern each independently
  fail at construction (I3) — added per `ADR_017_RED_TEAM.md` Finding 2.

## Activation requirements

None of the following were granted by this document or by ADR-017's
original acceptance. Each was, and remains, its own separate decision:

- [x] **A new, narrowly-scoped MCP tool exposing guidance directly**
      (`pfsense_get_official_guidance(capability)`, not "READ-tool output
      wiring" — no existing READ tool's schema was changed) — owner-
      authorized 2026-08-22, implemented per
      `reports-ai/GUIDANCE_MCP_EXPOSURE_QUALIFICATION_2026-08-22.md`'s
      Candidate A recommendation and
      `reports-ai/OFFICIAL_GUIDANCE_TOOL_IMPLEMENTATION_2026-08-22.md`.
      Appliance identity for applicability resolution is tool-resolved
      (via the same already-authenticated client every READ tool uses),
      never model-supplied; fails closed to "unknown" on any resolution
      failure. Accounted for separately from the 95 pfSense READ tools in
      the public contract, never blended into that count.
- [ ] **Existing READ-tool output-schema wiring** (attaching guidance to
      an existing tool's own response) — still not done, still requires
      the same explicit approval any public MCP tool output-schema change
      requires (`AGENTS.md`); the tool added above is a new, separate
      tool, not a change to any existing one.
- [ ] **Live retrieval (TB-G3)** — requires its own ADR selecting the
      allow-listed domain(s), size bound, and hash-pinning/trust-labeling
      behavior in full, plus explicit activation approval (matching
      `ADR-011`'s deferred-backend pattern).
- [ ] **Semantic retrieval** — requires evidence that a specific
      capability's curated corpus has grown large enough that whole-corpus
      return is no longer useful, plus its own scoping decision restricted
      to retrieval *within* that capability's already-approved document
      set only.
- [ ] **Tier 1 PREPARE evidence wiring** — requires Phase 5 or later's
      existing gates (`IMPLEMENTATION_ROADMAP.md`) to be satisfied for
      whatever capability is involved, plus confirmation that the wiring
      is additive-evidence-only and does not touch confirmation-digest
      computation, capability selection, or endpoint selection.

## Implementation checklist

- [ ] Define `DocumentSource`/`GuidanceReference`/`Edition`/`RetrievalMode`
      with `extra="forbid"` on both `BaseModel` subclasses.
- [ ] Bound every free-text field (`content_excerpt`, `title`,
      `license_note`), not only the excerpt (I4).
- [ ] Constrain `source_id` to its slug pattern and `canonical_url` to the
      named hostname allow-list, both enforced at construction, not only
      documented (I3).
- [ ] Build the registry as a Git-tracked, versioned data source (module
      literal or bundled file) with a load-time content-hash self-check.
- [ ] Implement `lookup_guidance()` as a pure function per I5; no client,
      transport, or I/O object in its signature.
- [ ] Add the isolation test before or alongside the first registry entry,
      not after — matching this project's existing practice of proving a
      boundary before there is any code that could tempt someone to cross
      it.

## Review checklist

- [ ] Confirm every `DocumentSource`/`GuidanceReference` field is one of
      the ones listed in Interfaces — an addition needs its own
      justification, not a rubber stamp (G1).
- [ ] Confirm the registry contains no field or value that could be read
      as a capability/endpoint/method/confirmation token (G1).
- [ ] Confirm `content_excerpt` is the actual bundled text, not a
      generated summary (I4).
- [ ] Confirm the excerpt text is verifiably present, at review time, on
      the page `canonical_url` actually points to — a real, correctly
      allow-listed URL paired with fabricated or altered excerpt text
      must fail review, not just an implausible URL (added per
      `ADR_017_RED_TEAM.md` Finding 5; do not approve on URL plausibility
      alone).
- [ ] Confirm `license_note` is filled in per source, not copy-pasted
      boilerplate (ADR-017 licensing self-challenge).
- [ ] Confirm the capability's total registered entry count stays small
      (no more than approximately three `DocumentSource` entries per
      `Capability`); a fourth is a signal to curate (retire a stale entry)
      or to revisit the deferred semantic-retrieval extension, not to
      silently accumulate (added per `ADR_017_RED_TEAM.md` Finding 7).
- [ ] Confirm the isolation test's forbidden-import list matches this
      document's Trust boundaries section exactly, not a subset of it.

## Security checklist

- [ ] Confirm zero network code exists anywhere in the accepted scope —
      grep for `socket`, `requests`, `httpx`, `urllib` imports in the
      guidance package and expect none.
- [ ] Confirm the registry is not readable-and-writable by the running
      process from any request-time input (I2).
- [ ] Confirm `lookup_guidance()` cannot raise past its own boundary for
      any of the documented absence/ambiguity cases (I6) — test each one
      explicitly, don't assume from the happy path.
- [ ] Confirm no test or fixture accidentally exercises a live network
      call to `docs.netgate.com` or any other host.
- [ ] Confirm every `DocumentSource.canonical_url` host is checked against
      the allow-list at construction time, not merely documented as a
      requirement (I3; the first draft of this document described this
      allow-list without actually enforcing it — `ADR_017_RED_TEAM.md`
      Finding 2).

## Test checklist

- [ ] Isolation test (both directions: guidance package's own forbidden
      imports, and no production module importing the guidance package).
- [ ] Registry integrity (hash) test.
- [ ] Deterministic-mapping tests (happy path, unregistered capability,
      unknown edition, non-matching version — each its own case).
- [ ] Excerpt-bound and schema-closure tests.
