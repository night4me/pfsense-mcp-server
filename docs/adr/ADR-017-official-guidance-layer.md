# ADR-017: Official pfSense/Netgate documentation guidance layer

- **Status:** Accepted — architecture and inert scaffolding only, at
  acceptance time not wired into any production READ tool output or any
  Tier 1 PREPARE path. Live retrieval and semantic search are explicitly
  deferred, not part of this acceptance, and remain deferred.
  **Implementation update (2026-08-22):** this layer is no longer inert —
  a single, narrowly-scoped, owner-authorized MCP guidance tool,
  `pfsense_get_official_guidance` (not a Tier 1 PREPARE path, not a
  pfSense READ capability), now consumes it in production. See
  `docs/adr/ADR-018-version-aware-guidance-resolution.md`'s own
  implementation update and `docs/THREAT_MODEL.md` TB9 for details; this
  ADR's architecture was not redesigned to enable that, only consumed as
  originally specified.
- **Date:** 2026-08-08

## Context

This project's READ tools currently return only OBSERVED STATE — typed
data read directly from the live appliance. They carry no context about
what official pfSense/Netgate documentation says about the thing being
read, and the inert Tier 1 WRITE-planning framework (`docs/tier1/`) has no
concept of consulting documentation before a future Recovery Contract is
prepared. The owner asked for research and a design for an "Official
Guidance Layer" that could eventually supply that context in both places,
under one hard constraint stated up front and treated as non-negotiable
throughout this ADR: **official documentation must never become
authorization.** A capability, endpoint, method, or mutation must remain
selectable only through this project's existing, explicit, reviewed
registries (`Capability`, `WriteEndpoints`, profiles) — never through
anything a document says, however official its source.

This ADR is architecture and design only. Per `AGENTS.md`'s Approval
boundaries and this session's own operating instructions, adding a new
public MCP tool, changing a READ tool's output schema, or wiring anything
into the Tier 1 PREPARE path all require separate explicit approval this
session does not have. What follows is accepted as the target
architecture and its inert building blocks (typed models, a deterministic
registry, isolation tests) — not as a production integration.

## The three-layer separation

This design keeps three concerns structurally distinct, matching the
framing the owner gave this task:

| Layer | What it is | Who/what already governs it |
|---|---|---|
| **Observed state** | What this MCP server reads from the live appliance right now | `PfSenseClient`, the existing 41 READ tools — unchanged by this ADR |
| **Official guidance** | Provenance-preserved excerpts of official pfSense/Netgate documentation, capability-keyed | New: this ADR's guidance layer |
| **Safety authority** | Capability gates, endpoint allow-lists, Recovery Contracts, confirmation, sealed executor, reconciliation, lab evidence, owner activation controls | Already exists (`capabilities.py`, `write_endpoints.py`, `pfsense_mcp.tier1`) — this ADR adds nothing to it and grants it no new input channel |

The guidance layer is only ever a *read-only annex* to the first layer and
a *read-only, advisory input* to material a human reviews before using the
third layer's existing confirmation mechanism. It has no write access to
any of the three layers, including its own registry at runtime — the
registry is Git-tracked, PR-reviewed data, not something the running
server can extend.

## Options considered

| Option | Strengths | Costs |
|---|---|---|
| **A — No guidance layer** | Zero new attack surface, zero new trust boundary, zero maintenance | READ recommendations and future WRITE planning stay context-free forever; does not answer what the owner actually asked for |
| **B — General web search / unrestricted retrieval, LLM-summarized** | Maximum coverage, least curation effort | Unbounded source trust, no deterministic capability→document mapping, summarization is itself a hallucination surface, no fixed corpus to security-review; explicitly the failure mode the task's own framing warns against |
| **C — Full RAG: crawl docs.netgate.com, embed into a vector database, semantic search over the whole corpus** | Best recall for free-text questions | A large new dependency stack and a poisonable index for a corpus that, capability-by-capability, is actually small (a handful of pages per capability at most); the task's own instructions explicitly warn against introducing this "merely because fashionable" |
| **D (recommended) — Deterministic `Capability → DocumentSource` registry, bundled/offline snapshot corpus, advisory-only typed references; live retrieval and semantic search both deferred as narrower, separately-activated future extensions** | Reuses the existing `Capability` enum as the join key (no new taxonomy to keep in sync); fully offline-testable; reviewable at commit time like code; smallest attack surface that still answers the actual question; matches this project's existing "protocol designed, backend/activation deferred" pattern (`ADR-011`, `ADR-015`) | Narrower recall than B/C — a capability with no curated snapshot yields no guidance, by design, not as a bug |

Recommendation: **D**. It is the option that satisfies "prefer the
simplest architecture that preserves deterministic trust boundaries" and
the explicit steer toward "capability → deterministic approved
documentation family → optional semantic retrieval within that approved
corpus" rather than unrestricted search. B and C are rejected for the
reasons the task itself gives; A is rejected because it does not address
the stated objective.

### Why bundled/offline first, not live retrieval

A live fetch from `docs.netgate.com` (even domain-allowlisted, even
TLS-strict) is a runtime network call whose response was never reviewed by
anyone at commit time. Everything this project's existing threat model
already says about A2 (untrusted upstream appliance/API response) applies
identically to a live documentation fetch — except a documentation
response is *text meant to be read and acted on*, which is a strictly
worse position than a typed JSON appliance response that goes through
Pydantic validation before anything downstream sees it. Starting with a
small, curated, PR-reviewed, content-hash-pinned offline snapshot gets the
actual value (context for common capabilities) with a fraction of the
trust-boundary cost, and is fully deterministic for testing — no
`MockTransport`-equivalent has to be invented for a v1 that makes zero
network calls of its own. Live retrieval is not rejected outright; it is
named as a distinct, future, separately-activated mode (see "Future
migration path" below), exactly as `ADR-011` named a future anti-rollback
backend without selecting or building one.

### Why capability-keyed, not free-text/semantic, in v1

Per-capability, the realistic document count is small — a handful of
pages at most (e.g., the alias documentation family, the firewall-rule
documentation family). Semantic search over a handful of items has worse
expected value than simply returning the curated set for that capability
directly: it adds a new dependency, a new failure mode (false match), and
a new thing to test, to solve a recall problem that does not exist yet at
this corpus size. If a capability's curated corpus ever grows large enough
that returning it whole becomes unhelpful, semantic retrieval **scoped
only inside that capability's already-deterministically-selected
document set** — never a general search — is the sanctioned future
extension, matching the task's own preferred shape.

### Self-challenge: is "advisory-only" actually enforceable, or just a policy statement?

A policy statement is what the task explicitly warns is not enough — this
project's own convention (`capability_adapter_contract.md`'s G1/G2: "the
type system, not just documentation, refuses it") is to make the unsafe
shape structurally awkward to write, not merely against the rules. This
design applies that same discipline:

- `GuidanceReference` (the only object type the layer ever returns) has no
  field of type capability, endpoint, method, HTTP verb, or confirmation
  token — Pydantic `extra="forbid"`, a closed field set, and a review
  checklist item requiring any addition to be independently justified.
- The guidance package has zero import of `pfsense_mcp.tier1`, zero import
  of `WriteEndpoints`/`capabilities.py`'s WRITE members, zero import of
  `RestApiClient`/`WriteApiClient`/`Transport` — enforced by a new AST
  isolation test in the same style as `tests/tier1/test_isolation.py`,
  not just a docstring promise.
- The registry itself is a Git-tracked, PR-reviewed static data file, not
  a database or runtime-writable structure — there is no code path, today
  or in the design's future extensions, by which the running server
  mutates which documents map to which capability while it runs.
- Confirmation evidence (`confirmation_authority.md`) binds to the
  contract's own canonical digest, computed from the contract's PREPARE
  fields — guidance content is never part of that digest, so a compromised
  or adversarial document cannot alter what an owner's confirmation
  signature actually authorizes even if it tried.

This makes "guidance becomes authorization" not just discouraged but
absent a code path to happen through, matching the standard this project
already holds itself to elsewhere. See the companion spec
(`docs/OFFICIAL_GUIDANCE_LAYER.md`) for the full invariant list.

### Self-challenge: does returning documentation text to the model create a prompt-injection channel?

Yes, and this ADR does not claim otherwise. A malicious or compromised
document could contain injected instructions. Three things bound the
actual risk, none of which is "trust the source because it's official":

1. **No privilege exists for injected text to escalate into.** Even once
   a first WRITE capability is eventually authorized (Phase 5+, entirely
   separate from this ADR), moving a Recovery Contract from `PREPARED` to
   `EXECUTING` requires exact-bound, externally-authenticated confirmation
   evidence (`confirmation_authority.md`) that the guidance layer has no
   path to produce, forge, or influence. An LLM "convinced" by injected
   document text still cannot invoke a tool that does not exist, still
   cannot select a capability/endpoint outside the existing allow-lists,
   and still cannot manufacture a valid Ed25519-verified confirmation
   signature. This collapses the threat to the same class already named
   in the threat model as A1 (a caller with full tool access but no
   ability to reach anything beyond what the profile's tools expose) —
   "a bad influence on the conversation," not privilege escalation.
2. **Bundled snapshots are human-reviewed before they ship.** Unlike a
   live fetch, an offline snapshot only enters the corpus through an
   ordinary Git commit and PR review — the same review discipline that
   already catches other classes of bad content in this repository.
3. **Excerpts are bounded, structured, and separated from any instruction
   channel.** `GuidanceReference.content_excerpt` is a length-bounded plain
   string field inside a typed object returned as tool-call *data*, not
   concatenated into system/instruction content — reviewers can see
   exactly what content a capability can surface, and a bound on length
   both limits how much an injected payload can carry and keeps manual
   review of the bundled corpus tractable.

Live retrieval (deferred) reintroduces A2-class risk at the level of "did
this specific fetch return what we expect," which is exactly why it is
named as a separate, narrower, future activation rather than folded into
this ADR's v1 scope.

### Self-challenge: pfSense CE vs. Plus, and version drift

The registry's `DocumentSource` records explicit edition applicability
(`CE` / `Plus` / `both`) and a version-applicability expression per entry —
this is inspectable, deterministic data, not inference. The currently
existing `SystemVersion` READ model (`src/pfsense_mcp/models/system_version.py`)
exposes `base`/`patch`/`version`/`buildtime` but **no explicit CE-vs-Plus
discriminator field** — this is a real, open gap this ADR does not resolve:
matching an observed appliance to the right edition-scoped guidance may
require either a new field derived from existing upstream data (an
investigation, not a design decision, and out of scope for this session)
or an explicit "edition unknown, showing edition-neutral guidance only"
fallback. The spec adopts the fallback as the default behavior: when
edition cannot be determined, only `both`-applicable entries are eligible,
never a guess. Version-string matching against an entry's
`version_applicability` expression follows the same fail-closed rule —
on any parse ambiguity, exclude rather than guess. A guidance/state
version mismatch never overrides or edits the guidance text; it either
excludes the reference or (spec detail) attaches a `version_mismatch` flag
for it to be displayed as clearly non-authoritative for this appliance,
never silently presented as current.

### Self-challenge: licensing and redistribution

Netgate documentation content ownership/licensing terms were not
independently verified this session — that determination is a legal
question this session is not positioned to resolve, and asserting a
specific license here would be a claim this ADR cannot back. The design
sidesteps needing that determination to proceed safely: the bundled
snapshot corpus is scoped to short, attributed excerpts plus a canonical
source URL for the reader to follow — never a full-page mirror — which
keeps the redistribution footprint small regardless of the exact license
terms, and every `DocumentSource` entry carries a `license_note` field the
registry maintainer must fill in per-source rather than assume. If a
future session or the owner determines a specific source's terms do not
even permit short-excerpt reuse, that source is removed from the registry;
nothing else in the design depends on any one source being present.

### Self-challenge: why is this not simply folded into an existing Tier 1 spec?

Because its blast radius is not Tier 1-shaped. It is meant to annotate
*today's active READ tools* (once separately approved to do so) as much as
it is meant to feed a future WRITE PREPARE step — Tier 1's own package
boundary (`pfsense_mcp.tier1`, deliberately unimported by production) is
the wrong home for something that must also be reachable, eventually, from
the READ path that already ships. It is documented as its own top-level
spec (`docs/OFFICIAL_GUIDANCE_LAYER.md`, paired with `TIER1_ARCHITECTURE.md`'s
existing sibling pattern for ADR-006) precisely so it is not mistaken for
Tier 1-gated work, and so its own activation gate (a schema-change
approval for the READ side; the existing Tier 1 gates for the WRITE side)
is stated once, correctly, in one place.

## Consequences

### Positive

- Answers the owner's stated objective (official documentation as
  provenance-preserved decision evidence) without weakening any existing
  trust boundary — verified structurally (isolation test), not just
  documented.
- Fully inert and fully offline-testable in this ADR's accepted scope: no
  network code, no new runtime dependency, no schema change to any shipped
  tool.
- Reuses the existing `Capability` enum as the join key, so there is no
  second capability taxonomy to keep in sync with `capabilities.py` as it
  grows.
- Establishes a clear, narrow activation gate for each future extension
  (READ-output wiring, live retrieval, semantic search, WRITE-PREPARE
  wiring) rather than one large "guidance layer, activated" decision —
  matching this project's existing phased-activation discipline.

### Negative

- v1's bundled-snapshot corpus is necessarily small and will go stale
  relative to live documentation; staleness is handled by explicit
  `version_applicability`/`retrieved_at` metadata and fail-closed exclusion
  on ambiguity, not by silently serving old content as current.
- A capability with no curated snapshot yields no guidance at all, which
  may read as a coverage gap rather than a deliberate boundary if not
  clearly labeled at the presentation layer (a requirement carried into
  the spec, not resolved by this ADR alone).
- Every future extension named here (READ-tool wiring, live retrieval,
  semantic search, WRITE-PREPARE wiring) is a separate activation decision
  with its own review — this is deliberate (see Positive), but it does
  mean this ADR alone does not make guidance visible to any actual user
  yet.

## Future migration path

None of the following is authorized by this ADR; each requires its own
future ADR/activation decision, exactly as `ADR-011`'s anti-rollback
backend and `ADR-016`'s lab authorization were separated from the
protocol-level ADRs that preceded them:

1. **READ-tool output wiring.** Attaching an optional `guidance` field to
   specific READ tool outputs is a public schema change and requires the
   same explicit approval any other schema change requires
   (`AGENTS.md`). This ADR's scaffolding (typed models, registry, isolation
   test) is what such a future change would build on, not what performs it.
2. **Live retrieval mode.** A capped, domain-allowlisted, hash-comparing
   HTTPS fetch, using its own isolated HTTP client entirely separate from
   `RestApiClient`/`WriteApiClient`, with the same fail-closed-on-anomaly
   posture already applied to the pfSense transport. Needs its own
   spec section (present as an explicitly deferred section in the
   companion spec) and its own decision to actually build/activate it.
3. **Semantic retrieval within an approved per-capability corpus.** Only
   if a capability's curated corpus grows large enough that whole-corpus
   return stops being useful — not before, and never as retrieval outside
   the deterministically-selected set for that capability.
4. **WRITE-PREPARE consumption.** Attaching `GuidanceReference` evidence
   to a future Recovery Contract's evidence bundle for human review during
   confirmation — additive only, never a substitute for confirmation,
   never an input to capability/endpoint selection. This is a Phase 5+
   concern and is gated by everything Phase 5 already requires
   (`IMPLEMENTATION_ROADMAP.md`), plus this ADR's own non-authorization
   invariants.

## References

- [OFFICIAL_GUIDANCE_LAYER.md](../OFFICIAL_GUIDANCE_LAYER.md) — the
  companion spec: security goals, invariants, trust boundaries, registry
  schema, failure modes, required tests, activation requirements.
- [THREAT_MODEL.md](../THREAT_MODEL.md) — TB9 and the guidance-layer
  adversarial-paths table added alongside this ADR.
- `reports-ai/reviews/ADR_017_RED_TEAM.md` — adversarial review of this
  design and the revisions it produced (external, not Git-tracked; see
  `reports-ai/README.md`).
- [capability_adapter_contract.md](../tier1/specs/capability_adapter_contract.md) —
  precedent for "the type system, not just documentation, refuses it."
- [ADR-011](ADR-011-whole-store-anti-rollback-anchor.md),
  [ADR-016](ADR-016-alias-candidate-lab-authorization.md) — precedent for
  separating protocol/architecture acceptance from backend
  selection/live-execution activation.
