# ADR-019: API Surface, Capability Discovery, and Extension Architecture

Status: **Proposed**. Architecture and vocabulary only. Nothing in this
ADR is implemented; every mechanism it describes requires its own
separate, explicit future approval before any line of code is written.
This ADR does not change the public MCP contract (still 42 READ / 0
WRITE), does not begin Phase 5, does not activate WRITE, and does not
modify `pfsense_mcp_info` or ADR-018.

**Independently red-teamed before this Proposed text was finalized**
(`reports-ai/reviews/ADR_019_RED_TEAM.md`) — findings and their
resolution are summarized in "Self-challenges" below; read the red-team
report for full failure scenarios.

## Context

This project currently exposes 42 individually typed, individually
reviewed READ tools against a pfSense REST API surface that is, in
reality, far larger — hundreds of documented operations across dozens of
domains, plus whatever a given appliance's installed packages add. As
this project's coverage grows — and eventually as a WRITE track begins —
the risk is not "too few tools." It is that convenience pressure to cover
more of that surface faster eventually produces the pattern a competitive
review performed for this ADR found in a real, shipped competitor
(`Pixelworlds/opnsense-mcp-server`,
`reports-ai/reviews/PIXELWORLDS_OPNSENSE_MCP_COMPETITIVE_REVIEW.md`):
reflection-generated tool schemas with no human curation gate, producing
a tool (`core_manage`) whose `method` parameter includes `systemReboot`
and `systemHalt` in the exact same schema, same trust tier, as a status
read.

The owner asked for an architecture investigation — not implementation —
into how this project can *understand* a much larger API/package/plugin
surface than it exposes today, without that understanding automatically
becoming exposure or authorization. The primary design invariant given:

    DISCOVERED != SUPPORTED != AVAILABLE != AUTHORIZED != EXPOSED

## Decision

Adopt a **vocabulary and evaluation**, not a build plan. Full technical
detail: `docs/API_SURFACE_ARCHITECTURE.md` (this ADR's companion spec,
mirroring `OFFICIAL_GUIDANCE_LAYER.md`'s relationship to ADR-017 and
`VERSION_AWARE_GUIDANCE.md`'s relationship to ADR-018). Summary of each
part:

1. **Endpoint Catalogue vocabulary** (companion spec Part 1): a six-state
   sequence — `DISCOVERED` → `CATALOGUED` → `TYPED` → `IMPLEMENTED` →
   `CAPABILITY-MAPPED`/`AUTHORIZED` → `MCP_EXPOSED` — formalizing the
   pipeline this project already practices informally via
   `scripts/discover_endpoints.py`/`scripts/lib/openapi.py`, which
   already fetch pfSense's own live OpenAPI 3.0 schema
   (`GET /api/v2/schema/openapi`, primary-source confirmed) for
   inspection-only discovery.
2. **No generic API escape hatch** (companion spec Part 3): a
   **permanent** invariant — no `pfsense_api_call(method, path, body)`
   or equivalent dynamic dispatch, ever. Concretely evidenced, not
   theoretical: the companion competitive review's `core_manage` finding.
3. **Feature/Package Capability vocabulary** (companion spec Part 2): a
   second, deliberately separate five-state sequence for
   *installed-package* awareness — `DISCOVERED` → `AVAILABLE` →
   `SUPPORTED` → `AUTHORIZED` → `EXPOSED` — with the invariant that
   `AVAILABLE` (observed installed, e.g. via the already-shipped
   `pfsense_get_system_packages` tool) must never, by itself, cause any
   transition toward `SUPPORTED`, `AUTHORIZED`, or `EXPOSED`.
4. **Relationship to ADR-018's `ApplianceIdentity`** (companion spec
   Part 4): a future `InstalledFeatures` model is a sibling, never a
   duplicate — `resolve_appliance_identity()` remains the one canonical
   identity assembly point.
5. **Relationship to Version-aware Official Guidance** (companion spec
   Part 5): endpoint/package information may become additional
   *evidence* alongside `GuidanceEvidence`, strictly additive, never
   authority — ADR-018's already-accepted trust boundary is unchanged.
6. **Progressive capability discovery** (companion spec Part 6):
   evaluated four options; current preference (many explicit typed
   tools) confirmed with no reason found to change at current or
   near-term scale. Dynamic/progressive discovery mechanisms rejected for
   the foreseeable future — they would reintroduce a runtime-decided
   reachable surface one layer up from where Part 3 already rejects it.
7. **Retry semantics** (companion spec Part 7): READ retry, if ever
   implemented, bounded to transport-level failures only, never a
   received response; WRITE retry never automatic by default — this
   restates, rather than changes, the existing accepted Tier 1 sealed
   executor's 4xx-`VERIFIED_FAILURE`-vs-5xx/3xx-`AMBIGUOUS`-to-
   reconciliation classification. No retry logic exists anywhere in this
   project today (confirmed by direct inspection) — a clean slate.
8. **TLS trust** (companion spec Part 8): evaluated and judged
   **already sufficient** — `src/pfsense_mcp/tls.py`'s existing
   `STRICT`/`AUTO`/`INSECURE` model already matches pfSense's own
   documented self-signed/internal-CA pattern, with `INSECURE` requiring
   explicit configuration and documented as temporary. **No dedicated
   TLS Trust Bootstrap ADR is warranted at this time.**
9. **Generated typed client** (companion spec Part 9): if ever built, a
   generator may only produce `DISCOVERED`/`CATALOGUED`-layer artifacts
   or draft response-model candidates for human review-and-commit —
   never an auto-registered MCP tool, `Capability` mapping, or
   `WriteEndpoints` entry. Deferred — no current bottleneck identified.
10. **Machine-readable coverage report** (companion spec Part 10):
    concept adopted as a natural extension of the existing discovery
    script; implementation deferred; explicitly never authorization.
11. **Permanently forbidden operations** (companion spec Part 11):
    evaluated and **rejected as a new enforcement mechanism** — the
    existing allow-list model (`SUPPORTED_CAPABILITIES_THIS_BUILD`,
    `WriteEndpoints`) already makes absence equivalent to prohibition. A
    documentation-only "never" list is recommended as a future,
    separately-authorized addition to `docs/SECURITY_MODEL.md`.

## Trust boundary: understanding is not exposure

Every part above shares one invariant, restated once here because it is
the single property this whole ADR exists to protect: **a fact this
project's tooling learns about the pfSense API surface, or about a
connected appliance's installed packages, must never by itself change
what any MCP client can call.** The only things that ever change what is
reachable are the same two mechanisms that already govern it today —
`SUPPORTED_CAPABILITIES_THIS_BUILD` and `WriteEndpoints` — both closed,
both requiring a human-authored code change and the existing review/CI
gates, neither ever mutated at runtime by a discovery result, a package
observation, or a generated artifact.

## Consequences

**Positive**: this project gains a durable vocabulary for reasoning about
its own future growth (endpoint coverage, package-awareness, eventual
WRITE track) without that vocabulary itself becoming a new attack
surface. The existing `scripts/discover_endpoints.py` tool is confirmed,
not replaced, as the correct shape for `DISCOVERED`-layer tooling. The
existing TLS design is confirmed sufficient without new work. The
existing zero-retry baseline is confirmed as the right starting point for
a READ/WRITE-differentiated policy, decided before any retry code exists
rather than retrofitted after.

**Negative / cost**: this ADR adds conceptual surface (two new closed
vocabularies) that must be kept coherent with the existing `EndpointInfo.
verified`/`Capability`/`WriteEndpoints` model as both evolve — a future
implementer must read this ADR's companion spec's explicit note that
`VERIFIED` is not redefined, only contextualized, or risk two documents
disagreeing about what the word means.

**Deliberately not resolved by this ADR**: whether any specific pfSense
package (pfBlockerNG, FRR, HAProxy, ACME, Suricata, or others) actually
exposes REST API surface worth building `SUPPORTED` capabilities for;
whether a durable `CATALOGUED` artifact should be a checked-in file or
generated on demand; the exact wording of any future "permanently
forbidden" documentation list. Each is named as a real future question,
not silently decided here.

## Self-challenges

Full adversarial pass: `reports-ai/reviews/ADR_019_RED_TEAM.md`. Findings
summarized here, folded into the Decision/Trust-boundary sections above
rather than left only in the review document:

### Self-challenge: does formalizing a catalogue create the very allow-list-confusion risk it warns against?

A checked-in `CATALOGUED` artifact, if ever built, would sit in the same
repository as `Endpoints`/`WriteEndpoints`. A future contributor
skimming the repo could plausibly mistake "this endpoint is in the
catalogue" for "this endpoint is authorized." The first draft of this
ADR mitigated this with prose alone ("a catalogue entry has no runtime
effect"); the red-team pass found that insufficient given this project's
own established pattern of backing every isolation claim with a test, not
just a docstring (`reports-ai/reviews/ADR_019_RED_TEAM.md`, Finding 1).
Fixed: companion spec Part 1 now requires any future catalogue to be
stored as non-executable data and covered by an AST-based isolation test
proving no import relationship with `Endpoints`/`WriteEndpoints`/
`Capability`/`ToolRegistry`, in the same style as the existing `tier1`/
`guidance` isolation tests. The same pattern was applied to package
discovery (companion spec Part 2, Finding 2).

### Self-challenge: is "no generic dispatch" actually a new decision, or already true?

Already true today — no dynamic-dispatch tool exists in this project's
current 42-tool surface. This ADR's contribution is making that fact a
**named, permanent, evidenced invariant** rather than an unexamined
accident of how the project happened to grow so far, specifically so a
future contributor proposing "just one flexible tool to cover the long
tail faster" has a documented decision to weigh against, with a concrete
failure example (`core_manage`) rather than an abstract objection.

### Self-challenge: does "no `method=`/`path=` parameter" actually close the dispatch risk?

No — the first draft only forbade dispatch *visible in the public
schema*. The red-team pass (Finding 3, MATERIAL) identified the subtler
failure the companion competitive review's own evidence actually
demonstrates: Pixelworlds' `core_manage` tool has a *closed-looking*
enum parameter, not an open string — the danger is not the parameter's
schema shape, it is that one tool's implementation internally selects
among multiple distinct underlying operations at call time. Fixed:
companion spec Part 3 now states the invariant as a rule about
*implementation*, not schema shape — one tool, one `Capability`, exactly
one fixed underlying client method call, with a recommended future
mechanical (AST-based) check, not a schema-level check alone.

### Self-challenge: does the `FeatureCapabilityState` model duplicate `ApplicabilityState` (ADR-018)?

No — `ApplicabilityState` (ADR-018) answers "is this *guidance document*
applicable to the observed appliance." `FeatureCapabilityState` (this
ADR) answers "is this *package* installed, and has this project decided
to build anything for it." Different subjects, different questions,
deliberately not unified into one enum — see companion spec Part 2's
explicit reasoning for keeping the two vocabularies (Part 1 and Part 2)
separate for the same reason.

## Alternatives considered

- **One unified `SurfaceState` enum** covering both endpoints and
  packages. Rejected — companion spec Part 2 explains why: an endpoint's
  existence is a property of the API surface itself, discoverable once;
  a package's installation is a property of one specific appliance,
  observed live. Conflating them would eventually force one of the two
  concepts to stretch its meaning to cover the other.
- **Adopting Pixelworlds/opnsense-mcp-server's reflection-generation
  pattern directly**, reasoning that "generate now, curate later" is
  faster. Rejected — the companion competitive review demonstrates
  concretely what "curate later" actually produces when there is no
  structural gate forcing the curation step to happen before shipping.
- **A parallel "permanently forbidden" registry** (companion spec Part
  11). Rejected as redundant enforcement over an already-closed
  allow-list; a documentation-only convention recommended instead.

## References

- `docs/API_SURFACE_ARCHITECTURE.md` — full technical detail for every
  part of this Decision.
- `reports-ai/reviews/PIXELWORLDS_OPNSENSE_MCP_COMPETITIVE_REVIEW.md` —
  primary evidentiary source.
- `reports-ai/reviews/ADR_019_RED_TEAM.md` — independent adversarial
  review of this ADR's first draft.
- `docs/adr/ADR-004-capability-profiles.md`,
  `docs/adr/ADR-007-security-first-public-schemas.md` — the existing
  capability/schema controls this ADR's invariants are grounded in.
- `docs/adr/ADR-018-version-aware-guidance-resolution.md`,
  `src/pfsense_mcp/guidance/appliance_identity.py` — integration points
  (companion spec Parts 4–5).
- `src/pfsense_mcp/endpoints.py`, `src/pfsense_mcp/write_endpoints.py`,
  `src/pfsense_mcp/capabilities.py`, `src/pfsense_mcp/tls.py`,
  `scripts/discover_endpoints.py`, `scripts/lib/openapi.py` — existing
  code this ADR's vocabulary extends conceptually without modifying.
