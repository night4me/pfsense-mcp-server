# API Surface, Capability Discovery, and Extension Architecture

Companion spec to [ADR-019](adr/ADR-019-api-surface-capability-discovery-and-extension-architecture.md),
mirroring `OFFICIAL_GUIDANCE_LAYER.md`'s relationship to ADR-017 and
`VERSION_AWARE_GUIDANCE.md`'s relationship to ADR-018. Status: **design
only, nothing here is implemented.** Every mechanism this document
describes requires its own separate, explicit future approval before any
line of code is written — this document establishes vocabulary and
boundaries, not a build plan.

## Why this document exists

pfSense's actual API surface — and its actual installed-package surface —
is far larger than the 95 tools this project currently exposes. As this
project grows toward that surface (more endpoints, eventually a WRITE
track, possibly package-aware capabilities), the risk is not "too few
tools" — it is that convenience pressure eventually produces the pattern
this document's companion competitive review
(`reports-ai/reviews/PIXELWORLDS_OPNSENSE_MCP_COMPETITIVE_REVIEW.md`)
found in a real, shipped competitor: reflection over an upstream shape,
with no human review gate, producing a tool that can call `systemReboot`
through the same schema as a status read.

The organizing principle: **understanding a large surface must never
imply exposing or authorizing it.** This document names the vocabulary
that keeps those separate, at every layer they could otherwise blur
together.

## Part 1 — Endpoint Catalogue vocabulary

Seven closed states an internal record of a pfSense API operation can be
in, listed in dependency order. Nothing later in this sequence is implied
by anything earlier in it. **`VERIFIED` is not a state in this
sequence — it is `pfsense_mcp.endpoints.EndpointInfo`'s own existing
field, reused, not redefined; see the note after the sequence.**

1. **`DISCOVERED`** — the operation appears in a fetched OpenAPI schema
   (live, via `GET /api/v2/schema/openapi`, or a saved snapshot file).
   Nothing more is claimed: not that it is safe, useful, well-documented,
   or that this project will ever touch it. Produced today, informally,
   every time a developer runs `scripts/discover_endpoints.py` — that
   script already embodies exactly this state and nothing more (its own
   module docstring: "must never classify an endpoint as verified... must
   never modify production source files... must never generate source
   code").
2. **`CATALOGUED`** — a human has recorded the `DISCOVERED` entry in a
   durable, reviewed artifact, with basic descriptive metadata (path,
   method, domain/tag, READ-vs-mutation semantics read directly off the
   HTTP verb, an `intended_use` marker of `NONE` / `CANDIDATE` /
   `IMPLEMENTED_ELSEWHERE`). Still purely descriptive and offline — a
   catalogue entry has no runtime effect and is not reachable through any
   MCP tool by virtue of existing.
3. **`TYPED`** — a reviewed Pydantic response (and, for a future mutation,
   request) model exists for the operation, matching this project's
   existing `models/` convention exactly (ADR-002).
4. **`IMPLEMENTED`** — a typed client method exists (`PfSenseClient` for
   READ, a future capability-specific path for WRITE) that calls it.
5. **`CAPABILITY-MAPPED`** — a `Capability` enum member has been assigned
   to it (existing `pfsense_mcp.capabilities.Capability`, not a new enum)
   and is present in `SUPPORTED_CAPABILITIES_THIS_BUILD`.
6. **`AUTHORIZED`** — **split from `CAPABILITY-MAPPED` during the
   ADR-019 acceptance-track review** (`reports-ai/reviews/
   ADR_019_ACCEPTANCE_REVIEW.md`), because the two states are not the
   same depth of gate for both operation kinds. For a **READ** operation,
   `CAPABILITY-MAPPED` and `AUTHORIZED` are the same event —
   `SUPPORTED_CAPABILITIES_THIS_BUILD` is READ's one and only runtime
   authorization gate, and no separate `AUTHORIZED` state exists for
   READ beyond it. For a **mutation**, they are two independently
   enforced chokepoints in different code paths: `CAPABILITY-MAPPED`
   only gates tool *registration*; `AUTHORIZED` additionally requires the
   endpoint be present in `WriteEndpoints` with `verified=True`, an
   explicit `RollbackPlan`, and `dry_run_supported=True` — the bar the
   sealed executor's send chokepoint (`WriteApiClient.send_for_tier1()`)
   actually checks at mutation time, reusing `WriteEndpoints`'s own
   already-existing bar exactly, not a new one. Collapsing these into one
   combined state in the first draft understated that a mutation
   candidate can be truthfully `CAPABILITY-MAPPED` (a capability exists
   and is supported) while still **not** `AUTHORIZED` (its specific
   endpoint is not yet allow-listed) — a real, meaningful, and currently
   real-world-relevant intermediate state: today, `Capability.
   FIREWALL_WRITE`/`ALIAS_WRITE`/`SERVICE_WRITE` already exist as enum
   members (`src/pfsense_mcp/capabilities.py`) but none is in
   `SUPPORTED_CAPABILITIES_THIS_BUILD`, and `WriteEndpoints` is
   separately, independently empty (`WriteEndpoints.active_entries() ==
   []`) — two facts a reader must be able to check independently, which a
   single combined state name would obscure.
7. **`MCP_EXPOSED`** — a tool is registered under `ToolRegistry`,
   reachable by at least one profile.

**On `VERIFIED`**: `pfsense_mcp.endpoints.EndpointInfo.verified` already
means exactly one thing — "independently, authenticated-GET-confirmed
against a real instance" — enforced today by
`tests/test_endpoints_verified.py`. That meaning does not change. A
`CATALOGUED` entry is explicitly *not required* to be `VERIFIED`;
`DISCOVERED`/`CATALOGUED` describe pre-registration, exploratory state,
while `VERIFIED` (like `TYPED`/`IMPLEMENTED`) is a property of an entry
that has been promoted into `pfsense_mcp.endpoints.Endpoints` — which
today happens to bundle `VERIFIED`+`TYPED`+`IMPLEMENTED` together at
registration time, since registration currently only happens right before
exposure. Formalizing the catalogue does not change that existing bundle;
it only names the earlier, currently-informal `DISCOVERED`/`CATALOGUED`
steps that already happen (in a developer's head, not in a durable
artifact) before an endpoint is ever promoted that far.

**The pipeline, stated as one line**: API specification → generated/
internal endpoint catalogue → human/security-reviewed capability mapping
→ typed implementation → curated MCP exposure. Every arrow is a distinct,
separately-gated step. No step may be skipped by tooling, ever — the
mechanism this pipeline exists to prevent is exactly "API specification →
automatically expose every endpoint as MCP tools," which is explicitly
and permanently rejected (ADR-019 §2 / the companion competitive review's
REJECT findings).

**Structural requirement if the catalogue is ever built (red-team
Finding 1, `reports-ai/reviews/ADR_019_RED_TEAM.md`)**: a prose statement
that "a catalogue entry has no runtime effect" is not, by itself, a
sufficient guarantee — this project's own established pattern (the
`tier1`/`guidance` isolation tests) exists precisely because prose claims
about inert code drift out of sync with reality unless a test enforces
them. Any future `CATALOGUED`-layer artifact must therefore: (a) be
stored as non-executable data (e.g. JSON/YAML), never as importable
Python class attributes that could be mistaken for `Endpoints`/
`WriteEndpoints` entries; (b) be covered by an AST-based isolation test,
in the same style as `tests/tier1/test_isolation.py`/`tests/guidance/
test_evidence_isolation.py`, proving the catalogue is not imported by
`pfsense_mcp.endpoints`, `pfsense_mcp.write_endpoints`,
`pfsense_mcp.capabilities`, or `pfsense_mcp.tools.registry`, and that
`Endpoints`/`WriteEndpoints` do not import it either. This is a
requirement on the *future* implementation, not something this document
builds — no such artifact or test exists yet.

**Catalogue regeneration must not bypass human review either (found
during the acceptance-track review, MATERIAL,
`reports-ai/reviews/ADR_019_ACCEPTANCE_REVIEW.md`)**: Part 9 below
already requires that any future *generated code* be checked in only
after a human reads the diff, never auto-committed by a build or CI
step. That requirement, as first drafted, did not explicitly extend to
the `CATALOGUED`-layer artifact itself, which is *data*, not code — the
isolation-test requirement above only proves the data has no runtime
effect, it says nothing about how the data gets updated. A CI job that
nightly re-fetches the live schema and auto-commits catalogue changes
would satisfy every requirement stated so far while still being a real
supply-chain integrity gap: a compromised or MITM'd schema fetch (already
mitigated at the TLS layer, but defense-in-depth matters here) could
silently inject a misleading entry — for example, a plausible-looking but
false `intended_use` marker — that a human reviewer later trusts at face
value specifically because "the catalogue already says this." Any future
catalogue regeneration must therefore land via an ordinary, human-
reviewed pull request, exactly like code, never auto-committed by CI —
the same discipline Part 9 already requires for generated code, now
stated for catalogue data explicitly rather than left as an inference.

**Version-drift visibility (red-team Finding 4, MINOR)**: `VERIFIED` is a
point-in-time claim, not a permanent one — pfSense upgrades can change an
already-`VERIFIED` endpoint's real behavior without this project noticing,
since nothing currently re-checks a registered endpoint after its one
verification. Not treated as blocking (existing `EndpointInfo.
min_api_version` already gives a coarse signal), but recorded as a real
gap: a future coverage report (Part 10) should treat "last verified
against which API version" as a first-class field, so drift becomes
*visible* even though this document does not propose re-verification
automation.

## Part 2 — Feature/Package Capability vocabulary

A second, deliberately separate closed vocabulary — for *installed
pfSense packages/features* (pfBlockerNG, FRR, HAProxy, ACME, Suricata, or
others; none of these names are confirmed relevant to this project's
actual API surface by this document, see "Explicitly unverified claims"
below). Kept separate from Part 1's endpoint vocabulary rather than
folded into one grand enum, because the two describe different kinds of
fact: an endpoint's existence is a property of the *API surface itself*
(discoverable once, from the schema, independent of any one appliance's
runtime state); a package's installation is a property of *one specific
connected appliance*, observed live and potentially different across two
pfSense instances running the identical API version.

`FeatureCapabilityState`, five closed members:

1. **`DISCOVERED`** — the package/feature name is known to exist in the
   pfSense package ecosystem, from primary-sourced documentation
   research. A fact about the ecosystem, not about any appliance.
2. **`AVAILABLE`** — observed, via a live READ call against the connected
   appliance (today, this project's own already-shipped
   `pfsense_get_system_packages` tool, backed by `Endpoints.
   SYSTEM_PACKAGE_READ` → `/system/packages`), to actually be installed
   on *this* appliance, at the time of that specific call. Live observed
   fact, not cached by default — any future caching of this value must
   carry the same explicit freshness/provenance discipline this
   project's competitive-review session already ADAPTed as a standing
   principle for any future inventory cache (`reports-ai/reviews/
   OPNSENSE_MCP_COMPETITIVE_REVIEW.md`), not silently reintroduced here.
3. **`SUPPORTED`** — a human has reviewed the package's own API surface
   (its own OpenAPI schema contributions, if any — some pfSense packages
   extend the REST API's schema; unconfirmed for any specific package by
   this document) and designed a capability mapping for some subset of
   its functionality. Still not built.
4. **`AUTHORIZED`** — a real `Capability` enum member exists for that
   functionality and is present in `SUPPORTED_CAPABILITIES_THIS_BUILD` —
   the exact same authorization mechanism every existing capability
   already uses, not a parallel one.
5. **`EXPOSED`** — a real MCP tool is registered under an active profile.

**The one invariant this entire model exists to enforce**: `AVAILABLE`
must never, by itself, cause any transition toward `SUPPORTED`,
`AUTHORIZED`, or `EXPOSED`. A package being installed on the connected
appliance is *evidence a human capability-design reviewer might one day
act on* — never a trigger. No code path may exist by which observing
`AVAILABLE=true` for a package changes `SUPPORTED_CAPABILITIES_THIS_BUILD`,
registers a tool, or changes what `ToolRegistry.register_all()` does for
the current process. This is the same "capability, not just endpoint
authorization" discipline ADR-004/ADR-007 already establish for every
existing tool, restated for the package dimension specifically because
that is exactly where Pixelworlds/opnsense-mcp-server's plugin-flag
mechanism (companion review, item 3) blurred it: a static/environmental
signal (their deploy-time flag; here, hypothetically, `AVAILABLE`)
directly gating tool registration, with no independent authorization step
between observation and exposure.

**Structural requirement if this is ever built (red-team Finding 2,
`reports-ai/reviews/ADR_019_RED_TEAM.md`)**: the same isolation-test
discipline Part 1 now requires for the endpoint catalogue applies here —
whenever a real `InstalledFeatures`/`FeatureCapabilityState` module is
implemented, it must ship with an isolation test proving no code path
from that module reaches `ToolRegistry.register_all()` or mutates
`SUPPORTED_CAPABILITIES_THIS_BUILD`/`WriteEndpoints` at runtime, matching
this project's existing test-backed (not merely documented) isolation
guarantees for `tier1` and `guidance`.

**Package-name dispatch is a Part 3 violation, not a separate exception
(red-team Finding 6, MINOR)**: a hypothetical future tool like
`package_status(name: str)` that internally selects behavior based on an
arbitrary package-name parameter would be exactly the "smuggled generic
dispatch" pattern Part 3's strengthened invariant (below) forbids, applied
to the package dimension instead of the endpoint dimension. Any future
package-aware tool must be capability-scoped to one specific, named
package (e.g. a dedicated `Capability` per package's status/config
surface), never a single tool accepting an arbitrary package identifier
that changes which underlying operation runs.

**Package-contributed endpoints are not an exception to either vocabulary
(found during the acceptance-track review, MATERIAL,
`reports-ai/reviews/ADR_019_ACCEPTANCE_REVIEW.md`)**: this Part opens by
noting some pfSense packages may extend the REST API's own schema with
new endpoints. The first draft described Part 1 (Endpoint Catalogue) and
this Part as fully independent, orthogonal vocabularies answering
different questions — true in general, but it left one real dependency
unaddressed: for an endpoint a *package* contributes, its actual runtime
callability genuinely depends on that package's `AVAILABLE` state, even
though the endpoint's `DISCOVERED`/`CATALOGUED`/`TYPED`/`IMPLEMENTED`/
`CAPABILITY-MAPPED`/`AUTHORIZED` progress (Part 1) is otherwise identical
to any core endpoint's. Left unstated, this is exactly the seam where a
future implementer could be tempted to reason "well, this endpoint
literally doesn't exist unless the package is installed, so it's fine to
let `AVAILABLE` gate its promotion" — precisely the invariant this
document exists to forbid, entering through the one case not explicitly
covered. **Resolution**: a package-contributed endpoint must still be
promoted through the full Endpoint Catalogue pipeline (Part 1)
independently of its package's `FeatureCapabilityState`, and `AVAILABLE`
must never gate its `CAPABILITY-MAPPED`/`AUTHORIZED`/`MCP_EXPOSED`
promotion, exactly as Part 1 already requires for any endpoint — this
note exists only to make explicit that package-contributed endpoints are
not a special case, not to grant a new exception.

**Explicitly unverified claims, not to be treated as established fact by
a future reader**: this document does not confirm that pfBlockerNG, FRR,
HAProxy, ACME, or Suricata specifically expose any REST API surface at
all, nor that any of them would be a good SUPPORTED candidate. They are
named only because the owner's originating instruction named them as
examples, explicitly caveated there as unconfirmed. Any future work in
this area starts from primary-source verification of *whichever specific
package* is actually being considered, not from this list.

### Extended design and red-team (2026-08-09, evaluated — not implemented)

Owner-directed follow-on design pass (Track 3 of an extended autonomous
mission), extending the Part 2 vocabulary above with the specific
lifecycle/persistence/staleness questions and attack scenarios it did not
yet spell out. **Live appliance access was checked and found unavailable
this session** (`pfsense_mcp.config.load_config()` fails closed with
`ConfigurationError: Missing required environment variable(s):
PFSENSE_API_URL, PFSENSE_IDENTITY, PFSENSE_API_KEY_FILE` — no
`PFSENSE_*` variables are set in this environment) — so this remains
design/red-team only, per this task's own explicit instruction: implement
the inert foundation only if a concrete feature/package is justified by
primary-source evidence, which requires exactly the live access this
session does not have.

**Lifecycle transitions — legal and illegal, stated explicitly (not
previously enumerated).** Forward progression is strictly sequential,
mirroring Part 1's Endpoint Catalogue sequence: `DISCOVERED → AVAILABLE →
SUPPORTED → AUTHORIZED → EXPOSED`, no state may be skipped. The
structurally-forbidden transitions — the ones the whole model exists to
prevent — are `AVAILABLE → AUTHORIZED` and `AVAILABLE → EXPOSED`
directly, bypassing the human-authored `SUPPORTED` design step. **Two
kinds of fact must not be confused**: `DISCOVERED`/`SUPPORTED`/
`AUTHORIZED`/`EXPOSED` are *project-level* facts — true or false for this
codebase, independent of which appliance is connected, exactly like
`Capability.ALIAS_READ` existing today doesn't depend on any specific
appliance having aliases configured. `AVAILABLE` alone is an
*appliance-level* fact, re-derived per live call. This means `EXPOSED`
does not "revert" merely because one connected appliance happens not to
have the package installed — the tool stays registered (same as any
existing tool registers regardless of whether the specific feature it
reads is configured on a given appliance); an unavailable package simply
means that tool's underlying READ call returns empty/absent data for
*this* appliance, the same failure shape every existing tool already
handles for an unconfigured service. There is therefore no "downgrade"
transition to design for `SUPPORTED`/`AUTHORIZED`/`EXPOSED` — those are
monotonic project facts, changed only by a new commit, never by runtime
observation.

**Persistence vs. runtime derivation, per state**:

| State | Persisted? | Where |
|---|---|---|
| `DISCOVERED` | Yes | A small Git-tracked, human-reviewed data artifact, same discipline as Part 1's catalogue — ecosystem research, not appliance-specific. |
| `AVAILABLE` | **No, by design** | Always a live, per-call observation via the already-shipped `pfsense_get_system_packages` tool. Restates Part 2's existing "not cached by default" text as a persistence rule, not merely a caching note. |
| `SUPPORTED` | Yes | Wherever the human-authored capability-mapping design is recorded (a reviewed doc/data file, analogous to the endpoint catalogue's `intended_use` field) — implementation detail for whoever builds this, not decided here. |
| `AUTHORIZED` | Yes, implicitly | Source code: a real `Capability` enum member present in `SUPPORTED_CAPABILITIES_THIS_BUILD` — the existing mechanism, no new persistence layer. |
| `EXPOSED` | Yes, implicitly | Source code: a tool registered in `ToolRegistry` — the existing mechanism. |

**Stale capability evidence**: because `AVAILABLE` is never cached by
default, staleness is a non-issue for the baseline design — every
observation is fresh by construction. It only becomes a live question if
a *future* caching layer is added, which Part 2's existing text already
requires to carry "the same explicit freshness/provenance discipline" as
the OPNsense-review-derived principle. Stated more concretely here: any
future cache of `AVAILABLE` must carry an explicit `observed_at`
timestamp and must never be treated as still-current at a later decision
point without a fresh re-read — the identical rule Part 4 already
requires for TOCTOU protection between discovery and a future PREPARE
phase, restated because a cache is exactly where that rule would
otherwise silently lapse.

**Package removal / appliance reconnect**: because `AVAILABLE` carries no
persisted per-appliance state, package removal is handled automatically
— the next live call simply reflects it. "Appliance reconnect" (the same
running server process being pointed at a *different* appliance
mid-session) is not a scenario this project's current architecture
supports at all: `Application`'s bootstrap loads `PfSenseConfig` once at
process start from `PFSENSE_*` environment variables (confirmed by
reading `config.py`/`application.py` directly, not assumed) — this is a
single-appliance-per-process design, unchanged by this document. This is
recorded as a scope boundary of the *current* architecture, not a gap
this design closes; it would need re-examination only if a future,
separate decision ever introduced multi-appliance or live-reconnect
support.

**Interaction with future PREPARE/WRITE**: unchanged from Part 4's
existing TOCTOU section — any future integration of `InstalledFeatures`/
capability evidence into a PREPARE phase must reuse Tier 1's existing
fingerprint-binding/authoritative-re-read discipline, not invent a
second one. Restated here only to confirm this extended pass introduces
no new mechanism for this question.

**Testability and auditability, extended**: Part 2's existing isolation-
test requirement (no code path from a future `InstalledFeatures` module
reaches `ToolRegistry.register_all()` or mutates
`SUPPORTED_CAPABILITIES_THIS_BUILD`/`WriteEndpoints`) is necessary but
not sufficient by itself — an isolation test only catches what it's
written to check. **New structural requirement, mirroring
`CatalogueEntry`'s own already-accepted design (Part 1)**: whatever type
represents an `AVAILABLE` observation (a "`PackageObservation`" or
equivalent) must have **no field capable of representing**
`SUPPORTED`/`AUTHORIZED`/`EXPOSED` — the same "cannot infer later states
even by mistake" property `CatalogueEntry` already has for Part 1's
sequence, applied to Part 2. This turns "availability can never imply
authority" from a code-review convention into something the type system
itself makes impossible to violate, not merely something a test happens
to catch. `AVAILABLE`-observation READ calls need no new audit trail —
this project's existing pattern already doesn't audit-log READ calls
(unlike Tier 1 WRITE's dedicated `write_audit.py`), and nothing about
this model changes that.

**Red-team, against all 8 explicitly named attack scenarios:**

1. **Availability→authority collapse.** The core invariant this entire
   model exists to enforce (already stated). Concrete attack: a future
   engineer writes `if package_available("frr"): register_tool(...)`
   directly inside `ToolRegistry.register_all()` or equivalent bootstrap
   code, collapsing observation into registration. **Closed by two
   independent mechanisms, not one**: the required isolation test
   (existing) plus the new structural-typing requirement above — even a
   reviewer who misses the isolation-test gap would find no
   `AVAILABLE`-shaped value that type-checks where an `AUTHORIZED`/
   `EXPOSED`-shaped one is required.
2. **Dynamic MCP surface generation.** Concrete attack: rather than
   gating registration directly on `AVAILABLE`, a tool's *schema* (e.g.
   an operations enum) is computed from which packages are installed at
   startup. This is Part 3's already-forbidden "closed-looking schema
   hiding dynamic dispatch" pattern, restated for the package dimension:
   a tool's registered existence and its complete input schema must be
   decided entirely at code-review time, never computed from any runtime
   `AVAILABLE` observation. No new mechanism needed — Part 3's existing
   invariant already covers this if stated to cover it, which it now
   explicitly does.
3. **Stale package state.** Closed by design, not by policy: `AVAILABLE`
   is never persisted by default, so there is no stale value to act on
   in the baseline model (see Persistence table above).
4. **Appliance identity changes.** Out of scope for the *current*
   single-appliance-per-process architecture (confirmed directly from
   `config.py`/`application.py`, see above) — not a gap in this design,
   a boundary of what the running process can even do today.
5. **Privilege escalation through installed packages.** Genuine, but a
   Track 4 (Phase 5 readiness) concern, not a Part 2 (READ-only
   observation) concern — the state model itself creates no new
   authority; it only gates exposure of the *existing* capability system.
   **New requirement recorded here for whenever a package is actually
   proposed as `SUPPORTED`**: a package-derived capability (e.g. a
   hypothetical FRR or HAProxy WRITE surface) must go through the exact
   same rate/blast-radius policy (`rate_policy.py`) and Recovery Contract
   discipline as any other WRITE capability — no exemption for
   package-derived ones, and no assumption that a package's own scope is
   narrower than a core firewall capability's just because it arrived via
   this vocabulary.
6. **Generated capability adapters.** Already evaluated and rejected
   project-wide (Part 9 — no code generation). Restated for this Part
   specifically: `FeatureCapabilityState`/`SUPPORTED` must never feed a
   code-generation pipeline that auto-produces a capability adapter —
   `SUPPORTED` remains a human-authored design step, full stop, not a
   template-generation trigger.
7. **Generic dispatch disguised behind closed enums.** Already covered
   ("Package-name dispatch is a Part 3 violation" above) — restated as
   fully closed: any future package-aware tool must be capability-scoped
   to exactly one named package, matching the existing "one tool → one
   `Capability` → exactly one client method" invariant. A closed-looking
   enum of package names accepted as a tool parameter and dispatched
   internally is exactly the Pixelworlds anti-pattern this whole document
   exists to prevent, regardless of how closed the enum looks.
8. **Accidental WRITE enablement.** **Confirmed closed by the existing
   two-independent-chokepoint design, not merely by this Part's own
   invariant** — traced directly, not assumed: `AUTHORIZED` still
   requires a real `Capability` enum member present in
   `SUPPORTED_CAPABILITIES_THIS_BUILD` (gates registration), and any
   WRITE-flavored capability additionally requires a *separate*
   `WriteEndpoints` allow-list entry (gates the executor's send path) —
   the same split the ADR-019 acceptance review already established
   ("same event for READ; two independent chokeponts for a mutation").
   `FeatureCapabilityState` is fully orthogonal to both gates; it cannot
   weaken either one, since it only ever feeds the human `SUPPORTED`
   design step that precedes both.

**Verdict: 0 BLOCKING.** Two explicit new requirements recorded (the
`PackageObservation`-shaped structural-typing rule; the package-derived-
capability rate/blast-radius rule) — both closures of gaps in what was
*written down*, not new mechanisms; the remaining six angles were already
closed by existing, already-accepted design, now traced and confirmed
rather than assumed. **Implementation gate**: no concrete feature/package
is justified by primary-source live-appliance evidence this session (no
live access — see above) — per this task's own explicit condition, this
track stops here, at a committed design/red-team artifact. No
`FeatureCapabilityState` code was written. Full record:
`reports-ai/reviews/ADR_019_FEATURE_CAPABILITY_STATE_EXTENDED_DESIGN_2026-08-09.md`.

## Part 3 — No generic API escape hatch (permanent invariant)

**This project's public MCP surface must never expose dynamic dispatch**
— no `pfsense_api_call(method, path, body)`, no
`firewall_manage(method=<string>)`, no equivalent. This is proposed as a
**permanent** architectural invariant, not merely "not currently done."

Why, concretely, each existing control depends on it:

- **Capability gating** (ADR-004): `Capability` is a closed `Enum`;
  `ToolRegistry` dispatches per-capability at *registration* time, once,
  deterministically. A dynamic-dispatch tool's `method` parameter is a
  runtime string chosen by the calling model, not a registration-time
  fact — no `Capability` can gate it without becoming, itself, a runtime
  string-comparison check reimplementing exactly what the closed-enum
  design exists to avoid, and reintroducing exactly the class of bug the
  companion review found concretely (`core_manage`'s `systemReboot` sits
  in the same enum, same trust tier, as `systemStatus`).
- **Endpoint allow-listing** (`Endpoints`/`WriteEndpoints`): both are
  Python class attributes — a fixed, closed, statically-analyzable set.
  A `path` parameter accepted at call time cannot be checked against a
  closed allow-list without, again, becoming a runtime lookup that is
  only as strong as its own implementation — and one dynamic-dispatch
  tool existing anywhere in the public surface is one path by which that
  runtime check, if it ever has a bug, bypasses every other tool's static
  guarantees simultaneously.
- **Typed schemas** (ADR-002, ADR-007): a `body: dict[str, Any]`-shaped
  parameter is exactly the "docstring-only, untyped" pattern this
  project's public-schema security model already treats as strictly
  weaker than a real Pydantic model (confirmed weaker, not assumed, per
  the earlier `lucamarien/opnsense-mcp-server` competitive review). No
  Pydantic validator can meaningfully constrain an arbitrary JSON body
  whose shape depends on a runtime-chosen `method`.
- **Public-contract review** (`scripts/public_contract.py`,
  `make validate`): the entire mechanism depends on each tool being one
  fixed, individually diffable, individually reviewed unit. A
  dynamic-dispatch tool collapses N distinguishable operations (which, in
  Pixelworlds' case, is up to 2000+ methods) into one contract line —
  the contract snapshot would still show "1 tool changed," even when the
  actual reachable operation set changed by hundreds of methods.
- **Recovery Contracts** (ADR-006, Tier 1): every accepted Tier 1 spec —
  `CapabilityAdapter.read_target()`'s `natural_identity` parameter,
  fingerprint binding, capability-specific `RollbackPlan` — assumes the
  *capability itself* is a compile-time-known fact about which adapter is
  running, not a runtime string a model supplies. A generic-dispatch tool
  has no fixed capability to bind a Recovery Contract to; "the contract
  scoped to whichever operation the caller decided to name this time" is
  not a coherent Recovery Contract at all.

**Strengthened invariant (red-team Finding 3, MATERIAL,
`reports-ai/reviews/ADR_019_RED_TEAM.md`)**: the paragraphs above only
forbid dispatch that is *visible in the public schema* — an arbitrary
`method`/`path`/`body` parameter. They do not, as originally drafted,
forbid the subtler failure mode Pixelworlds/opnsense-mcp-server's own
`core_manage` tool actually demonstrates: a *closed-looking* enum
parameter (which would show as a reviewable diff in
`scripts/public_contract.py`'s exact-snapshot mechanism whenever a new
value is added — a genuine, real structural protection already present
in this project, confirmed by inspection) whose underlying Python
implementation dispatches across multiple distinct pfSense operations
based on that parameter's value at call time — one tool function
internally doing the equivalent of `getattr(client, method_name)()`
rather than calling exactly one fixed client method.

The precise, closable rule this document adopts instead: **every MCP
tool must map to exactly one `Capability` and its implementation must
call exactly one fixed underlying client method — never select among
several based on a request parameter, regardless of whether that
parameter is schema-typed as an open string or a closed enum.** This is
already true, incidentally, of every one of the 42 existing tools —
**independently re-verified during the ADR-019 acceptance-track review**
(`reports-ai/reviews/ADR_019_ACCEPTANCE_REVIEW.md`) by an AST scan of
every file under `src/pfsense_mcp/tools/read/`: exactly 42 tool files
exist, exactly one (`mcp_info.py`, the local-only introspection tool,
expected) calls zero client methods, and zero files call more than one
distinct client method — this document's contribution is making it a
**named, checkable invariant** rather than an unexamined fact about how
the project happened to grow. A future mechanical check is the
recommended enforcement mechanism whenever this invariant is formalized —
not built by this document.

**The check's own description must not itself be a loophole (found
during the acceptance-track review, MATERIAL)**: a check phrased only as
"exactly one call site into `PfSenseClient`" could be satisfied by a tool
that never writes a literal `client.<method>(...)` attribute access at
all, and instead calls `getattr(client, method_name)(...)` with a
runtime-chosen `method_name` — the same acceptance review's AST scan
confirmed this pattern does not exist anywhere in
`src/pfsense_mcp/tools/`/`src/pfsense_mcp/pfsense_client.py` today, but a
check that only *counts* literal attribute call sites would not
necessarily flag it if it were ever introduced, since a `getattr`-based
dispatcher can show zero literal attribute calls while still being a
dispatcher. The recommended future mechanical check must therefore be
two rules, not one: (a) at most one literal `client.<method>(...)`
attribute-access call site per tool implementation function, **and**
(b) zero uses of `getattr`/`setattr`/`hasattr` (or any other dynamic
attribute-name construct) where the target object is the client — not a
single "count call sites" check that a dynamic-dispatch pattern could
satisfy by having an artificially low literal count.

**Recommendation, not executed by this document**: this invariant belongs
recorded durably in `docs/SECURITY_MODEL.md` and `docs/THREAT_MODEL.md`
(a new STRIDE/adversarial-paths row: "generic or smuggled API dispatch
bypassing capability/endpoint/schema controls") — flagged here, left for
a separate, explicitly authorized documentation-update turn, consistent
with this task's "do not implement any recommendation" instruction. It is
not proposed as a new ADR of its own; it is proposed as part of ADR-019.

## Part 4 — Relationship to ADR-018's `ApplianceIdentity`

`InstalledFeatures`/`FeatureCapabilityState` (Part 2) is conceptually a
**sibling** to `ApplianceIdentity`, never a duplicate or a second
assembly point. `resolve_appliance_identity()`
(`src/pfsense_mcp/guidance/appliance_identity.py`) remains the **one**
canonical source of `(edition, version)` — nothing in this document
proposes a second edition/version inference path. A future
`InstalledFeatures` snapshot would be gathered independently (via the
already-shipped `pfsense_get_system_packages` tool's output — no new
capability required to observe package presence today, since an AI client
can already call that tool and read its result), and would be combined
with `ApplianceIdentity` only as two separate fields in some future
composite context object, never merged into one inference function.

**TOCTOU between discovery and any future PREPARE (red-team Finding 9,
MATERIAL, `reports-ai/reviews/ADR_019_RED_TEAM.md`)**: package/endpoint
state observed at discovery time is not guaranteed still true by the time
a hypothetical future WRITE PREPARE phase would act on it — a package
could be uninstalled, or an endpoint's behavior could drift, between the
two. This is not a new class of problem for this project: the existing,
already-accepted Tier 1 threat model already names and mitigates exactly
this pattern for mutation targets generally ("Stale snapshot or
concurrent target update" → "Fingerprint binding and one-target
reservation" → "Immediate authoritative re-read and capability drift
projection," `docs/THREAT_MODEL.md`). Any future integration of
`InstalledFeatures`/catalogue evidence into a PREPARE phase must reuse
that exact existing re-read/fingerprint-binding discipline — evidence
gathered at discovery time must never be treated as still-current at
execute time without a fresh authoritative re-read at PREPARE time. This
document does not invent a new mechanism for this; it requires reuse of
the one that already exists.

Conceptual future composition (design-only, nothing wired):

```
ApplianceIdentity          (ADR-018, existing, one assembly point)
+ InstalledFeatures         (this document, Part 2, not yet built)
+ API Surface Catalogue     (this document, Part 1, not yet built)
+ Capability Policy         (existing: capabilities.py + profiles.py, unchanged)
+ Official Guidance         (ADR-018, existing, unchanged)
```

## Part 5 — Relationship to Version-aware Official Guidance (ADR-018)

A discovered endpoint or an `AVAILABLE` package must never itself become
guidance authority — this restates ADR-018's own trust boundary
(guidance remains evidence, never authorization) for a new input source,
it does not weaken it. The only way endpoint/feature information could
ever feed ADR-018 is as an additional, structurally separate piece of
*evidence* alongside `GuidanceEvidence`, e.g.:

```
ApplianceIdentity
+ InstalledFeature (AVAILABLE, this document)
+ Capability / use-case
+ Version-aware Official Guidance (ADR-018)
= Recommendation evidence for a human or a future PREPARE phase
```

This is strictly additive to ADR-018's already-accepted `GuidanceEvidence`
model — it does not change any accepted ADR-018 field, state, or
trust boundary, and is not proposed as an ADR-018 amendment. It is a
named future extension point, nothing more, matching how ADR-018 itself
described its own relationship to a still-hypothetical future PREPARE
wiring.

## Part 6 — Progressive capability discovery (evaluated, not adopted)

Four options, evaluated against this project's existing security
preference (explicit typed schemas, explicit capability association,
inspectable public contracts, no arbitrary method dispatch):

- **(A) Many explicit typed tools** (current design, 95 tools). Preserves
  every existing control at full strength. Cost: linear growth in tool
  count as coverage grows. **Current preference — no reason found to
  change it at 95 tools, or even considered up to roughly 80–150 by this
  document's own judgment, absent evidence MCP client-side tool-list
  ergonomics actually degrade at that scale (not tested by this
  document).**
- **(B) Module mega-tools with `method=` dispatch.** Rejected — Part 3
  above, directly evidenced by the companion competitive review.
- **(C) Progressive/dynamic capability discovery** (e.g., a tool that
  itself returns more tool definitions, or session-scoped tool-list
  changes). Rejected for the foreseeable future: MCP's dynamic
  tool-list-changed mechanism, if used for security-relevant transitions,
  would mean the *set of capabilities reachable in a session* is no
  longer a static, fully-reviewable fact at server-start — reintroducing
  exactly the "runtime-decided reachable surface" problem Part 3
  rejects, one layer up (at the tool-list level instead of the
  parameter level). Not ruled out forever, but no current justification
  exists to accept that cost.
- **(D) Tool families / other MCP-supported discovery.** Not evaluated in
  depth — no concrete MCP mechanism was identified during this
  investigation that avoids (C)'s core problem while still reducing tool
  count; revisit only if the MCP specification itself gains a
  security-reviewable, still-static-per-session grouping primitive.

**`pfsense_mcp_info` as a discovery entry point**: could eventually gain
a purely informational field summarizing catalogue coverage (e.g.
`known_endpoints_total`, `mcp_exposed_endpoints_total` — counts only,
never raw catalogue content, never a mechanism to request tool schemas
dynamically) — a future, separately-gated public-schema change, same bar
as any other `ServerIntrospection` field addition. **`pfsense_mcp_info`
is not modified by this document or by anything in this investigation.**
It must never become a security authority — its existing "structurally
non-authorizing, presence-not-secret" discipline (established at its own
design review) extends unchanged to any future coverage-summary field.

## Part 7 — Retry semantics (evaluated, not implemented)

**Current baseline, confirmed by direct code inspection, not assumed**:
no retry logic exists anywhere in this project's transport, client, or
executor layers today (`grep -rn "retry" src/pfsense_mcp/` returns
nothing). This is a clean slate, not an unexamined inherited behavior —
the invariant below can be adopted *before* any retry code is ever
written, which is strictly easier than retrofitting a READ/WRITE
distinction into existing undifferentiated retry logic later.

Proposed permanent invariant:

- **READ**: bounded retry may be acceptable, but only for specifically
  classified *transport-level* transient failures —
  `TransportConnectionError`/`TransportTimeoutError` (connection refused,
  connect/read timeout) — never for a response that was actually
  received. A received 5xx is not automatically "transient" from the
  client's perspective; the safe, general rule is retry-before-response,
  never retry-after-response, for READ. (A narrower future exception —
  retrying on a *specific, confirmed-transient* received status like 503
  with a `Retry-After` header — is not ruled out, but is not adopted now;
  it would need its own evidence that pfSense's REST API actually behaves
  that way, which this document does not have.)
- **WRITE**: no automatic retry by default, full stop. This is not a new
  decision — it already matches the accepted, implemented Tier 1 sealed
  executor's outcome classification exactly: a 4xx response is
  `VERIFIED_FAILURE` (confidently no effect, safe to report failure and
  stop); a 5xx/3xx or a transport-level failure after a mutation was
  actually sent is `AMBIGUOUS` (pfSense may have partially processed the
  request) and routes to **reconciliation**, never to automatic replay.
  A lost or ambiguous WRITE response is exactly the case Recovery
  Contracts exist to handle safely — automatic retry would silently
  reintroduce the double-mutation risk that architecture was built to
  close.
- **Future idempotent-operation exception**: only a specific,
  capability-scoped operation with *proven* idempotency (e.g. an
  idempotency-key mechanism pfSense's REST API is independently confirmed
  to support for that operation — not assumed, not general) may ever
  become eligible for WRITE retry, and that eligibility must be a
  property of that one `CapabilityAdapter`, never a transport-wide
  default.

No code changes proposed by this document. Recorded here as the
recommended shape for whenever retry logic is first written, so the
READ/WRITE distinction is designed in from the first line rather than
retrofitted.

## Part 8 — TLS trust (evaluated, current baseline judged sufficient)

**Current baseline, confirmed live against Netgate's own documentation
and this project's own code, not assumed:**

pfSense auto-generates a self-signed certificate for its GUI/API HTTPS
listener on first boot (and on any missing-certificate condition); the
documented, supported alternative for anything beyond "accept the
self-signed cert once" is an internal CA (System > Certificate
Authorities in the pfSense GUI), whose exported CA certificate a client
then trusts explicitly. This project's existing `src/pfsense_mcp/tls.py`
already implements exactly the client-side half of that documented
pattern: a closed `TLSMode` enum —

- `STRICT` (default): verify against the system CA trust store.
- `AUTO`: verify against an explicitly configured `PFSENSE_TLS_CA_FILE`
  — i.e. exactly "trust the appliance's own internal CA," the documented
  pfSense pattern above.
- `INSECURE`: `verify=False`, must be explicitly requested (never a
  default, never silently reachable), documented in the module's own
  docstring as "a temporary mode, intended to be replaced by `AUTO` once
  this instance's internal CA certificate is available to configure."

**Evaluated and judged sufficient, not a gap requiring immediate
action**: `verify=False` is never the normal solution here already — it
requires explicit configuration and is documented as temporary, which is
the responsible direction the companion competitive review found the
comparison project's own documentation get backwards (recommending
verification-disable as *the* fix, with no alternative offered). No
change to TLS behavior is proposed by this document.

**Explicitly not implemented, evaluated as genuinely open questions, not
urgent**:

- **Certificate/fingerprint pinning**: no mechanism exists beyond CA-based
  trust. Not recommended now — `AUTO` already solves the self-signed-
  appliance case via the documented pfSense mechanism (an internal CA),
  and pinning adds real operational cost (rotation coordination) without
  a concrete threat this project has identified that CA-based trust does
  not already address.
- **Secure trust bootstrap / rotation**: how `PFSENSE_TLS_CA_FILE` first
  gets onto the host running this server, and what happens when the
  appliance's internal CA rotates, are operational questions this
  document does not resolve — recorded as open, not blocking.
- **Hostname verification**: inherited from `httpx`'s standard TLS
  verification behavior (active whenever `verify` is not `False`); not
  independently re-implemented or weakened anywhere in this project's
  code — confirmed by inspection of `transport/http.py`, which passes
  `verify` straight through to `httpx.Client` with no other TLS-related
  parameter.

**Determination**: a dedicated "Secure Appliance TLS Trust Bootstrap" ADR
is **not warranted at this time** — the existing `TLSMode` design already
satisfies every invariant this investigation was asked to check
(no-insecure-by-default, custom-CA support, documented temporary-only
insecure path, no hostname-verification weakening). Revisit only if a
concrete future need (fleet-scale rotation, pinning against a specific
threat model) actually materializes — DEFER, not REJECT.

## Part 9 — Generated typed client / code generation (evaluated, not implemented)

**ADOPT the pipeline discipline this project already practices manually**
(Part 1's five-step sequence) as the permanent rule for *any* future code
generation: a generator may only ever produce artifacts at the
`DISCOVERED`/`CATALOGUED` layer (structured, offline, human-reviewed-
before-merge descriptions of the schema) or, at most, draft
low-level typed *response model* candidates for a human to review and
commit by hand (mirroring `scripts/lib/openapi.py`'s existing
`describe_response_fields()`, which already derives field name/type/
nullable/enum information from the live schema for exactly this purpose,
today, manually invoked). **A generator may never produce, or
auto-register, an MCP tool, a `Capability` mapping, or a `WriteEndpoints`
entry.** This is the concrete, general form of "REJECT: API specification
→ automatically expose every endpoint as MCP tools."

**REJECT specifically**: any build-time or install-time generation step
that produces code shipped without a human review-and-commit step in
between — this is the exact mechanism the companion competitive review
found in Pixelworlds/opnsense-mcp-server (`generate-tools.ts` → committed
`tools-generated.json`, reflection-derived, no recorded review gate).
Generated *code* (as opposed to a generated *report*, see Part 10) must
always be checked in only after a human has read the diff, exactly like
any hand-written change — never regenerated silently as part of a build
or CI step that then ships without that diff being reviewed.

**Mutation request models must never be pre-staged (red-team Finding 5,
MATERIAL, `reports-ai/reviews/ADR_019_RED_TEAM.md`)**: the paragraph above
allows draft-generating *response* model candidates for human review. It
must **not** extend to request-body models for mutation (POST/PUT/PATCH/
DELETE) operations, even as an unused "candidate" a human is meant to
review later. The concrete risk: once a plausible-looking typed request
model already exists in the tree, the marginal effort to wire it into a
tool drops, and the explicit, deliberate WRITE-authorization decision this
project's architecture requires (a `WriteEndpointInfo` entry with
`verified=True`, an explicit `RollbackPlan`, `dry_run_supported=True`)
could be approached as "just connect the already-generated model" rather
than as the standalone security decision it must remain. Any future
generation tooling must therefore be scoped to READ/response models only;
a mutation's request model must always be 100% hand-authored, written
only as part of the same review that adds its `WriteEndpoints` entry.

**Generator input handling (red-team Finding 12, MINOR)**: any future
generation tooling must remain in the same category as the existing
`scripts/lib/openapi.py` — pure, structural parsing of the fetched schema
document (dict/JSON traversal only), never dynamic execution (`eval`,
`exec`, dynamic `getattr` chains driven by schema-supplied strings) of
any value the schema itself contains. This closes the theoretical path
where a compromised or malformed OpenAPI document (e.g. via a
compromised appliance or a MITM'd fetch — already covered by this
project's existing TLS/transport controls, Part 8) could cause generation
tooling itself to do more than parse data. `scripts/lib/openapi.py`
already satisfies this property today; this is a requirement to preserve
it, not a new one to build.

**Supply-chain note**: this project's existing `scripts/lib/openapi.py`
already fetches its input (the OpenAPI schema) live from the connected
appliance or a locally saved snapshot file — never from a third-party
package's reinterpretation of the spec (unlike Pixelworlds' dependency on
`@richard-stovall/opnsense-typescript-client`'s reflected shape). Any
future generation tooling should preserve that property: generate from
pfSense's own served schema directly, not from an intermediate dependency
whose own generation/curation process this project cannot review.

**DEFER actual implementation** — no current volume of manual typing
effort has been identified as a real bottleneck; this project's 95 tools
were all hand-typed against a manually-consulted schema without apparent
strain. Revisit if/when the catalogue (Part 1, also DEFERred) reveals a
large `CATALOGUED`-but-`TYPED`-backlog that manual typing genuinely
cannot keep pace with.

## Part 10 — Machine-readable coverage report (concept ADOPTed, implementation DEFERred)

A generated, offline, read-only report cross-referencing: the live/
snapshot OpenAPI schema (`DISCOVERED`), `pfsense_mcp.endpoints.Endpoints`
(`VERIFIED`+`TYPED`+`IMPLEMENTED`, bundled as today), `pfsense_mcp.
capabilities` (`CAPABILITY-MAPPED`), and `ToolRegistry`'s actual
registration (`MCP_EXPOSED`) — a natural, additive extension of
`scripts/discover_endpoints.py`/`scripts/lib/openapi.py`, not new
infrastructure. Purpose: drift detection and transparency (e.g., "this
endpoint's schema changed shape since it was last `VERIFIED`") — **never
authorization**. A row appearing in this report changes nothing about
what is reachable; it is read-only reporting over facts that are already
independently true or false.

**Not implemented by this document.** If built, it should remain outside
`make quick`/`make validate`/`make release-check` initially (an optional
target, e.g. `make coverage-report`, matching how `make sbom` was
introduced as a standalone, non-gating target), consuming only existing
data sources, producing no side effect.

## Part 11 — Permanently forbidden operations (evaluated: existing allow-list model judged sufficient)

Considered whether the capability architecture needs a distinct
"architecturally forbidden from AI invocation" marker (for `reboot`,
`halt`/`poweroff`, firmware upgrade, arbitrary package installation,
arbitrary API dispatch), separate from "simply not currently in the
allow-list."

**Determination: a new enforcement mechanism is not warranted.** This
project's authorization model is already fully allow-list-based —
`SUPPORTED_CAPABILITIES_THIS_BUILD` and `WriteEndpoints.active_entries()`
are both closed, and absence from either is already, structurally,
equivalent to prohibition; nothing is reachable by default, ever, for any
operation not positively enumerated. A second "forbidden" registry would
be enforcement-redundant with the allow-list that already exists, and
redundant security mechanisms covering the same code path are a
maintenance liability (two lists that must independently stay correct)
without a corresponding safety gain here.

**What does have real value, evaluated as worth adopting**: a
*documentation-only* convention — recording a short, explicit "never"
list (reboot, halt/poweroff, firmware upgrade, arbitrary package
installation, arbitrary API dispatch) in `docs/SECURITY_MODEL.md`, worded
distinctly stronger than "not yet implemented," to communicate design
intent to future maintainers/reviewers/auditors — this is the same
distinction the companion competitive review found *missing* from
Pixelworlds/opnsense-mcp-server, whose `core_manage` tool includes
`systemReboot`/`systemHalt` seemingly because nothing in that project's
design ever drew this line at all, not because someone decided to include
them. **Recommended for a future, separately-authorized documentation
turn — not executed by this document**, per this task's "do not implement
any recommendation" instruction; the exact wording and list should be the
owner's own call, not unilaterally drafted into a shipped security
document by this investigation.

## References

- `reports-ai/reviews/PIXELWORLDS_OPNSENSE_MCP_COMPETITIVE_REVIEW.md` —
  primary evidentiary source for Parts 2, 3, 6, 9.
- `scripts/discover_endpoints.py`, `scripts/lib/openapi.py` — the
  already-existing informal `DISCOVERED` tooling this document formalizes
  the vocabulary for, without proposing to change either script.
- `src/pfsense_mcp/endpoints.py`, `src/pfsense_mcp/write_endpoints.py`,
  `src/pfsense_mcp/capabilities.py` — the existing production
  registries this document's vocabulary extends conceptually, without
  modifying any of them.
- `src/pfsense_mcp/tls.py`, `src/pfsense_mcp/transport/http.py` —
  Part 8's evaluated baseline.
- `docs/adr/ADR-018-version-aware-guidance-resolution.md`,
  `src/pfsense_mcp/guidance/appliance_identity.py` — Parts 4–5's
  integration points.
- pfrest/pfSense-pkg-RESTAPI documentation (`https://pfrest.org/`) —
  primary source confirming the live OpenAPI schema endpoint
  (`GET /api/v2/schema/openapi`) and the package-listing operation.
- Netgate's own documentation (`docs.netgate.com`) — primary source for
  pfSense's default self-signed certificate and internal-CA pattern
  underlying Part 8.
