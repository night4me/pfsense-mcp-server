# ADR-018: Version-aware Official Guidance resolution

Status: **Accepted** (2026-08-09) — architecture and trust boundaries
only. See "Acceptance record" below for exactly what acceptance grants
and what it explicitly does not. Nothing in this ADR is implemented yet;
each piece still requires its own separate, explicit future approval
before any line of code is written, per ADR-017's own "Live retrieval
(TB-G3)" Activation requirement, which named exactly this document as a
prerequisite.

**Revised after independent adversarial review**
(`reports-ai/reviews/ADR_018_RED_TEAM.md`): 2 BLOCKING and 6 MATERIAL
findings, all fixed in this text and in `docs/VERSION_AWARE_GUIDANCE.md`.
The two BLOCKING findings were real defects in the first draft, not
review pedantry — reusing `Edition` for observed-appliance state was a
genuine type-safety gap (§1 below), and the original TB-G3 text
overclaimed what substring-presence verification actually proves (§3
below). Read the red-team report for full failure scenarios; this text
reflects the fixed design, not the original one.

## Context

ADR-017 accepted a deterministic, capability-keyed, bundled-snapshot-only
guidance registry. Its own "Self-challenge: pfSense CE vs. Plus, and
version drift" section left one investigation explicitly open: whether an
edition (CE vs. Plus) discriminator can be derived from existing upstream
data, or whether "edition unknown" must remain the permanent default. Its
TB-G3 trust-boundary section specified live retrieval only "for
forward-compatibility," left one design question explicitly unresolved
(`content_hash` pins an excerpt, not a live page — comparing the two is
not meaningful as originally worded), and required its own ADR before any
implementation.

The owner has now set a durable objective for this project: an AI client
should never give pfSense-specific operational advice — and especially
should never prepare a future WRITE — based on generic or `/latest/`
documentation alone, when the actual appliance's edition and version may
make that documentation inapplicable, partially applicable, or actively
wrong. This ADR is that resolution: it extends ADR-017's registry model
with edition/version applicability *reasoning* (not just filtering),
evaluates live retrieval as TB-G3 requires, and resolves the hash-pinning
question TB-G3 left open. It does not implement any of it.

## Decision

Extend ADR-017's model in four parts, each independently gated:

1. **Appliance identity resolution** — a pure function, not a new READ
   tool or network call, deriving `(edition, version)` from
   `SystemVersion.base`, the same field an existing READ tool
   (`pfsense_get_system_version`) already returns.
2. **A closed `ApplicabilityState` enum** replacing the reserved-but-inert
   `version_mismatch: bool` field, plus a new `ReleaseOverlay` registry
   concept for version-specific errata/caveats.
3. **A resolved live-retrieval design (TB-G3)**, answering the question
   ADR-017 explicitly left open, but **not activated** — activation
   remains its own future decision exactly as ADR-017 already required.
4. **A `GuidanceEvidence` composition model** describing how an AI client
   (or, later, a Tier 1 PREPARE phase) combines observed appliance state
   with resolved guidance — conceptual only, wired into nothing.

Full technical detail: `docs/VERSION_AWARE_GUIDANCE.md` (this ADR's
companion spec, mirroring `OFFICIAL_GUIDANCE_LAYER.md`'s relationship to
ADR-017).

### 1. Appliance identity: resolving ADR-017's open self-challenge

**Research finding, not assumption**: Netgate's own documentation
(`docs.netgate.com/pfsense/en/latest/releases/versions.html`) states the
two editions deliberately use different version-numbering *schemes*
"to make it easier to distinguish between them" — pfSense CE uses
`<major>.<minor>.<patch>` (major has always been `1` or `2`, e.g.
`2.7.2`, `2.8.1`); pfSense Plus uses `<year>.<month>.<patch>` (e.g.
`24.11`, `25.07`, `26.03`). The pfSense REST API package's own
`SystemVersion.base` field docstring independently confirms this exact
distinction for the `base` field specifically — the same field
`pfsense_get_system_version` (this project's existing tool) already
returns.

This is not a fragile heuristic — it is Netgate's own documented,
intentional design, confirmed independently at both the documentation
level and the API-field level, and re-confirmed a second time
independently during red-team review (first Plus version is exactly
`21.02`, February 2021; CE's major component has been exclusively `1`
or `2` across its entire documented history, `1.2.x` through the current
`2.9.x`). A CE major version below 10 and a Plus "year" component of 21
or higher cannot collide under the current scheme. A value outside both
ranges (never observed to date) resolves to edition **unknown**, not a
guess — matching ADR-017's existing fail-closed default.

**No new network call.** `SystemVersion.base` is already fetched by the
existing `pfsense_get_system_version` READ tool. The inference function
operates purely on that already-available string.

**Fixed after red-team review (Finding 1, BLOCKING)**: the first draft
represented "observed appliance edition" using ADR-017's existing
`Edition` enum (`CE`/`PLUS`/`BOTH`) with `None` standing for "unknown."
That enum's `BOTH` member is meaningful for *document applicability* (a
document can genuinely apply to both editions) but is never meaningful
for an *observed appliance* — a real appliance is always exactly one
edition or unknown, never both. Nothing prevented a future caller from
passing `Edition.BOTH` as an observed value, which means nothing for a
real appliance. Fixed: a new, separate, closed `ObservedEdition` enum —
`KNOWN_CE` / `KNOWN_PLUS` / `UNKNOWN` — is used exclusively for observed
appliance state; `Edition` continues to be used exclusively for
`DocumentSource`/`ReleaseOverlay` applicability, where `BOTH` remains
meaningful. `infer_edition_from_version_base()` returns `ObservedEdition`,
never `Edition | None`. Full shape in `docs/VERSION_AWARE_GUIDANCE.md`.

**Fixed after red-team review (Finding 9, MINOR)**: the numeric bounds
(`_CE_MAX_MAJOR = 9`, `_PLUS_MIN_YEAR = 21`) are correct against the
primary source (re-verified twice, independently) but are bare constants
a future one-line diff could widen without re-checking that source. The
implementing session must cite the specific primary-source page/date
re-verified against in the same commit that ever changes either bound —
specified as an explicit requirement in `docs/VERSION_AWARE_GUIDANCE.md`,
not left to reviewer diligence alone.

**Config revision**: no reliable, generally-available config-revision
field exists in the currently wrapped pfSense REST API surface (checked
directly — `pfsense_client.py`'s full endpoint set has no
`config_history`/`revision` method, and pfSense's own native
Configuration History feature is GUI-only with no confirmed API
exposure, the same finding the OPNsense competitive review already
recorded independently). Not pursued further in this ADR; noted as a
possible future READ addition if pfSense's API surface ever exposes one,
out of scope here.

### 2. `ApplicabilityState`: fulfilling ADR-017's own reserved field

ADR-017's `GuidanceReference.version_mismatch: bool` was explicitly
documented as "always False in this accepted scope... reserved for a
possible future policy that includes-with-caveat instead of excludes."
This ADR is that future policy.

```
APPLICABLE            — edition matches (or BOTH), version exactly
                         matches (or UNVERSIONED), no overlay contradicts it
PARTIALLY_APPLICABLE  — edition and base doc apply, but a registered
                         ReleaseOverlay for the observed version carries
                         a caveat (behavior differs in some documented way)
VERSION_UNCONFIRMED    — edition matches; observed_version is None, or
                         does not exactly match a version-specific entry,
                         and nothing indicates the guidance is actually
                         wrong for this version — merely unconfirmed
EDITION_MISMATCH       — entry is edition-specific and does not match
                         observed_edition (edition IS known and differs)
STALE                  — a newer ReleaseOverlay or a newer registry entry
                         for the same capability supersedes this one for
                         the observed version; this entry is known-outdated,
                         not merely unconfirmed
NO_OFFICIAL_GUIDANCE_FOUND — no registry entry exists for the capability
                         (today's empty-tuple case, now named explicitly)
```

**`CONFLICTING_GUIDANCE` is deliberately not a per-lookup runtime
state.** Two registry entries for the same capability disagreeing is a
registry-*authoring* defect, not a runtime condition — the registry is
Git-tracked and PR-reviewed (TB-G1), and ADR-017's own curation guidance
already caps entries at "no more than ~3 per capability." The correct
place to catch contradictory entries is the existing load-time
`_check_registry_integrity()` check, extended to flag same-capability,
overlapping-scope entries. This is a refinement of the seven-state
proposal, made because a cleaner closed model puts this concern where
ADR-017 already puts every other registry-integrity concern, not
because the state doesn't matter.

**Fixed after red-team review (Finding 8, MATERIAL)**: the first draft
described this check only as "a mechanical duplicate-scope check"
without defining what "duplicate scope" means mechanically — not
actually implementable as described. Fixed, concretely, as **two
separate, independent load-time checks** (the first draft's revision
conflated them into one ambiguous sentence — corrected here during
final acceptance review, since the original wording read as
self-contradictory: it listed "connected by a `supersedes_id` chain" as
a form of *overlap*, then simultaneously required *no* connecting
relationship, which cannot both be true of the same pair):

1. **Duplicate-scope check**: flags any two entries (`DocumentSource` or
   `ReleaseOverlay`, in any combination) that share the same
   `capability` **and** edition-compatible scope (same edition, or
   either is `BOTH`) **and** overlapping version scope (both
   `UNVERSIONED`-equivalent, or identical version strings) **and** are
   **not** connected by any `supersedes_id` relationship (direct or
   transitive) between them. This is a structural/identity check on
   matching conditions, not a content-similarity check — deliberately,
   since text-diffing for "disagreement" was never claimed to be
   tractable.
2. **Chain-integrity check**, independent of (1): a `supersedes_id`
   value that does not resolve to any known `source_id`/`overlay_id` is
   a dangling reference; a chain that revisits an entry already in its
   own ancestry (A supersedes B supersedes A) is a cycle. Both fail the
   load-time check, regardless of whether (1) would also have flagged
   the pair — a valid, connected `supersedes_id` chain is exactly what
   *exempts* two overlapping-scope entries from check (1), so check (2)
   is what confirms the chain used for that exemption is actually
   real and finite.

**Policy change this represents**: `lookup_guidance()` currently
*excludes* non-matching entries entirely (I6's accepted fail-closed
choice). This ADR proposes *including* them with an explicit
`ApplicabilityState` instead, for every state except
`NO_OFFICIAL_GUIDANCE_FOUND` (nothing to include) and a version/edition
mismatch so severe the entry is simply the wrong document (still
excluded — an EDITION_MISMATCH entry for an entirely different feature's
documentation is not useful "with a caveat"; the exclude/include line is
drawn per-entry by whether the underlying content is still about the
right feature, which the registry curator decides at authoring time via
which state values are legal for that entry's `version_applicability`
shape, not computed at lookup time). **This is a real behavior change to
already-shipped v0.3.0 code and needs its own explicit approval — it is
not silently implied as decided by this ADR's Proposed status.**

**Fixed after red-team review (Finding 5, MATERIAL)**: `UNVERSIONED`
(ADR-017's existing sentinel, unchanged) is a reasonable read for
genuinely evergreen content — but nothing distinguished "the source
explicitly states this applies regardless of version" from "this is
just the undated `/latest/` page and we don't actually know how far
back it applies," and silently treating the second as the first is
exactly the kind of unstated-scope inference the owner's review
instructions warned against, just inverted (inferring *unbounded*
applicability from *absent* version information). Fixed: a new,
orthogonal `EvidenceLevel` enum — `EXPLICIT_VERSION_SCOPED` /
`EXPLICIT_UNVERSIONED` / `INFERRED_FROM_CURRENT_DOCS` / `UNKNOWN` — is
now required on every `DocumentSource`/`ReleaseOverlay` entry.
`INFERRED_FROM_CURRENT_DOCS` (the honest default for most real-world
entries) can only ever contribute `VERSION_UNCONFIRMED`, never
`APPLICABLE`, even on an edition match — only an `EXPLICIT_*` entry can
reach `APPLICABLE`. Full shape in `docs/VERSION_AWARE_GUIDANCE.md`.

### 3. `ReleaseOverlay`: the missing piece for STALE/PARTIALLY_APPLICABLE

A new registry concept, same trust model as `DocumentSource` (Git-tracked,
PR-reviewed, `ALLOWED_DOCUMENT_HOSTS`-constrained, bounded free text):

```
ReleaseOverlay:
  overlay_id: str            # slug, same pattern as source_id
  capability: Capability
  applies_to_version: str    # exact SystemVersion.base value, or a small
                              # closed set — no ranges, no operators (I3)
  applies_to_edition: Edition
  evidence_level: EvidenceLevel      # Finding 5 — required, no default
  supersedes_id: str | None   # a DocumentSource.source_id OR another
                               # ReleaseOverlay.overlay_id — see Finding 6
  caveat_excerpt: str         # bounded, same I4 discipline
  canonical_url: str          # release notes / errata page, same allowlist
  content_hash: str
```

Curated exactly like `DocumentSource` — Git-tracked, one entry per known
behavior change worth surfacing, not a scrape of every release note.

**Fixed after red-team review (Finding 6, MATERIAL)**: the owner's own
example — base doc says X, a release note modifies X, a later errata
corrects the release note — requires an overlay to supersede *another
overlay*, not only a `DocumentSource`. The first draft's
`supersedes_source_id` field's type and name both restricted it to
referencing a `DocumentSource` only, with no way to express an
errata-corrects-a-release-note chain. Separately, the composition model
(§5 below) originally flattened all applicable overlays into an
unordered set, losing exactly the supersession order the owner's
example depends on being preserved. Fixed: renamed to `supersedes_id`,
documented as referencing either ID space (both already use the same
slug pattern); `GuidanceEvidence` now carries an ordered `overlay_chain`
(most-superseded first, current-truth last) instead of an unordered set
— see §5. A supersession cycle (A supersedes B supersedes A) is now an
explicit load-time registry-integrity failure (Finding 8's extended
check).

### 4. Live retrieval (TB-G3): resolved design, **not activated**

TB-G3 flagged its own hash-pinning approach as unresolved: a hash of a
short curated excerpt can never equal a hash of a full fetched page, even
for an unchanged, honest source. **Resolution**: replace hash-equality
with **substring presence** — at fetch time, verify the *exact* pinned
`content_excerpt` text (the same text a human reviewer read and approved
into the registry) is still present, verbatim, somewhere in the fetched
page's extracted text.

**Fixed after red-team review (Finding 2, BLOCKING)**: the first draft
described a successful presence check as confirming the reviewed text is
"still there, unchanged," and treated that as the basis for continuing
to serve the content as before. **This overclaims.** Substring presence
proves only that the exact string occurs *somewhere* in the fetched
page — it proves nothing about surrounding context (the same sentence
could now sit under a different heading with a different practical
meaning), and cannot distinguish "the original passage, intact" from
"the same string duplicated elsewhere while the original was altered or
removed." The design's actual safety property, correctly identified only
after this review: because **only the pre-approved, bounded excerpt
itself is ever returned to a consumer — never the live page's
surrounding text, regardless of presence-check outcome** — the
context-duplication and misleading-surrounding-content attack classes
are foreclosed by *never reading page context into anything
consumer-facing* at all, not by the presence check "verifying" them.
Restated precisely: the presence check's actual job is deciding whether
to serve the pinned excerpt (present → serve exactly the text a human
already reviewed) or fall back (absent → the reviewed claim may no
longer hold at that URL, don't serve it as current). A failed check —
now named **drifted**, not "tampered" or "unchanged" — never serves
`APPLICABLE` guidance; falls back to the bundled snapshot if one exists
for that entry, `trust_label` reflecting the fallback, or to
`NO_OFFICIAL_GUIDANCE_FOUND` if none does. Comparison is NFC-normalized
Unicode, case-sensitive, with no confusable/homoglyph folding — specified
explicitly rather than left to an implementer's discretion.

**Full design, still not activated in this ADR:**

- Retrieval fetches **only** the exact `canonical_url` already in the
  registry for that capability/entry — never a search query, never a
  derived or guessed URL. The "approved documentation family" is the
  existing Git-tracked registry itself; nothing new is introduced that
  could fetch an unreviewed URL.
- HTTPS-only, strict TLS validation. **Fixed after red-team review
  (Finding 3, MATERIAL — four concrete gaps, not one):** (1) the *final*
  URL after following any redirect must equal the registered
  `canonical_url` **exactly**, not merely share an allow-listed host —
  the first draft's host-only check would have accepted a same-host
  redirect to an entirely different, unreviewed page; max 3 redirect
  hops. (2) the response-size bound (2 MB) must be enforced on the
  **decompressed** byte stream, checked incrementally as it streams,
  never solely against a pre-decompression `Content-Length` header —
  the first draft's "check size before parse" wording did not actually
  bound a decompression-bomb response. (3) `Content-Type` must indicate
  HTML or plain text before any parse is attempted; anything else aborts
  the fetch. (4) DNS rebinding: resolve the hostname once, validate the
  resolved address is public (not private/loopback/link-local) *before*
  connecting — a hostname-string allow-list alone does not bind the IP
  actually connected to. Any of the four failing aborts the fetch,
  same fallback chain as a drift result.
- A hard fetch timeout, in addition to the above.
- **Fixed after red-team review (Finding 4, MATERIAL):** live retrieval
  **must** use an HTTP transport instance entirely separate from
  `pfsense_client.py`'s pfSense-facing transport — no shared client,
  session, connection pool, cookie jar, or default-header configuration
  — and must never attach the pfSense API key or any `PFSENSE_*`
  credential to a documentation-host request under any circumstance.
  The first draft never stated this explicitly; a future implementer
  reusing an existing configured client for convenience was a real,
  foreseeable path to a credential leak toward `docs.netgate.com`.
- Extracted text is scanned only for the pinned excerpt's presence — the
  fetched page's *other* content is never stored, never summarized, never
  passed to a model. Only the already-reviewed excerpt (verified present)
  or a drift signal is ever returned; the live page's full text is
  discarded after the presence check.
- Cache: TTL-based, proposed default 24 hours (documentation pages change
  rarely; this bounds request volume without serving indefinitely stale
  content). `GuidanceReference` gains `retrieval_mode:
  bundled_snapshot | live_fetch_cached`, `cached_at: datetime | None`,
  and `freshness_state: fresh | stale_cache | drift_detected`. Cache is
  process-lifetime, in-memory only — no disk persistence, matching the
  guidance layer's existing "owns no mutable state" invariant as closely
  as a cache can (the cache itself is the one new piece of mutable
  state this would introduce, and is explicitly scoped: keyed only by
  `source_id`, cleared on process restart, never written to disk).
- Offline behavior: if a live fetch fails for any reason (network,
  timeout, non-2xx, TLS failure, disallowed redirect, drift), fall back
  to the bundled snapshot for that entry if one exists; otherwise return
  `NO_OFFICIAL_GUIDANCE_FOUND` for that entry. Never raise past this
  boundary, never block on retry — same I6 discipline ADR-017 already
  established.

**Still not recommended**: a vector database or embeddings. Every
capability's curated corpus remains small (ADR-017's own ~3-entries-per-
capability guidance); there is no concrete evidence deterministic,
per-capability URL retrieval is insufficient. Revisit only if that
evidence appears.

### 5. `GuidanceEvidence`: the read-recommendation composition model

```
GuidanceEvidence:
  capability: Capability
  observed_edition: ObservedEdition   # Finding 1 — KNOWN_CE | KNOWN_PLUS | UNKNOWN, never Edition
  observed_version: str | None
  appliance_identity_source: str   # e.g. "SystemVersion.base (pfsense_get_system_version)"
  guidance: tuple[GuidanceReference, ...]   # each carrying its own ApplicabilityState
  overlay_chain: tuple[str, ...]     # Finding 6 — ordered most-superseded-first,
                                       # current-truth last; overlay_id values
  overall_state: ApplicabilityState  # the least-favorable state among
                                       # guidance/overlays actually applicable,
                                       # or NO_OFFICIAL_GUIDANCE_FOUND
```

Composition (conceptual — an orchestration function, not a new tool):

```
observed appliance (edition, version)
  -> capability/use case
  -> lookup_guidance() [extended: returns entries + ApplicabilityState]
  -> applicable ReleaseOverlays
  -> GuidanceEvidence
```

This is explicitly **not** wired into any READ tool's output in this ADR
— "Do not wire this into every READ tool yet" is followed literally.
**Smallest future integration point, if ever authorized**: a single new
orchestration function (not a new MCP tool, not a change to any of the
42 existing tools) that a future consumer — the eventual Tier 1 PREPARE
phase, most plausibly — could call directly. No READ tool's schema needs
to change for this to exist; `GuidanceEvidence` never needs to reach an
AI client through a *tool result* to be useful to PREPARE, which is
server-internal. If a future decision *does* want an AI client to see
this directly (e.g., an explicit "get guidance for capability X" tool),
that is its own separate, later, explicitly-approved public-API decision
— not a byproduct of accepting this ADR.

## Trust boundary: guidance remains evidence, never authorization

Restating and extending ADR-017's TB-G4, explicitly against every item
this ADR adds:

- `ApplicabilityState`, `ReleaseOverlay`, and `GuidanceEvidence` are all
  read-only, advisory classifications of *documentation content* — none
  has a field of type capability, endpoint, HTTP method, or confirmation
  token (the same closed-schema constraint ADR-017's G1 already enforces,
  extended to every new type this ADR introduces).
- Appliance identity resolution (edition/version inference) **observes**
  state; it cannot select a capability, endpoint, or WRITE action, and
  has no import path to `WriteEndpoints`, `pfsense_mcp.tier1`, or any
  WRITE-capable transport — same TB-G4 boundary, same enforcement
  mechanism (AST isolation tests), extended to cover the new module(s).
- `overall_state` can only ever make a future PREPARE phase's evidence
  *weaker* by triggering fail-closed behavior (see below) — it can never
  strengthen or substitute for a Recovery Contract, confirmation, or the
  sealed executor's own gates. There is no code path from "guidance says
  APPLICABLE" to "mutation proceeds" that does not pass through every
  existing Tier 1 gate unchanged.
- **Fixed after red-team review (Finding 7, MATERIAL)**: the preceding
  bullet stated this as a policy intent in the first draft, without
  pinning down *where in the call graph* it holds — a future
  implementer could plausibly (and in good faith) wire
  `GuidanceEvidence.overall_state` into the state machine's own
  transition-rule table alongside the existing PREPARED→EXECUTING gates,
  which would make "guidance says APPLICABLE" one of several jointly
  sufficient conditions — a real, if subtle, violation of the intended
  asymmetry. Fixed with a structural, checkable rule, not only a
  restated intention: guidance evidence may be consulted **only as a
  boolean AND-veto applied before contract creation** — `may_prepare =
  existing_authorization AND (guidance_not_required_for_capability OR
  guidance_check_passes)`, never as an OR, never as an independent
  alternative path — and **`GuidanceEvidence`/`ApplicabilityState` must
  never appear as a field the state machine's own transition-rule table
  (`state_machine.py`) reads, and must never enter
  `confirmation_authority.md`'s digest computation**, both exactly as
  ADR-017's TB-G4 already established, unchanged. A future reviewer can
  check this concretely: "is `GuidanceEvidence` read anywhere inside
  `state_machine.py` or the confirmation digest computation? If yes,
  that's wrong" — not only "does this feel consistent with the stated
  intent."
- Live retrieval (TB-G3), if ever activated, still cannot expand which
  capability, endpoint, or document any request touches — it only changes
  *when* the exact, pre-approved excerpt is fetched, never *what* URL is
  reachable. The registry (Git-tracked, PR-reviewed) remains the only
  thing that decides which URLs exist to fetch, unchanged from TB-G1.
- **Guidance→recommendation separation** (re-examined in red-team
  review, no change needed): `GuidanceEvidence`'s fields
  (`observed_edition`/`observed_version`/`guidance`/`overall_state`) are
  structurally separate typed fields, never concatenated into one
  string — that is this layer's actual, honest guarantee. Whether a
  future *consumer* (a prompt template, a tool description) preserves
  that separation when presenting to a human or model is a
  consumption-boundary concern, the same class of residual risk
  ADR-017's TB-G2 already names for excerpt content generally — named
  here explicitly rather than left implicit.

## Future WRITE / PREPARE integration (design only, not implemented)

```
OBSERVED STATE
+ APPLIANCE VERSION (this ADR's identity resolution)
+ OFFICIAL GUIDANCE (lookup_guidance(), extended)
+ VERSION/EDITION APPLICABILITY (ApplicabilityState)
+ RELEASE-SPECIFIC CAVEATS (ReleaseOverlay)
+ DRY_RUN/VALIDATION EVIDENCE where available (a future capability
  adapter's own PREPARE-phase check — see the OPNsense competitive
  review's §6/§7 findings on the community pfSense REST API's `dry_run`
  parameter, a separate, already-tracked future input)
+ RECOVERY CONTRACT
+ AUTHORIZATION
= a PREPARE phase whose evidence is honest about what it does and does
  not know, not merely "structurally present."
```

**Open policy question, not resolved here**: should a capability whose
safety policy is designed to *require* official guidance fail PREPARE
closed when guidance is `NO_OFFICIAL_GUIDANCE_FOUND`,
`VERSION_UNCONFIRMED`, or `EDITION_MISMATCH`? This ADR's position:
**yes, for any capability whose adapter contract explicitly opts into
requiring it** — but *not* as a blanket rule for every future capability,
since some capabilities may be safe enough by construction (rate/blast-
radius limits, reversibility, confirmation) that documentation-derived
evidence adds little. This is a per-capability-adapter-contract decision
for Phase 5, not decided here, and explicitly deferred to whichever
future ADR designs that first real adapter.

**This ADR does not begin Phase 5.** No capability adapter exists to
wire this into.

## Acceptance record (2026-08-09)

Accepted following an independent adversarial red-team review
(`reports-ai/reviews/ADR_018_RED_TEAM.md`, 10 findings, all fixed) and a
subsequent independent final acceptance review
(`reports-ai/reviews/ADR_018_ACCEPTANCE_REVIEW.md`, verdict RECOMMEND
ADR-018 ACCEPTANCE, two further coherence gaps found and fixed in that
same pass). The owner accepted that verdict.

**Acceptance of this ADR:**

- Accepts the architecture and trust boundaries described above —
  `ObservedEdition`, the appliance-identity assembly point,
  `ApplicabilityState`, `EvidenceLevel`, `ReleaseOverlay`, the resolved
  (not activated) TB-G3 live-retrieval design, the `GuidanceEvidence`
  composition model, and the guidance-can-only-remove-never-create-
  permission structural rule — as the authoritative design for future
  version-aware Official Guidance work.
- Does **NOT** activate live documentation retrieval (TB-G3) — remains
  its own future, separately-gated decision per this ADR's own
  "Activation requirements."
- Does **NOT** expose guidance through the public MCP API — no READ
  tool schema changes, no new guidance-facing tool.
- Does **NOT** activate Tier 1 — the guidance package and any future
  appliance-identity/guidance code remain unimported by production
  bootstrap, unchanged.
- Does **NOT** authorize WRITE in any form.
- Does **NOT** resolve future per-capability guidance requirements —
  whether a given capability's adapter contract opts into *requiring*
  guidance evidence for PREPARE remains an explicit Phase-5,
  per-capability decision (see "Future WRITE / PREPARE integration"
  above), not decided by this acceptance.
- Does **NOT** authorize Phase 5 — no capability adapter exists, and
  none is authorized by this acceptance.
- **Preserved three explicitly deferred implementation questions**
  (owner-accepted as non-blocking, not to be silently resolved in a way
  that changes the properties above). Status as of 2026-08-09, updated by
  a dedicated design-and-red-team pass
  (`reports-ai/reviews/ADR_018_APPLICABILITY_DECISION_PROCEDURE_RED_TEAM.md`):
  1. **The exact `APPLICABLE`/`PARTIALLY_APPLICABLE`/`STALE` decision
     procedure for a `GuidanceReference` given its overlay chain —
     specified, then owner-authorized and implemented (2026-08-09).**
     `applicability.compute_entry_applicability()` implements the
     five-step algorithm `docs/VERSION_AWARE_GUIDANCE.md`'s "Single-entry
     applicability decision procedure" section specifies, replacing the
     removed `applicability_state_for_entry_is_not_implemented_here()`
     marker; `registry.lookup_guidance()` now returns the extended,
     inclusion-with-state `GuidanceReference` shape (the "exclude vs.
     exclude-with-state" policy change this ADR's §2 and this same
     Acceptance record both flagged as needing separate explicit
     approval — now granted); `bridge.bridge_guidance_reference()`
     implements the `GuidanceReference`→`EvidenceReference` bridge.
     Still entirely offline and unwired: no MCP tool, no READ-tool
     schema change, no PREPARE/Tier 1 consumer — nothing calls
     `compose_guidance_evidence()` yet, and wiring it into a real
     consumer remains its own separate, explicit, not-yet-granted
     decision.

     **Re-investigated 2026-08-09, now that the bridge above exists**
     (full record:
     `reports-ai/reviews/ADR_018_CONSUMER_INTEGRATION_INVESTIGATION_2026-08-09.md`):
     confirmed, directly from this ADR's own §5 text above, that no
     legitimate real consumer currently exists without crossing an
     explicitly-gated boundary — either a public MCP schema/tool change
     (its own separate product decision) or Tier 1 PREPARE construction
     (Phase 5). A non-MCP developer/reviewer CLI tool was considered and
     explicitly rejected as a fabricated consumer with no documented need
     (checked directly against `OFFICIAL_GUIDANCE_LAYER.md`'s Review
     checklist, which names no such tool), not a legitimate integration
     point this ADR's own text ever identified. No code written; nothing
     wired. This question is closed for any future session re-reading
     this record — re-investigate only if the bridge's own shape changes
     or a new consumer candidate genuinely did not exist at this writing.
  2. **`NO_OFFICIAL_GUIDANCE_FOUND`'s exact runtime representation —
     formally confirmed CLOSED, not merely assumed.** It is an empty
     `EvidenceReference` tuple passed to the already-shipped
     `compose_guidance_evidence()` (Step 3), which already computes
     `overall_state = NO_OFFICIAL_GUIDANCE_FOUND` via
     `applicability.compute_overall_state(())` — not a synthetic
     sentinel object. No runtime behavior changed by closing this
     question; it was already true of the shipped Step 2/3 code, only
     now stated as resolved rather than left listed as open.
  3. **Per-capability guidance-requirement opt-in** — a future Phase-5
     decision, not this ADR's to make. Unchanged, still open.

Each piece of the accepted architecture (appliance identity,
`EvidenceLevel`/`ApplicabilityState`/`ReleaseOverlay`,
`lookup_guidance()`'s exclude→include policy change, live retrieval,
any READ-tool or PREPARE wiring) remains independently gated behind its
own future, separate, explicit approval exactly as this ADR's
"Activation requirements" section already specifies — acceptance of the
architecture is not activation of any of its parts.

## Consequences

- ADR-017's own explicitly-flagged open items (edition self-challenge,
  TB-G3's unresolved hash question) are now resolved at the design
  level — nothing about ADR-017's *accepted, shipped* scope changes;
  this ADR's own pieces still require their own separate activation
  (see "Acceptance record" above).
- `pfsense_mcp_info` (v0.3.1, pushed to `origin/main` as `459262e`)
  requires **no change**. See "Self-challenge: pfsense_mcp_info" below.
- The concrete near-term deliverable, now that this ADR is accepted, is
  design/spec-only until further, separate implementation approval:
  `ApplicabilityState`, `EvidenceLevel`, `ReleaseOverlay`,
  `ObservedEdition`, `ApplianceIdentity`, and one canonical
  `resolve_appliance_identity()` assembly function (Finding 10 — the
  single call point every future consumer must share, not merely a
  single inference sub-function), as new, tested, but **unwired** code —
  the same "implemented, inert, isolated" pattern ADR-017 and Tier 1
  already use. Live retrieval (TB-G3 activation), the include-vs-exclude
  policy change to `lookup_guidance()`, and any READ-tool or PREPARE
  wiring each remain their own, later, separately-gated decisions.
- This revision followed an independent adversarial review
  (`reports-ai/reviews/ADR_018_RED_TEAM.md`, 10 findings — 2 BLOCKING, 6
  MATERIAL, 1 MINOR, 1 confirmed no-issue) required by the owner before
  requesting acceptance. Every "Fixed after red-team review" note above
  marks a real change from the first draft, not a rubber stamp.

## Self-challenges

### Self-challenge: pfsense_mcp_info

Does the already-implemented, already-validated, already-pushed
`pfsense_mcp_info` need to change now that appliance identity resolution
exists? Re-asked and re-confirmed independently during red-team review,
not merely carried over from the design pass.

**No.** `pfsense_mcp_info`'s entire design invariant is "local process
facts only, zero pfSense API calls" (explicitly required by its own
authorizing instructions and enforced by `openWorldHint=false`).
Appliance edition/version fundamentally requires an already-existing
pfSense API call (`pfsense_get_system_version`) — folding that in would
break the one invariant that makes `pfsense_mcp_info` cheap, safe, and
side-effect-free to call. The existing `pfsense_get_system_version` tool
already exposes the raw fact (`base`); a future edition-inference
utility function (this ADR) is the shared place that interprets it —
shared by any future consumer, not duplicated, and not owned by
`pfsense_mcp_info`. **Recommendation confirmed: no change to
`pfsense_mcp_info`'s already-validated design.**

### Self-challenge: is the CE/Plus version-scheme discriminator itself gameable or fragile?

An appliance could theoretically report a spoofed or corrupted
`/etc/version` file. This is not a new risk this ADR introduces — every
existing READ tool already trusts pfSense's own reported state as
ground truth (this project has no independent way to verify pfSense
itself is honest, and treating it as untrusted would make every READ
tool's output equally suspect, which is out of scope for this ADR to
solve). The discriminator's actual fragility is scheme-drift risk (what
if Netgate changes the numbering scheme again) — mitigated by the
explicit "outside both known ranges → unknown, never guess" fallback,
which fails closed exactly the way ADR-017's edition-unknown default
already does today.

### Self-challenge: does including near-miss guidance (PARTIALLY_APPLICABLE, VERSION_UNCONFIRMED) instead of excluding it increase prompt-injection surface?

No new surface: the same TB-G2 boundary applies unchanged — excerpt text
still only ever flows into a bounded, typed field, never into anything
instruction-bearing, regardless of which `ApplicabilityState` it carries.
Including *more* results with an honest state label is strictly more
information than silently excluding them was, and G1's closed schema
means a state label cannot itself be read as authorization no matter how
it's set — the risk this question is really probing (could a malicious
document manufacture an `APPLICABLE` label for itself) is foreclosed by
`ApplicabilityState` being computed entirely from registry metadata
(`pfsense_edition`, `version_applicability`, overlay entries) that TB-G1
already establishes is Git-tracked, PR-reviewed, and never derived from
the fetched content itself — the *state* is data about the document
elected by a human reviewer, not something the document's own text can
influence.

## Alternatives considered

- **Do nothing; keep `version_mismatch: bool` as a permanent False** —
  rejected: leaves the owner's stated objective (version-aware guidance)
  entirely unaddressed and leaves ADR-017's own explicitly-reserved field
  permanently unused.
- **Free-text edition/version matching via regex against arbitrary
  version strings, not scheme-based** — rejected: exactly the "fragile
  heuristic" the owner's instruction warned against; the scheme-based
  approach is grounded in Netgate's own documented, intentional design
  choice, not pattern-matching happenstance.
- **Vector database / embeddings for retrieval** — rejected per the
  owner's explicit instruction and ADR-017's own existing "Future
  migration path" reasoning: no evidence the small, curated,
  per-capability corpus needs it.
- **Full-page hashing for TB-G3 instead of substring presence** —
  rejected: requires defining a page-normalization scheme (whitespace,
  markup, ads/nav-chrome changes) that would false-positive on every
  cosmetic site update; substring presence directly answers the only
  question that matters and degrades safely.

## References

- `docs/adr/ADR-017-official-guidance-layer.md` — the accepted base this
  ADR extends.
- `docs/OFFICIAL_GUIDANCE_LAYER.md` — ADR-017's companion spec; TB-G3 and
  the edition self-challenge are the two sections this ADR resolves.
- `docs/VERSION_AWARE_GUIDANCE.md` — this ADR's own companion spec
  (implementation-ready detail, still not implemented).
- `reports-ai/reviews/OPNSENSE_MCP_COMPETITIVE_REVIEW.md` — §2/§3/§6/§7,
  the competitive-review findings that fed this design (appliance
  compatibility model, observability vocabulary, `dry_run` as a future
  PREPARE input).
- `reports-ai/reviews/ADR_018_RED_TEAM.md` — the independent adversarial
  review of this ADR's first draft: 2 BLOCKING and 6 MATERIAL findings,
  all fixed in this text. Read it for full failure scenarios behind each
  "Fixed after red-team review" note above.
- `docs.netgate.com/pfsense/en/latest/releases/versions.html` — the
  primary source for the CE/Plus version-numbering-scheme distinction,
  independently re-verified twice (design pass and red-team pass).
