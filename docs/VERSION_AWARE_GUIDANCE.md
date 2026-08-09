# Version-aware Official Guidance resolution — implementation-ready spec

Companion spec to `docs/adr/ADR-018-version-aware-guidance-resolution.md`,
mirroring `OFFICIAL_GUIDANCE_LAYER.md`'s relationship to ADR-017. Read the
ADR first — it carries the decision, the resolved TB-G3 design question,
and the self-challenges. This document is the implementation-ready shape
for whichever future session builds the parts ADR-018 authorizes as inert
scaffolding (not the parts it explicitly leaves deferred/unactivated).

**Nothing in this document is implemented.** ADR-018 is now **Accepted**
(2026-08-09) — architecture and trust boundaries only; see its
"Acceptance record" section for exactly what that does and does not
grant. Like `OFFICIAL_GUIDANCE_LAYER.md` after ADR-017's acceptance,
this specifies enough to remove ambiguity at build time without
asserting any of it is built yet — each piece still requires its own
separate, future implementation approval.

**Revised after independent adversarial review**
(`reports-ai/reviews/ADR_018_RED_TEAM.md`) — every section below reflects
the fixed design; a "Fixed after red-team review" note marks each place
that changed from the first draft, with the finding number for
cross-reference.

## Purpose

Let a future consumer (an AI client via some future tool, or a Tier 1
PREPARE phase) answer: "for this capability, on the appliance actually
observed, what official guidance applies, and how confidently?" — instead
of silently assuming `/latest/` documentation universally applies.

## Scope boundary (what this spec covers vs. does not)

Covers: appliance-identity inference and its one canonical assembly
point (Finding 10), `ApplicabilityState`, `EvidenceLevel`, `ReleaseOverlay`,
the extended `lookup_guidance()` shape, `GuidanceEvidence` composition,
and the resolved (but not activated) TB-G3 live-retrieval design.

Does not cover: any READ tool schema change, any Tier 1 PREPARE wiring,
any new public MCP tool. Each is a separate, later, explicitly-approved
activation per ADR-018's "Activation requirements" below.

## Appliance identity resolution

```python
# src/pfsense_mcp/guidance/appliance_identity.py (not yet created)

from datetime import datetime, timezone
from enum import Enum

_CE_MAX_MAJOR = 9  # pfSense CE has used 1.x/2.x to date -- re-verified
# against docs.netgate.com/pfsense/en/latest/releases/versions.html
# twice (design pass and red-team pass, 2026-08-09). ANY future change
# to this bound must cite the specific primary-source page/date it was
# re-verified against in the same commit -- Finding 9. This is a
# known-schemes table, reviewed against that page, not an evergreen
# assumption.
_PLUS_MIN_YEAR = 21  # pfSense Plus's year-based scheme began with
# version 21.02 (February 2021) -- same re-verification requirement.


class ObservedEdition(str, Enum):
    """Fixed after red-team review, Finding 1 (BLOCKING): the first
    draft reused ADR-017's Edition enum (CE/PLUS/BOTH) for observed
    appliance state, with None standing for unknown. Edition.BOTH is
    meaningful for document *applicability* (a document can apply to
    both editions); it is never meaningful for an *observed appliance*
    (a real appliance is always exactly one edition or unknown, never
    both). Nothing prevented a future caller from passing Edition.BOTH
    as an "observed" value, which means nothing for a real appliance.
    This closed, three-member enum is used exclusively for observed
    state; Edition continues to be used exclusively for
    DocumentSource/ReleaseOverlay applicability.
    """

    KNOWN_CE = "known_ce"
    KNOWN_PLUS = "known_plus"
    UNKNOWN = "unknown"


def infer_edition_from_version_base(base: str) -> ObservedEdition:
    """Infer pfSense edition from SystemVersion.base's version-string
    shape, per Netgate's own documented CE (<major>.<minor>.<patch>) vs.
    Plus (<year>.<month>.<patch>) numbering schemes -- see ADR-018 S1.
    Never a network call: operates on a string the caller already has
    from an existing pfsense_get_system_version call.

    Returns ObservedEdition.UNKNOWN on any value outside both known
    ranges -- never guesses. This is the single function any future
    consumer calls for inference; it must not be reimplemented
    elsewhere (ADR-018's "no duplicated parallel source of truth"
    requirement, same discipline already applied to
    WriteEndpoints.active_entries() in v0.3.1). See
    resolve_appliance_identity() below for the one canonical assembly
    point that wraps this function -- Finding 10: a single shared
    inference function is necessary but not sufficient; three future
    consumers must also share one assembly path, not three independent
    integrations of the same function.
    """
    first_component = base.split(".", 1)[0]
    if not first_component.isdigit():
        return ObservedEdition.UNKNOWN
    major = int(first_component)
    if 1 <= major <= _CE_MAX_MAJOR:
        return ObservedEdition.KNOWN_CE
    if _PLUS_MIN_YEAR <= major <= 99:
        return ObservedEdition.KNOWN_PLUS
    return ObservedEdition.UNKNOWN
```

**No new capability, no new READ tool.** Callers obtain `base` from the
existing `pfsense_get_system_version` tool's already-shipped
`SystemVersion.base` field.

### `ApplianceIdentity` and its one canonical assembly function

**Added after red-team review, Finding 10 (MATERIAL)**: the first draft
specified only the inference sub-function above, leaving assembly
(calling `pfsense_get_system_version`, extracting `base`, calling
inference, packaging the result with provenance) as implicit glue code
each future consumer might write independently. Three future sessions,
each correctly reusing `infer_edition_from_version_base()`, could still
diverge on provenance labeling, error handling, or timestamp semantics —
a softer but real version of the "three independent detection
implementations" risk the owner named. Fixed with one canonical value
object and one canonical assembly function:

```python
# src/pfsense_mcp/guidance/appliance_identity.py (continued)

from pydantic import BaseModel, ConfigDict

from ..pfsense_client import PfSenseClient


class ApplianceIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    observed_edition: ObservedEdition
    observed_version: str | None  # SystemVersion.base, verbatim
    identity_source: str  # fixed literal: "SystemVersion.base (pfsense_get_system_version)"
    resolved_at: str  # ISO8601 UTC, when this was assembled


def resolve_appliance_identity(client: PfSenseClient) -> ApplianceIdentity:
    """The one function any future consumer calls -- guidance
    resolution, a future Tier 1 PREPARE precondition check, and
    pfsense_mcp_info itself if a future explicit approval ever expands
    its scope to include appliance facts. No other module may
    reimplement this assembly independently -- a code-review rule as
    firm as capability_adapter_contract.md's I2 ("no adapter constructs
    its own client"). Internally: one call to
    client.get_system_version(), one call to
    infer_edition_from_version_base(). Requires an existing pfSense API
    call (via the caller-supplied client) -- this is why
    pfsense_mcp_info does not call this function today; see ADR-018's
    "Self-challenge: pfsense_mcp_info."
    """
    version = client.get_system_version()
    edition = infer_edition_from_version_base(version.base) if version.base else ObservedEdition.UNKNOWN
    return ApplianceIdentity(
        observed_edition=edition,
        observed_version=version.base,
        identity_source="SystemVersion.base (pfsense_get_system_version)",
        resolved_at=datetime.now(timezone.utc).isoformat(),
    )
```

## `EvidenceLevel` (new — Finding 5)

```python
# src/pfsense_mcp/guidance/models.py (extends the existing module)


class EvidenceLevel(str, Enum):
    """Fixed after red-team review, Finding 5 (MATERIAL): the first
    draft had no way to distinguish "the source explicitly states this
    applies regardless of version" from "this is just the undated
    /latest/ page and we don't actually know how far back it applies" --
    both would have been recorded identically as ADR-017's existing
    UNVERSIONED sentinel. A registry curator who cannot truthfully claim
    EXPLICIT_UNVERSIONED must use INFERRED_FROM_CURRENT_DOCS instead --
    the honest default for most real-world entries.
    """

    EXPLICIT_VERSION_SCOPED = "explicit_version_scoped"
    EXPLICIT_UNVERSIONED = "explicit_unversioned"
    INFERRED_FROM_CURRENT_DOCS = "inferred_from_current_docs"
    UNKNOWN = "unknown"
```

`DocumentSource` and `ReleaseOverlay` both gain a required
`evidence_level: EvidenceLevel` field (no default — a registry curator
must actively choose it, matching every other required-at-authoring-time
field in this module).

## `ApplicabilityState`

```python
class ApplicabilityState(str, Enum):
    APPLICABLE = "applicable"
    PARTIALLY_APPLICABLE = "partially_applicable"
    VERSION_UNCONFIRMED = "version_unconfirmed"
    EDITION_MISMATCH = "edition_mismatch"
    STALE = "stale"
    NO_OFFICIAL_GUIDANCE_FOUND = "no_official_guidance_found"
    # CONFLICTING_GUIDANCE is deliberately NOT a member -- see ADR-018
    # "ApplicabilityState" section and Finding 8 below. It is a
    # registry-integrity build/test failure, not a runtime-returned
    # state.
```

**Computation rule added after red-team review (Finding 5)**: an entry
whose `evidence_level` is `INFERRED_FROM_CURRENT_DOCS` can contribute at
most `VERSION_UNCONFIRMED`, even when its edition matches the observed
appliance exactly — only an `EXPLICIT_VERSION_SCOPED` or
`EXPLICIT_UNVERSIONED` entry can reach `APPLICABLE`.

`GuidanceReference` gains (replacing `version_mismatch: bool`):

```python
class GuidanceReference(BaseModel):
    # ... existing fields unchanged ...
    applicability: ApplicabilityState  # replaces version_mismatch
    evidence_level: EvidenceLevel  # echoes the registry entry's own field
    applicable_overlay_chain: tuple[str, ...]  # ReleaseOverlay.overlay_id values,
    # ORDERED most-superseded first, current-truth last -- () if none.
    # Finding 6's fix applies at this per-entry level too, not only at
    # GuidanceEvidence's aggregate level: a single DocumentSource can
    # itself have its own release-note-then-errata chain, and flattening
    # it here would reintroduce exactly the supersession-order loss
    # Finding 6 fixed one level up. Caught during final acceptance
    # review as a real, if narrow, gap in Finding 6's original fix --
    # the text was added at the aggregate level but the same problem at
    # the per-reference level was missed on the first revision pass.
    observed_edition_used: ObservedEdition  # Finding 1 -- ObservedEdition, never Edition
    observed_version_used: str | None  # echoes the input, for auditability
    retrieval_mode: RetrievalMode  # promoted from registry-entry-only to every reference
    cached_at: datetime | None = None  # only set when retrieval_mode is a live/cached mode
    freshness_state: str | None = None  # "fresh" | "stale_cache" | "drift_detected"; None for bundled_snapshot
```

## `ReleaseOverlay`

```python
class ReleaseOverlay(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    overlay_id: str = Field(pattern=SOURCE_ID_PATTERN)
    capability: str  # Capability member name, same representation choice as GuidanceReference
    applies_to_version: str  # exact SystemVersion.base value -- no ranges (I3 discipline)
    applies_to_edition: Edition
    evidence_level: EvidenceLevel
    supersedes_id: str | None
    caveat_excerpt: str = Field(max_length=MAX_EXCERPT_LENGTH)
    canonical_url: str  # same ALLOWED_DOCUMENT_HOSTS validator as DocumentSource
    content_hash: str

    @field_validator("canonical_url")
    @classmethod
    def _check_canonical_url(cls, value: str) -> str:
        return _validate_canonical_url(value)
```

**Fixed after red-team review (Finding 6, MATERIAL)**: `supersedes_id`
(renamed from `supersedes_source_id`) may reference **either** a
`DocumentSource.source_id` **or** another `ReleaseOverlay.overlay_id` —
both already share `SOURCE_ID_PATTERN`, so this requires no new pattern,
only documentation and lookup-logic that resolves against both
registries when following a chain. This makes the owner's own example
representable: base doc → release-note overlay supersedes the base doc
→ errata overlay supersedes the release-note overlay. A chain that
cycles (A supersedes B supersedes A) is a load-time registry-integrity
failure — see Finding 8 below.

Registered in a new, separate, Git-tracked dict — not merged into
`_REGISTRY` — so a registry maintainer authoring a `DocumentSource` never
has to reason about overlay entries in the same review pass:

```python
_OVERLAY_REGISTRY: dict[Capability, tuple[ReleaseOverlay, ...]] = {}
```

## Single-entry applicability decision procedure

**Added by a dedicated design-and-red-team pass** (2026-08-09,
`reports-ai/reviews/ADR_018_APPLICABILITY_DECISION_PROCEDURE_RED_TEAM.md`),
resolving ADR-018's Acceptance record deferred question #1. Not
implemented by this pass — this section specifies the algorithm the
future extended `lookup_guidance()` (below) must run for each registry
entry; building it remains its own separate, explicit approval.

### Scope: exact-match only, by the already-accepted schema

`DocumentSource.version_applicability` and `ReleaseOverlay.
applies_to_version` are both plain `str` fields with no range/operator
grammar (I3: "no ranges, no operators, no grammar to parse", restated
consistently across ADR-017 and ADR-018). This procedure is defined
**only** in terms of exact-string-equality-or-`UNVERSIONED`, matching
that accepted schema exactly. It does **not** define behavior for
bounded ranges, minimum-version, or maximum-version scoping, because
`DocumentSource`/`ReleaseOverlay` cannot represent them today — adding
that expressiveness is its own future, separately-authorized schema
extension, not something this procedure may assume into existence. This
is not merely an omission: staying exact-match-only avoids an entire bug
class (two independently-written version-range comparators disagreeing)
that a richer grammar would introduce — see the red-team report's
finding on this point.

### Inputs

For one registry entry `E` (a `DocumentSource`, or equivalently a
`ReleaseOverlay` being evaluated as a caveat/supersession source) and
one already-resolved `(observed_edition: ObservedEdition, observed_version:
str | None)` pair (from `ApplianceIdentity` — never re-derived here):

- `E.pfsense_edition: Edition` (`CE` / `Plus` / `BOTH`)
- `E.version_applicability: str` (`UNVERSIONED` or an exact version string)
- `E.evidence_level: EvidenceLevel`
- The full `_OVERLAY_REGISTRY[E's capability]` — needed to determine
  supersession/caveat relationships, not merely `E` in isolation.

### Step 1 — classify edition status

```
edition_status =
    MATCH        if E.pfsense_edition == Edition.BOTH
    MATCH        if E.pfsense_edition maps to observed_edition
                    (Edition.CE ~ ObservedEdition.KNOWN_CE,
                     Edition.PLUS ~ ObservedEdition.KNOWN_PLUS)
    MISMATCH     if E.pfsense_edition != BOTH and observed_edition is
                    KNOWN_CE or KNOWN_PLUS and does not map to E.pfsense_edition
    UNCONFIRMED  if E.pfsense_edition != BOTH and observed_edition is UNKNOWN
```

**Resolves a real gap found while writing this procedure, not merely
transcribed from the ADR's prose**: ADR-018 §2's own definitions of
`EDITION_MISMATCH` ("edition IS known and differs") and
`VERSION_UNCONFIRMED` ("edition matches; ...") leave `edition_status ==
UNCONFIRMED` unclassifiable by either state's literal wording — an
edition-specific entry when `observed_edition == UNKNOWN` fits neither
"edition is known and differs" nor "edition matches." **Resolution**:
`edition_status == UNCONFIRMED` routes into `VERSION_UNCONFIRMED` (Step
4 below), generalizing that state's evident purpose — "insufficient
identity information to confirm applicability, with no affirmative
evidence of mismatch" — to cover edition uncertainty as well as version
uncertainty, since `ApplicabilityState` has no separate
`EDITION_UNCONFIRMED` member and adding one would itself be a schema
change beyond this procedure's scope. **Flagged for owner confirmation,
not silently assumed correct** — the same discipline this project
applied to the `CONFLICTING_GUIDANCE` discrepancy in ADR-018 Step 2.

### Step 2 — classify version status (exact-match only)

```
version_status =
    MATCH        if E.version_applicability == UNVERSIONED
    MATCH        if E.version_applicability == observed_version
                    (both non-None, exact string equality)
    UNCONFIRMED  otherwise (observed_version is None, or differs from
                    a version-specific E.version_applicability)
```

There is no `MISMATCH` version status — ADR-018 §2's own
`VERSION_UNCONFIRMED` definition already folds "does not exactly match a
version-specific entry" into itself ("...or does not exactly match a
version-specific entry, and nothing indicates the guidance is actually
wrong for this version"). A version-specific entry whose observed
version merely differs is not treated as "the wrong document" (that is
`EDITION_MISMATCH`'s job) — it is treated as unconfirmed, unless a
curator has separately registered it as outdated (Step 3).

### Step 3 — classify overlay relationship (supersession vs. caveat)

Collect **candidate overlays**: every `ReleaseOverlay` in
`_OVERLAY_REGISTRY[E's capability]` where `applies_to_edition` is
edition-compatible with `observed_edition` (same rule as Step 1, applied
to the overlay) **and** `applies_to_version` is `UNVERSIONED` or exactly
equals `observed_version`.

**Symmetry clarification, not a schema change**: the accepted
`ReleaseOverlay.applies_to_version` field has no validator restricting it
away from `UNVERSIONED` (confirmed by direct inspection of `evidence.py`
— no pattern, no enum constraint exists today). This procedure extends
`DocumentSource`'s existing `UNVERSIONED` convention to overlays for
symmetry (a general, version-independent caveat is a real, useful
registry-authoring pattern) — compatible with, not a change to, the
already-shipped `ReleaseOverlay` type.

For each candidate overlay `O`, follow `O.supersedes_id`'s chain (reusing
`applicability.find_supersession_chain_defects()`'s already-accepted
ancestor-walk, not a new traversal algorithm):

```
supersession_status =
    SUPERSEDED   if E's source_id/overlay_id appears anywhere in any
                    candidate overlay's supersedes_id ancestry
    CAVEATED     if not SUPERSEDED, and at least one candidate overlay
                    exists (regardless of its own supersedes_id target)
    NONE         if no candidate overlay exists at all
```

### Step 4 — final per-entry state (priority order, first match wins)

```
1. edition_status == MISMATCH          -> EDITION_MISMATCH
2. supersession_status == SUPERSEDED   -> STALE
3. edition_status in {MATCH, UNCONFIRMED}
   and version_status == UNCONFIRMED   -> VERSION_UNCONFIRMED
4. edition_status == MATCH
   and version_status == MATCH
   and supersession_status == CAVEATED -> PARTIALLY_APPLICABLE
5. edition_status == MATCH
   and version_status == MATCH
   and supersession_status == NONE     -> APPLICABLE
```

**Priority rationale, each grounded in the ADR text, not invented**:
`EDITION_MISMATCH` first — a confirmed wrong-edition document is the
single most definitive "not this document" signal, and nothing else
about it (version, overlays) is worth evaluating once that is known.
`STALE` second, ahead of the ordinary match/caveat branches — a
curator-registered supersession is an authoritative, reviewed fact about
currency, stronger than an unresolved version/edition question and
stronger than a mere caveat (an entry that is both matching and
known-superseded must never present as current). `VERSION_UNCONFIRMED`
is checked before `PARTIALLY_APPLICABLE`/`APPLICABLE` specifically so
that edition-uncertainty (Step 1's resolved gap) and version-uncertainty
both fail safe ahead of any favorable classification, regardless of
overlay state — an unconfirmed entry with a caveat is still fundamentally
unconfirmed, not "partially applicable with extra uncertainty." Every
combination of the three status values maps to exactly one branch above
— the table is total, not merely covering the cases the ADR's prose
happened to name.

### Step 5 — evidence-level cap (already-accepted, reused unchanged)

Apply `applicability.cap_applicability_by_evidence_level()` (Step 2,
already shipped) to the Step 4 result: `INFERRED_FROM_CURRENT_DOCS`/
`UNKNOWN` evidence levels cap `APPLICABLE`/`PARTIALLY_APPLICABLE` down to
`VERSION_UNCONFIRMED`; every other state passes through unchanged. This
is a **second, independent** fail-safe layer beneath Steps 1–4 — even a
hypothetical bug in the priority ordering above that reached `APPLICABLE`
incorrectly still cannot survive this cap unless the entry's own
`evidence_level` is genuinely `EXPLICIT_*`.

### `PARTIALLY_APPLICABLE`'s one precise meaning

**Overlay-caveat existence, and only that** — "the base document is
confirmed applicable (edition and version both match), but a
curator-registered `ReleaseOverlay` for this exact observed version/
edition documents that behavior differs in some way." Explicitly **not**:
partial semantic relevance (this schema has no notion of a document being
"part relevant" to a capability — a `DocumentSource` either is or isn't
registered for a capability), partial version-range overlap (no ranges
exist to partially overlap), or incomplete identity evidence (that is
`VERSION_UNCONFIRMED`'s job, entirely). Rejecting the other readings
explicitly, per the design task's own instruction not to leave this
state's meaning overloaded.

### `applicable_overlay_chain` for a single entry

When `supersession_status == SUPERSEDED`: the ordered chain from `E`
(most-superseded) through to the current-truth overlay, via
`applicability.order_overlay_chain()` (already accepted, unchanged).
When `CAVEATED`: the candidate overlay id(s) that produced the caveat,
in registry order (no supersession chain to order, since none supersedes
`E`). When `NONE`: `()`.

## Extended `lookup_guidance()`

```python
def lookup_guidance(
    capability: Capability,
    observed_version: str | None,
    observed_edition: ObservedEdition,
) -> tuple[GuidanceReference, ...]:
    """Same purity/determinism guarantee as ADR-017's original (I5/I6).

    Signature change from the v0.3.0-shipped version (Finding 1):
    observed_edition is now ObservedEdition, not Edition | None --
    ObservedEdition.UNKNOWN replaces the old None sentinel; Edition.BOTH
    can no longer be passed here at all, by construction.

    Behavior change from the v0.3.0-shipped version (requires its own
    explicit approval before this signature ships, per ADR-018 --
    listed here as the implementation-ready shape, not as already
    authorized): entries are no longer excluded on edition/version
    mismatch. Every registry entry for the capability is returned, each
    carrying its own computed ApplicabilityState. NO_OFFICIAL_GUIDANCE_FOUND
    is represented as a single synthetic GuidanceReference-shaped
    sentinel or as an empty tuple with the caller expected to treat ()
    as that state -- exact representation is an implementation choice
    for whichever session builds this, not fixed here.
    """
```

## `GuidanceEvidence` (orchestration, not a new tool)

```python
# Illustrative -- an orchestration function, not a class method on any
# existing object. Lives in the guidance package; takes plain values
# plus an ApplianceIdentity already resolved by the one canonical
# resolve_appliance_identity() call (Finding 10) -- not a PfSenseClient
# or transport directly (same "no network I/O capability given to this
# layer" rule ADR-017 already established; identity resolution is the
# caller's job, done once, upstream of this function).


def resolve_guidance_evidence(
    capability: Capability,
    identity: ApplianceIdentity,
) -> GuidanceEvidence: ...
```

```python
class GuidanceEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    observed_edition: ObservedEdition  # Finding 1
    observed_version: str | None
    appliance_identity_source: str  # copied from ApplianceIdentity.identity_source
    guidance: tuple[GuidanceReference, ...]
    overlay_chain: tuple[str, ...]  # Finding 6 -- ORDERED, most-superseded first,
    # current-truth last. Never an unordered set: preserves the full
    # correction history (base -> release note -> errata), not only
    # the final flattened conclusion.
    overall_state: ApplicabilityState
```

`overall_state` computation: the least-favorable state present among
`guidance`, using a fixed total ordering (most to least favorable):
`APPLICABLE` > `PARTIALLY_APPLICABLE` > `VERSION_UNCONFIRMED` >
`STALE` > `EDITION_MISMATCH` > `NO_OFFICIAL_GUIDANCE_FOUND`. Deterministic,
no ambiguity — a fixed, reviewable ordering, not a runtime heuristic.

**Note on the pseudocode above vs. what actually shipped**: this
illustrative sketch (written before implementation) shows
`GuidanceEvidence.guidance: tuple[GuidanceReference, ...]`. The actual
Step 2 implementation (`src/pfsense_mcp/guidance/evidence.py`) uses a
new, additive `EvidenceReference` type instead, deliberately not
modifying the shipped `GuidanceReference` (see `evidence.py`'s own module
docstring). `compose_guidance_evidence()` (Step 3,
`src/pfsense_mcp/guidance/composition.py`) is already built and consumes
`EvidenceReference`, not `GuidanceReference`. The
`GuidanceReference`→`EvidenceReference` bridge specified below is exactly
what reconciles this pseudocode's original vision with what actually
shipped.

## `GuidanceReference` → `EvidenceReference` bridge (specified, not implemented)

**This section is design only** — part of the same dedicated design pass
that produced the single-entry decision procedure above
(2026-08-09, `reports-ai/reviews/
ADR_018_APPLICABILITY_DECISION_PROCEDURE_RED_TEAM.md`). No code in this
section exists yet; building it is its own future, separately-authorized
implementation slice (see "Next implementation slice" below).

### Where the decision procedure actually runs

The single-entry decision procedure above is **not** part of this
bridge — it runs *inside* the future extended `lookup_guidance()`
(below), the one already-accepted assembly point for guidance lookup.
`lookup_guidance()` would return `GuidanceReference` objects that
**already carry** a computed `applicability: ApplicabilityState` (Steps
1–5 above already applied, replacing the current always-`False`
`version_mismatch: bool`). By the time a `GuidanceReference` reaches this
bridge, its classification is already final — the bridge performs **no
inference of its own**, only field reshaping. This keeps exactly one
inference path in the whole system (inside `lookup_guidance()`), not two
— directly closing the red-team's "second guidance inference path"
attack angle (see the red-team report).

### Field mapping — almost entirely mechanical, by construction

Comparing the extended `GuidanceReference` shape (this document's own
"`ApplicabilityState`" section, above) against the already-shipped
`EvidenceReference` (`evidence.py`) field-by-field: **13 of 14 fields
correspond exactly, 1:1, same name and type** — `capability`,
`source_id`, `title`, `canonical_url`, `content_excerpt`, `content_hash`,
`pfsense_edition`, `evidence_level`, `applicability`,
`applicable_overlay_chain`, `observed_edition_used`,
`observed_version_used`, `retrieval_mode`, `snapshot_version`. The
extended `GuidanceReference`'s `trust_label: str` field has no
`EvidenceReference` equivalent — **confirmed safe to drop, not silently
dropped**: `trust_label` is currently always the constant
`"pinned-snapshot"` for the only `retrieval_mode` that exists
(`BUNDLED_SNAPSHOT`), making it fully redundant with `retrieval_mode` in
the current accepted scope; if TB-G3 live retrieval is ever activated,
trust nuance would be expressed through `retrieval_mode`/`freshness_state`,
not a separate field, so no future information is lost by omitting it
now.

### Bridge properties (specified, for whoever implements it)

- **Pure function**, no I/O, no network, no clock read:
  `bridge_guidance_reference(ref: GuidanceReference) -> EvidenceReference`.
- **Cardinality: exactly one `EvidenceReference` per `GuidanceReference`
  — never zero, never multiple.** The bridge does not filter by
  `applicability` (e.g. it must not silently drop `EDITION_MISMATCH`
  entries) — filtering, if a future consumer ever wants it, is that
  consumer's own policy choice, applied *after* the bridge, never inside
  it. A bridge that filters is a bridge that makes a policy decision it
  has no business making.
- **What must never be invented**: the bridge must never default, guess,
  or widen any field — in particular, it must never recompute
  `applicability`/`evidence_level` independently of what
  `lookup_guidance()` already determined (no second inference path), and
  must never synthesize `content_excerpt`/`canonical_url`/`content_hash`
  from anything but the source `GuidanceReference`'s own already-reviewed
  values.
- Applied to an empty `tuple[GuidanceReference, ...]` (the
  `NO_OFFICIAL_GUIDANCE_FOUND` case — no registry entry for the
  capability), the bridge naturally produces an empty
  `tuple[EvidenceReference, ...]` — **no special-case branch needed**;
  `compose_guidance_evidence()` (already shipped, Step 3) already computes
  `overall_state = NO_OFFICIAL_GUIDANCE_FOUND` from `compute_overall_state(())`
  when handed an empty `guidance` tuple. This is exactly ADR-018's
  Acceptance-record deferred question #2, confirmed formally closed by
  this design pass — see ADR-018's own "Acceptance record" section,
  updated to reflect this.

## TB-G3 live retrieval — resolved design (not activated)

**Fixed after red-team review (Finding 2, BLOCKING — read this before
anything else in this section)**: the first draft described a
successful presence check as confirming the reviewed text is "still
there, unchanged." **This overclaims.** Substring presence proves only
that the pinned string occurs *somewhere* in the fetched page — it
proves nothing about surrounding context, and cannot distinguish "the
original passage, intact" from "the same string duplicated elsewhere
while the original was altered." The design's actual safety property:
because **only the pre-approved, bounded excerpt is ever returned to a
consumer — never the live page's surrounding text, regardless of
presence-check outcome** — context-duplication and misleading-context
attacks are foreclosed by *never reading page context into anything
consumer-facing*, not by the presence check "verifying" them. The
presence check's real job: decide whether to serve the pinned excerpt
(present → serve exactly the already-reviewed text) or fall back
(absent → the reviewed claim may no longer hold at that URL).

```python
class RetrievalMode(str, Enum):
    BUNDLED_SNAPSHOT = "bundled_snapshot"
    LIVE_FETCH_CACHED = "live_fetch_cached"  # newly named; still inert until activated


_LIVE_FETCH_MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024  # 2 MB, enforced on the
# DECOMPRESSED stream incrementally -- Finding 3(2): a Content-Length
# check alone does not bound a decompression-bomb response.
_LIVE_FETCH_TIMEOUT_SECONDS = 10
_LIVE_FETCH_MAX_REDIRECTS = 3  # Finding 3(1)
_LIVE_FETCH_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h default, revisit with evidence
_ALLOWED_CONTENT_TYPES = frozenset({"text/html", "text/plain"})  # Finding 3(3)


def _verify_excerpt_still_present(pinned_excerpt: str, fetched_text: str) -> bool:
    """Textual presence only -- NOT a content-authenticity, context-
    integrity, or tamper-proof check (Finding 2). NFC-normalize both
    sides; case-sensitive; no confusable/homoglyph folding of any kind;
    no fuzzy match, no partial-match scoring. Returns False on any
    non-exact result; False means "drift detected," never "probably
    fine."
    """
```

Fetch discipline (all required, none optional, before this mode is ever
activated):

- Fetch exactly `canonical_url` from the existing registry entry — never
  a derived, templated, or search-resolved URL.
- **A transport instance entirely separate from `pfsense_client.py`'s
  pfSense-facing transport** (Finding 4, MATERIAL) — no shared client,
  session, connection pool, cookie jar, or default-header configuration;
  the pfSense API key or any `PFSENSE_*` credential must never be
  attachable to a documentation-host request under any circumstance.
- HTTPS only; TLS verification always on; no equivalent of an
  `insecure`/`verify=False` flag anywhere in this path.
- **DNS rebinding defense** (Finding 3(4), MATERIAL): resolve the
  hostname once, validate the resolved address is public (reject
  private/loopback/link-local ranges) *before* connecting — a hostname
  allow-list alone does not bind the IP actually connected to.
- Redirects: follow up to `_LIVE_FETCH_MAX_REDIRECTS` hops; **the final
  URL must equal the registered `canonical_url` exactly** (Finding
  3(1), MATERIAL — not merely "same allow-listed host," which would
  accept a same-host redirect to an entirely different, unreviewed
  page). Any deviation aborts the fetch — do not return
  partial/redirected content, do not silently follow.
- `Content-Type` must be in `_ALLOWED_CONTENT_TYPES` before any parse is
  attempted (Finding 3(3)); anything else aborts the fetch.
- Enforce `_LIVE_FETCH_MAX_DECOMPRESSED_BYTES` on the decompressed
  stream incrementally as it is read — abort the moment the running
  total exceeds the bound, not only against a pre-decompression
  `Content-Length` header (Finding 3(2)) — and `_LIVE_FETCH_TIMEOUT_SECONDS`.
- Extract visible text only (no script/style content); run
  `_verify_excerpt_still_present`. On `False`: `freshness_state =
  "drift_detected"`, fall back to the bundled snapshot for that entry if
  present, else treat as `NO_OFFICIAL_GUIDANCE_FOUND` for that entry.
- On success: cache `(content, fetched_at)` in-memory, keyed by
  `source_id`, honoring `_LIVE_FETCH_CACHE_TTL_SECONDS`; `freshness_state
  = "fresh"` while within TTL, `"stale_cache"` past it (still served,
  clearly labeled, until the next successful re-fetch — never silently
  treated as fresh). TTL/freshness comparisons use a monotonic clock,
  not wall-clock `datetime.now()`, so a system clock anomaly cannot make
  a cache entry appear artificially fresh or immediately stale. A cached
  result's `ApplicabilityState` is never upgraded merely because it is
  cached — caching affects only `freshness_state`/`retrieval_mode`
  metadata, never the applicability computation itself.
- Any transport failure (connection error, timeout, non-2xx, TLS failure,
  disallowed redirect, disallowed content type, size-bound exceeded,
  DNS-rebinding rejection): same fallback chain as a drift result. Never
  raises past this boundary — same I6 discipline as the rest of the
  guidance layer.
- Process restart clears the cache entirely (in-memory only, no disk
  persistence) — every restart begins from bundled-snapshot-only until
  the first live fetch succeeds again.

## Failure modes (new/changed from `OFFICIAL_GUIDANCE_LAYER.md`'s table)

| Failure | Detection | Result |
|---|---|---|
| Appliance version string outside both known CE/Plus ranges | `infer_edition_from_version_base()`'s explicit range check | Returns `ObservedEdition.UNKNOWN` — feeds the existing edition-unknown fail-closed path |
| Live fetch's page no longer contains the pinned excerpt verbatim | `_verify_excerpt_still_present()` returns False | `freshness_state = "drift_detected"`; fall back to bundled snapshot or `NO_OFFICIAL_GUIDANCE_FOUND` — never described as "tampering detected," only as "reviewed claim unconfirmed" (Finding 2) |
| Live fetch's final URL is on an allow-listed host but not the exact registered `canonical_url` | Final-URL exact-match re-check | Fetch aborted; same fallback chain as drift (Finding 3(1)) |
| Live fetch response is compressed and decompresses past the size bound | Incremental decompressed-stream size check | Fetch aborted mid-stream; same fallback chain (Finding 3(2)) |
| Live fetch `Content-Type` is not HTML/text | Header check before parse | Fetch aborted; same fallback chain (Finding 3(3)) |
| Hostname resolves to a private/loopback/link-local address | Pre-connect resolved-address check | Fetch aborted; same fallback chain (Finding 3(4)) |
| Two registry entries (`DocumentSource` and/or `ReleaseOverlay`, any combination) share capability, edition-compatible scope, and overlapping version scope, and are not connected by any `supersedes_id` relationship | Extended `_check_registry_integrity()`, duplicate-scope check (Finding 8) | Import fails loudly — a registry-authoring defect, never served |
| A `supersedes_id` value does not resolve to any known `source_id`/`overlay_id` (dangling reference) | Extended `_check_registry_integrity()`, chain-integrity check (Finding 6/8) | Import fails loudly |
| A `supersedes_id` chain cycles (A supersedes B supersedes A) | Extended `_check_registry_integrity()`, chain-integrity check (Finding 6/8) | Import fails loudly |
| `ReleaseOverlay.applies_to_version` does not exactly match observed version | Explicit closed-set comparison, same I3 discipline as `DocumentSource` | Overlay excluded from `overlay_chain`, not fabricated as approximately-relevant |
| An entry's `evidence_level` is `INFERRED_FROM_CURRENT_DOCS` | Explicit check in `ApplicabilityState` computation | Capped at `VERSION_UNCONFIRMED`, never `APPLICABLE` (Finding 5) |

## Non-goals (extends `OFFICIAL_GUIDANCE_LAYER.md`'s list)

- Does not implement a config-revision-aware identity model — no
  reliable existing READ source for it was found (ADR-018).
- Does not activate `lookup_guidance()`'s exclude→include policy change,
  live retrieval, or any wiring — each requires its own explicit
  approval per "Activation requirements" below, matching ADR-017's own
  pattern exactly.
- Does not add a vector database, embeddings, or unrestricted search —
  explicitly ruled out per the owner's instruction and re-confirmed in
  ADR-018's "Alternatives considered" and re-confirmed again in
  red-team review.
- Does not let `GuidanceEvidence`/`ApplicabilityState` be read by
  `state_machine.py`'s transition-rule table or by
  `confirmation_authority.md`'s digest computation, under any future
  wiring decision (Finding 7) — this is a hard non-goal, not a
  configuration choice.

## Activation requirements

None of the following are granted by this document or by ADR-018's
Proposed status. Each is its own future decision, exactly mirroring
`OFFICIAL_GUIDANCE_LAYER.md`'s existing checklist pattern:

- [ ] **ADR-018 acceptance itself** — currently Proposed, not Accepted.
- [ ] **`lookup_guidance()` exclude→include policy change** — a real
      behavior change to shipped v0.3.0 code; needs its own explicit
      approval separate from ADR-018's acceptance.
- [ ] **Live retrieval (TB-G3) activation** — this document resolves the
      design ADR-017 deferred, but activation is still its own decision,
      exactly as `OFFICIAL_GUIDANCE_LAYER.md` already required.
- [ ] **Any READ-tool or PREPARE wiring** — same approval bar
      `OFFICIAL_GUIDANCE_LAYER.md` already set; Phase 5 gates apply to
      any PREPARE wiring specifically; the AND-veto-only structural rule
      (Finding 7) applies to any PREPARE wiring without exception.

## Implementation checklist (for whichever future session builds the inert scaffolding)

- [ ] `appliance_identity.py`: `ObservedEdition`, `infer_edition_from_version_base()`
      (pure, no imports outside `guidance/models.py`), `ApplianceIdentity`,
      `resolve_appliance_identity()` (Finding 10 — the one canonical
      assembly point; no other module may reimplement this assembly).
- [ ] `ApplicabilityState`, `EvidenceLevel`, `ReleaseOverlay` added to
      `guidance/models.py` with the same `extra="forbid"`/bounded-field/
      allow-listed-host discipline every existing model in that module
      already has.
- [ ] `_OVERLAY_REGISTRY` as a new, separate, empty-by-default dict —
      empty is the correct starting state, same as `_REGISTRY` and
      `WriteEndpoints` before their first real entry.
- [ ] `_check_registry_integrity()` extended per Finding 8's concrete,
      two-part definition: (1) duplicate-scope check — same-capability,
      edition-compatible, overlapping-version entries with no
      `supersedes_id` relationship connecting them; (2) chain-integrity
      check, independent of (1) — dangling `supersedes_id` references
      and cycle detection.
- [ ] Isolation test extended: the new module(s) still import none of
      `pfsense_mcp.tier1`, `write_endpoints`, `rest_api_client`,
      `write_api_client`, `transport`; still imported by nothing outside
      the guidance package.
- [ ] A dedicated test asserting `GuidanceEvidence`/`ApplicabilityState`
      are never read by `state_machine.py` or
      `confirmation_authority.md`'s digest computation (Finding 7) — an
      AST/import-graph check, the same style as the existing isolation
      tests, not a runtime assertion.
- [ ] Deterministic-mapping tests for `infer_edition_from_version_base()`:
      every known CE major (1, 2), every known Plus year range boundary
      (21, 99), and at least one out-of-range value returning
      `ObservedEdition.UNKNOWN`.
- [ ] `GuidanceEvidence.overall_state` ordering tested explicitly for
      every pairwise combination, not just the happy path.
- [ ] `EvidenceLevel` cap test: an `INFERRED_FROM_CURRENT_DOCS` entry
      with a matching edition never reaches `APPLICABLE`.
- [ ] TB-G3 (once ever activated, separately): decompression-bomb test
      (compressed payload under the raw bound, decompressed payload
      over it, must abort mid-stream); exact-canonical-URL-after-redirect
      test; disallowed-Content-Type test; DNS-rebinding-simulation test;
      transport-separation test (assert no shared client/session/headers
      with `pfsense_client.py`'s transport).

**Status of the items above, as of 2026-08-09**: `appliance_identity.py`
(ADR-018 Step 1), `EvidenceLevel`/`ApplicabilityState`/`ReleaseOverlay`/
`EvidenceReference` and the deterministic primitives (ADR-018 Step 2),
and `compose_guidance_evidence()` (ADR-018 Step 3) are all implemented,
tested, and pushed — this checklist predates that work and is retained
here as historical design intent, not a current TODO list. The
`_OVERLAY_REGISTRY`/extended-`_check_registry_integrity()`/extended-
`lookup_guidance()` items remain genuinely unbuilt; see the next section
for the precise, bounded next slice.

## Next implementation slice: the `GuidanceReference` → `EvidenceReference` bridge (specified, not implemented)

**Not authorized by this design pass** — this section exists so a future,
separately-authorized implementation session has an exact, bounded scope
to build against, matching the same level of precision Step 1/2/3's own
STOP-gate reports gave their respective next steps.

### Exact scope

1. Extend `guidance/models.py`'s `GuidanceReference`: replace
   `version_mismatch: bool` with `applicability: ApplicabilityState`
   (imported from `evidence.py`); add `evidence_level: EvidenceLevel`,
   `applicable_overlay_chain: tuple[str, ...]`,
   `observed_edition_used: ObservedEdition`,
   `observed_version_used: str | None`. **This is the "real behavior
   change to already-shipped v0.3.0 code" ADR-018 §2 already flags as
   needing its own explicit approval separate from ADR-018's own
   acceptance** — building this requires that approval, not implied by
   accepting this design document.
2. Add `_OVERLAY_REGISTRY: dict[Capability, tuple[ReleaseOverlay, ...]]`
   to `registry.py`, empty by default (same starting state as
   `_REGISTRY` and `WriteEndpoints` before their first real entry).
3. Implement the single-entry decision procedure specified above (Steps
   1–5) as pure functions in `applicability.py`, reusing
   `cap_applicability_by_evidence_level()`/`find_supersession_chain_defects()`/
   `order_overlay_chain()` unchanged — replacing
   `applicability_state_for_entry_is_not_implemented_here()`'s marker
   with the real implementation.
4. Extend `_check_registry_integrity()` per ADR-018 Finding 8's two
   independent checks, now covering `_OVERLAY_REGISTRY` too (this was
   already specified in this document's "Implementation checklist"
   above, unchanged by this design pass).
5. Extend `lookup_guidance()` itself to call the Step-3 procedure per
   entry and stop excluding non-matching entries (the "exclude→include"
   policy change) — this is the same already-flagged behavior change as
   item 1, requiring its own explicit approval.
6. Build `bridge_guidance_reference()` (new function, exact location TBD
   by whoever implements it — a natural candidate is a new
   `guidance/bridge.py`, mirroring `composition.py`'s one-function-one-
   file pattern) per the bridge specification above — pure, no I/O,
   1:1 cardinality, no independent inference.

### Required tests (specified, not written)

- Every branch of Steps 1–4's decision table exercised individually
  (all 5 terminal states, plus every intermediate `edition_status`/
  `version_status`/`supersession_status` combination that maps to each) —
  table-driven, matching `test_applicability.py`'s existing style for
  `may_prepare()`'s exhaustive truth table.
- The Step 1 edition-UNCONFIRMED resolution specifically: an
  edition-specific entry with `observed_edition = UNKNOWN` produces
  `VERSION_UNCONFIRMED`, not an exception and not any other state.
- `PARTIALLY_APPLICABLE` vs. `STALE` priority: an entry with both a
  superseding overlay and a merely-caveating overlay (from two different
  `ReleaseOverlay` entries) produces `STALE`, never
  `PARTIALLY_APPLICABLE`.
- The evidence-level cap (Step 5) still holds after the new procedure
  feeds it — regression test against Step 2's existing
  `cap_applicability_by_evidence_level()` test suite, unchanged.
- `bridge_guidance_reference()`: 1:1 cardinality (never zero, never
  multiple, for a single input); every field except `trust_label`
  copied exactly, byte-for-byte equal on the output; applied to an
  extended `GuidanceReference` whose `applicability` is
  `EDITION_MISMATCH` still produces exactly one `EvidenceReference`
  (proves the bridge does not filter).
- Applying the bridge to the extended `lookup_guidance()`'s empty-tuple
  result (`NO_OFFICIAL_GUIDANCE_FOUND` case) produces an empty
  `EvidenceReference` tuple, and `compose_guidance_evidence()` given that
  empty tuple still produces `overall_state ==
  NO_OFFICIAL_GUIDANCE_FOUND` — an explicit end-to-end regression test
  tying Steps 2/3's already-shipped behavior to this new slice.
- Isolation tests, same discipline as every prior step: the new/extended
  modules import nothing from `tier1`/`write_endpoints`/
  `rest_api_client`/`pfsense_client`/`transport`/`api_surface`/`tools`;
  `state_machine.py`/every confirmation-digest module still imports
  nothing from `guidance` (TB-G4, re-run, not merely re-asserted);
  public 42-tool contract unchanged; WRITE state unchanged.

### Invariants this slice must preserve (carried forward from this design pass, not new)

`ApplianceIdentity` and `resolve_appliance_identity()` remain the one
identity assembly point — the decision procedure and the bridge both
only ever *consume* an already-resolved identity, never re-derive one.
`GuidanceEvidence`/`compose_guidance_evidence()` are unmodified by this
slice — the bridge produces `EvidenceReference` values that flow into the
*already-shipped, unchanged* composition function. Guidance remains
evidence, never authorization — no new state, field, or function this
slice adds may be read by `may_prepare()`, `state_machine.py`, or any
confirmation-digest computation. No new runtime dispatch — the decision
procedure is a fixed sequence of guard checks over closed-enum values,
never a `method=`/`getattr`-style branch. Exact-match-only version
semantics preserved — no range/min/max grammar introduced.

## References

`docs/adr/ADR-018-version-aware-guidance-resolution.md` (the decision this
implements), `docs/OFFICIAL_GUIDANCE_LAYER.md` (ADR-017's companion,
whose TB-G3/edition self-challenge this resolves),
`docs/tier1/specs/capability_adapter_contract.md` (the eventual PREPARE
integration point), `reports-ai/reviews/ADR_018_RED_TEAM.md` (the
independent review that produced every "Fixed after red-team review"
note in this document).
