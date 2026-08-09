# Version-aware Official Guidance resolution — implementation-ready spec

Companion spec to `docs/adr/ADR-018-version-aware-guidance-resolution.md`,
mirroring `OFFICIAL_GUIDANCE_LAYER.md`'s relationship to ADR-017. Read the
ADR first — it carries the decision, the resolved TB-G3 design question,
and the self-challenges. This document is the implementation-ready shape
for whichever future session builds the parts ADR-018 authorizes as inert
scaffolding (not the parts it explicitly leaves deferred/unactivated).

**Nothing in this document is implemented.** Like `OFFICIAL_GUIDANCE_LAYER.md`
before ADR-017's acceptance, this specifies enough to remove ambiguity at
build time without asserting any of it is built yet.

## Purpose

Let a future consumer (an AI client via some future tool, or a Tier 1
PREPARE phase) answer: "for this capability, on the appliance actually
observed, what official guidance applies, and how confidently?" — instead
of silently assuming `/latest/` documentation universally applies.

## Scope boundary (what this spec covers vs. does not)

Covers: appliance-identity inference, `ApplicabilityState`,
`ReleaseOverlay`, the extended `lookup_guidance()` shape, `GuidanceEvidence`
composition, and the resolved (but not activated) TB-G3 live-retrieval
design.

Does not cover: any READ tool schema change, any Tier 1 PREPARE wiring,
any new public MCP tool. Each is a separate, later, explicitly-approved
activation per ADR-018's "Activation requirements" below.

## Appliance identity resolution

```python
# src/pfsense_mcp/guidance/appliance_identity.py (not yet created)

from .models import Edition

_CE_MAX_MAJOR = 9  # pfSense CE has used 1.x/2.x to date; documented
# <major>.<minor>.<patch> scheme, never observed >= 10
_PLUS_MIN_YEAR = 21  # pfSense Plus's year-based scheme began 2021


def infer_edition_from_version_base(base: str) -> Edition | None:
    """Infer pfSense edition from SystemVersion.base's version-string
    shape, per Netgate's own documented CE (<major>.<minor>.<patch>) vs.
    Plus (<year>.<month>.<patch>) numbering schemes -- see ADR-018.
    Never a network call: operates on a string the caller already has
    from an existing pfsense_get_system_version call.

    Returns None (unknown) on any value outside both known ranges --
    never guesses. This is the single function any future consumer
    calls; it must not be reimplemented elsewhere (ADR-018's "no
    duplicated parallel source of truth" requirement, same discipline
    already applied to WriteEndpoints.active_entries() in v0.3.1).
    """
    first_component = base.split(".", 1)[0]
    if not first_component.isdigit():
        return None
    major = int(first_component)
    if 1 <= major <= _CE_MAX_MAJOR:
        return Edition.CE
    if _PLUS_MIN_YEAR <= major <= 99:
        return Edition.PLUS
    return None
```

**No new capability, no new READ tool.** Callers obtain `base` from the
existing `pfsense_get_system_version` tool's already-shipped
`SystemVersion.base` field.

## `ApplicabilityState`

```python
# src/pfsense_mcp/guidance/models.py (extends the existing module)


class ApplicabilityState(str, Enum):
    APPLICABLE = "applicable"
    PARTIALLY_APPLICABLE = "partially_applicable"
    VERSION_UNCONFIRMED = "version_unconfirmed"
    EDITION_MISMATCH = "edition_mismatch"
    STALE = "stale"
    NO_OFFICIAL_GUIDANCE_FOUND = "no_official_guidance_found"
    # CONFLICTING_GUIDANCE is deliberately NOT a member -- see ADR-018
    # "ApplicabilityState" section. It is a registry-integrity build/test
    # failure, not a runtime-returned state.
```

`GuidanceReference` gains (replacing `version_mismatch: bool`):

```python
class GuidanceReference(BaseModel):
    # ... existing fields unchanged ...
    applicability: ApplicabilityState  # replaces version_mismatch
    applicable_overlays: tuple[str, ...]  # ReleaseOverlay.overlay_id values, () if none
    observed_edition_used: Edition | None  # echoes the input, for auditability
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
    supersedes_source_id: str | None
    caveat_excerpt: str = Field(max_length=MAX_EXCERPT_LENGTH)
    canonical_url: str  # same ALLOWED_DOCUMENT_HOSTS validator as DocumentSource
    content_hash: str

    @field_validator("canonical_url")
    @classmethod
    def _check_canonical_url(cls, value: str) -> str:
        return _validate_canonical_url(value)
```

Registered in a new, separate, Git-tracked dict — not merged into
`_REGISTRY` — so a registry maintainer authoring a `DocumentSource` never
has to reason about overlay entries in the same review pass:

```python
_OVERLAY_REGISTRY: dict[Capability, tuple[ReleaseOverlay, ...]] = {}
```

## Extended `lookup_guidance()`

```python
def lookup_guidance(
    capability: Capability,
    observed_version: str | None,
    observed_edition: Edition | None,
) -> tuple[GuidanceReference, ...]:
    """Same purity/determinism guarantee as ADR-017's original (I5/I6).

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
# existing object. Lives in the guidance package; takes plain values,
# not a PfSenseClient or transport (same "no network I/O capability
# given to this layer" rule ADR-017 already established).


def resolve_guidance_evidence(
    capability: Capability,
    observed_version: str | None,
    observed_edition: Edition | None,
) -> GuidanceEvidence: ...
```

```python
class GuidanceEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    observed_edition: Edition | None
    observed_version: str | None
    appliance_identity_source: str  # e.g. "SystemVersion.base (pfsense_get_system_version)"
    guidance: tuple[GuidanceReference, ...]
    overlays_considered: tuple[str, ...]  # ReleaseOverlay.overlay_id values
    overall_state: ApplicabilityState
```

`overall_state` computation: the least-favorable state present among
`guidance`, using a fixed total ordering (most to least favorable):
`APPLICABLE` > `PARTIALLY_APPLICABLE` > `VERSION_UNCONFIRMED` >
`STALE` > `EDITION_MISMATCH` > `NO_OFFICIAL_GUIDANCE_FOUND`. Deterministic,
no ambiguity — a fixed, reviewable ordering, not a runtime heuristic.

## TB-G3 live retrieval — resolved design (not activated)

```python
class RetrievalMode(str, Enum):
    BUNDLED_SNAPSHOT = "bundled_snapshot"
    LIVE_FETCH_CACHED = "live_fetch_cached"  # newly named; still inert until activated


_LIVE_FETCH_MAX_BYTES = 2 * 1024 * 1024  # 2 MB hard bound
_LIVE_FETCH_TIMEOUT_SECONDS = 10
_LIVE_FETCH_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h default, revisit with evidence


def _verify_excerpt_still_present(pinned_excerpt: str, fetched_text: str) -> bool:
    """The TB-G3 hash-comparison problem's resolution (ADR-018): exact
    substring presence, not hash equality against a full page. Case-
    sensitive, whitespace-normalized comparison only -- no fuzzy match,
    no partial-match scoring. Returns False on any non-exact result;
    False means "drift detected," never "probably fine."
    """
```

Fetch discipline (all required, none optional, before this mode is ever
activated):

- Fetch exactly `canonical_url` from the existing registry entry — never
  a derived, templated, or search-resolved URL.
- HTTPS only; TLS verification always on; no equivalent of an
  `insecure`/`verify=False` flag anywhere in this path.
- Redirects: capture the final URL after following; if the final host is
  outside `ALLOWED_DOCUMENT_HOSTS`, abort — do not return partial/redirected
  content, do not silently follow.
- Enforce `_LIVE_FETCH_MAX_BYTES` and `_LIVE_FETCH_TIMEOUT_SECONDS` before
  attempting any parse.
- Extract visible text only (no script/style content); run
  `_verify_excerpt_still_present`. On `False`: `freshness_state =
  "drift_detected"`, fall back to the bundled snapshot for that entry if
  present, else treat as `NO_OFFICIAL_GUIDANCE_FOUND` for that entry.
- On success: cache `(content, fetched_at)` in-memory, keyed by
  `source_id`, honoring `_LIVE_FETCH_CACHE_TTL_SECONDS`; `freshness_state
  = "fresh"` while within TTL, `"stale_cache"` past it (still served,
  clearly labeled, until the next successful re-fetch — never silently
  treated as fresh).
- Any transport failure (connection error, timeout, non-2xx, TLS failure):
  same fallback chain as a drift result. Never raises past this
  boundary — same I6 discipline as the rest of the guidance layer.

## Failure modes (new/changed from `OFFICIAL_GUIDANCE_LAYER.md`'s table)

| Failure | Detection | Result |
|---|---|---|
| Appliance version string outside both known CE/Plus ranges | `infer_edition_from_version_base()`'s explicit range check | Returns `None` (edition unknown) — feeds the existing edition-unknown fail-closed path |
| Live fetch's page no longer contains the pinned excerpt verbatim | `_verify_excerpt_still_present()` returns False | `freshness_state = "drift_detected"`; fall back to bundled snapshot or `NO_OFFICIAL_GUIDANCE_FOUND` |
| Live fetch redirects outside `ALLOWED_DOCUMENT_HOSTS` | Final-URL host re-check | Fetch aborted; same fallback chain as drift |
| Live fetch exceeds size/timeout bound | Enforced before parse | Fetch aborted; same fallback chain |
| Two registry entries for the same capability/edition/version overlap with materially different content | Extended `_check_registry_integrity()` | Import fails loudly — a registry-authoring defect (`CONFLICTING_GUIDANCE`'s build-time equivalent), never served |
| `ReleaseOverlay.applies_to_version` does not exactly match observed version | Explicit closed-set comparison, same I3 discipline as `DocumentSource` | Overlay excluded from `overlays_considered`, not fabricated as approximately-relevant |

## Non-goals (extends `OFFICIAL_GUIDANCE_LAYER.md`'s list)

- Does not implement a config-revision-aware identity model — no
  reliable existing READ source for it was found (ADR-018).
- Does not activate `lookup_guidance()`'s exclude→include policy change,
  live retrieval, or any wiring — each requires its own explicit
  approval per "Activation requirements" below, matching ADR-017's own
  pattern exactly.
- Does not add a vector database, embeddings, or unrestricted search —
  explicitly ruled out per the owner's instruction and re-confirmed in
  ADR-018's "Alternatives considered."

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
      any PREPARE wiring specifically.

## Implementation checklist (for whichever future session builds the inert scaffolding)

- [ ] `appliance_identity.py`: `infer_edition_from_version_base()`, pure,
      no imports outside `guidance/models.py`.
- [ ] `ApplicabilityState`, `ReleaseOverlay` added to `guidance/models.py`
      with the same `extra="forbid"`/bounded-field/allow-listed-host
      discipline every existing model in that module already has.
- [ ] `_OVERLAY_REGISTRY` as a new, separate, empty-by-default dict —
      empty is the correct starting state, same as `_REGISTRY` and
      `WriteEndpoints` before their first real entry.
- [ ] Isolation test extended: the new module(s) still import none of
      `pfsense_mcp.tier1`, `write_endpoints`, `rest_api_client`,
      `write_api_client`, `transport`; still imported by nothing outside
      the guidance package.
- [ ] Deterministic-mapping tests for `infer_edition_from_version_base()`:
      every known CE major (1, 2), every known Plus year range boundary
      (21, 99), and at least one out-of-range value returning `None`.
- [ ] `GuidanceEvidence.overall_state` ordering tested explicitly for
      every pairwise combination, not just the happy path.

## References

`docs/adr/ADR-018-version-aware-guidance-resolution.md` (the decision this
implements), `docs/OFFICIAL_GUIDANCE_LAYER.md` (ADR-017's companion,
whose TB-G3/edition self-challenge this resolves),
`docs/tier1/specs/capability_adapter_contract.md` (the eventual PREPARE
integration point).
