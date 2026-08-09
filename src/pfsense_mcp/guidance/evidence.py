"""Version-aware Official Guidance evidence model (ADR-018, Accepted --
architecture and trust boundaries only; step 2 of its implementation:
the offline evidence model, still entirely inert, no consumer wired).

Deliberately does not modify `models.GuidanceReference` or
`registry.lookup_guidance()` -- extending those is its own,
separately-gated "exclude vs. exclude-with-state" policy change
(`VERSION_AWARE_GUIDANCE.md`'s own explicit note: "requires its own
explicit approval before this signature ships"), not granted by
ADR-018's acceptance or by this step. `EvidenceReference` here is a new,
additive type -- structurally similar to what `VERSION_AWARE_GUIDANCE.md`
described as an amended `GuidanceReference`, under a distinct name so
nothing about the already-shipped v0.3.0 guidance registry is touched.

Reuses `Edition`, `RetrievalMode`, and the shared field-bound/allow-list
validators from `.models` -- the same single-source-of-truth discipline
already applied throughout this package. Reuses `ObservedEdition` from
`.appliance_identity` for observed-appliance fields; never reuses
`Edition` for that purpose (ADR-018 Finding 1).

No field here is a capability, endpoint, HTTP method, or confirmation
token (G1, unchanged). No field carries arbitrary live page text --
`content_excerpt`/`caveat_excerpt` are the same bounded, curated,
Git-reviewed strings `DocumentSource.content_excerpt` already is,
never a live fetch result (TB-G3 remains unactivated; nothing here
performs, or is capable of performing, network I/O).
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .appliance_identity import ObservedEdition
from .models import (
    MAX_EXCERPT_LENGTH,
    MAX_TITLE_LENGTH,
    SOURCE_ID_PATTERN,
    Edition,
    RetrievalMode,
    _validate_canonical_url,
)


class EvidenceLevel(str, Enum):
    """How the registry curator came to know a document's version
    scope -- orthogonal to `ApplicabilityState` (ADR-018 Finding 5).

    `EXPLICIT_VERSION_SCOPED`: the source explicitly states which
    version(s) this applies to.
    `EXPLICIT_UNVERSIONED`: the source explicitly states it applies
    regardless of version -- a real, affirmative claim, not silence.
    `INFERRED_FROM_CURRENT_DOCS`: an undated/`/latest/`-only page with
    no stated version scope at all -- the honest default for most
    real-world entries; must never be treated as equivalent to
    `EXPLICIT_UNVERSIONED`.
    `UNKNOWN`: evidence strength itself could not be established.
    """

    EXPLICIT_VERSION_SCOPED = "explicit_version_scoped"
    EXPLICIT_UNVERSIONED = "explicit_unversioned"
    INFERRED_FROM_CURRENT_DOCS = "inferred_from_current_docs"
    UNKNOWN = "unknown"


class ApplicabilityState(str, Enum):
    """Closed, fail-safe applicability classification (ADR-018 S2).

    Exactly the six members ADR-018's accepted text defines.
    `CONFLICTING_GUIDANCE` is deliberately **not** a member here --
    ADR-018's own accepted design treats a registry-authoring conflict
    as a load-time integrity defect (see `applicability.py`'s
    `find_duplicate_scope_conflicts()`/`find_supersession_chain_defects()`),
    not a per-lookup runtime state, because the registry is Git-tracked
    and PR-reviewed (TB-G1): a conflict is caught before any lookup ever
    runs, not represented as an answer a lookup can return. This is
    implemented exactly per the accepted ADR text; see the accompanying
    implementation report for the discrepancy this creates against a
    later informal restatement that listed CONFLICTING_GUIDANCE as an
    ApplicabilityState member, flagged rather than silently resolved
    either way.
    """

    APPLICABLE = "applicable"
    PARTIALLY_APPLICABLE = "partially_applicable"
    VERSION_UNCONFIRMED = "version_unconfirmed"
    EDITION_MISMATCH = "edition_mismatch"
    STALE = "stale"
    NO_OFFICIAL_GUIDANCE_FOUND = "no_official_guidance_found"


#: Most-favorable to least-favorable, used by
#: `applicability.compute_overall_state()`. Fixed, reviewable, never a
#: runtime heuristic (ADR-018 S5).
APPLICABILITY_STATE_ORDER: tuple[ApplicabilityState, ...] = (
    ApplicabilityState.APPLICABLE,
    ApplicabilityState.PARTIALLY_APPLICABLE,
    ApplicabilityState.VERSION_UNCONFIRMED,
    ApplicabilityState.STALE,
    ApplicabilityState.EDITION_MISMATCH,
    ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND,
)


class ReleaseOverlay(BaseModel):
    """A Git-tracked, PR-reviewed release-note/errata entry that may
    supersede a `DocumentSource` or another `ReleaseOverlay` (ADR-018
    Finding 6) -- same trust model as `DocumentSource`: never
    constructed from request-time input, same bounded-field/
    allow-listed-host discipline.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    overlay_id: str = Field(pattern=SOURCE_ID_PATTERN)
    capability: str
    applies_to_version: str
    applies_to_edition: Edition
    evidence_level: EvidenceLevel
    supersedes_id: str | None = Field(
        default=None,
        description="A DocumentSource.source_id or another ReleaseOverlay.overlay_id -- both share SOURCE_ID_PATTERN.",
    )
    caveat_excerpt: str = Field(max_length=MAX_EXCERPT_LENGTH)
    canonical_url: str
    content_hash: str

    @field_validator("canonical_url")
    @classmethod
    def _check_canonical_url(cls, value: str) -> str:
        return _validate_canonical_url(value)

    @field_validator("content_hash")
    @classmethod
    def _check_content_hash_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("content_hash must be a lowercase hex sha256 digest")
        return value

    @field_validator("supersedes_id")
    @classmethod
    def _check_supersedes_id_shape(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(SOURCE_ID_PATTERN, value):
            raise ValueError("supersedes_id must match SOURCE_ID_PATTERN when set")
        return value


class EvidenceReference(BaseModel):
    """One capability's resolved evidence for one registry entry --
    additive counterpart to `models.GuidanceReference`, not a
    replacement (see module docstring). No field here is a capability,
    endpoint, HTTP method, or confirmation token (G1, unchanged).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    source_id: str = Field(pattern=SOURCE_ID_PATTERN)
    title: str = Field(max_length=MAX_TITLE_LENGTH)
    canonical_url: str
    content_excerpt: str = Field(max_length=MAX_EXCERPT_LENGTH)
    content_hash: str
    pfsense_edition: Edition
    evidence_level: EvidenceLevel
    applicability: ApplicabilityState
    applicable_overlay_chain: tuple[str, ...] = Field(
        default=(),
        description="ReleaseOverlay.overlay_id values applicable to this entry, "
        "ORDERED most-superseded first, current-truth last -- never flattened "
        "into an unordered set (ADR-018 Finding 6, applied at this per-entry "
        "level too, not only at GuidanceEvidence's aggregate level).",
    )
    observed_edition_used: ObservedEdition
    observed_version_used: str | None
    retrieval_mode: RetrievalMode
    snapshot_version: str

    @field_validator("canonical_url")
    @classmethod
    def _check_canonical_url(cls, value: str) -> str:
        return _validate_canonical_url(value)

    @field_validator("content_hash")
    @classmethod
    def _check_content_hash_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("content_hash must be a lowercase hex sha256 digest")
        return value


class GuidanceEvidence(BaseModel):
    """The read-recommendation composition model (ADR-018 S5). Keeps
    observed fact, base guidance, release overlays, applicability
    result, evidence strength, and provenance/freshness metadata as
    structurally separate typed fields -- never concatenated into one
    string -- so a future consumer cannot confuse OBSERVED FACT with
    OFFICIAL GUIDANCE with MODEL INFERENCE by construction, to the
    extent a data model can enforce that (ADR-018's own TB-G2
    cross-reference: whether a *consumer* preserves this separation
    when presenting to a human or model remains a consumption-boundary
    concern this layer cannot close by itself).

    Not wired into any READ tool, guidance lookup, or PREPARE path.
    Constructed directly (by a test, or by a future orchestration
    function this step does not build) from already-resolved
    `EvidenceReference` values.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    observed_edition: ObservedEdition
    observed_version: str | None
    appliance_identity_source: str
    guidance: tuple[EvidenceReference, ...]
    overlay_chain: tuple[str, ...] = Field(
        default=(),
        description="ReleaseOverlay.overlay_id values considered for this "
        "capability, ORDERED most-superseded first, current-truth last.",
    )
    overall_state: ApplicabilityState
