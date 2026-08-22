"""Version-aware Official Guidance evidence model (ADR-018, Accepted --
architecture and trust boundaries only; step 2 of its implementation:
the offline evidence model, still entirely inert, no runtime consumer
wired).

`EvidenceReference` is an additive type, not a modification of
`models.GuidanceReference` -- structurally similar to what
`VERSION_AWARE_GUIDANCE.md` described as an amended `GuidanceReference`,
under a distinct name so `EvidenceReference`'s own shape stays stable
regardless of what `GuidanceReference` needs for its own reasons.
`registry.lookup_guidance()`'s "exclude vs. exclude-with-state" policy
change and `GuidanceReference`'s corresponding field extension
(`applicability`/`evidence_level`/`applicable_overlay_chain`/
`observed_edition_used`/`observed_version_used`/`retrieval_mode`,
replacing `version_mismatch`) were **not** granted by ADR-018's
acceptance or by this step -- they were implemented in a later,
separately owner-authorized step (`models.py`,
`registry.py`; see `bridge.py` for the resulting
`GuidanceReference` -> `EvidenceReference` bridge). `EvidenceLevel`/
`ApplicabilityState`/`APPLICABILITY_STATE_ORDER` were originally defined
in this module; that same later step moved their definitions into
`models.py` to avoid a circular import once `GuidanceReference` needed
them too -- re-imported here unchanged, so every existing import of
these three names from this module continues to work identically.

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

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .appliance_identity import ObservedEdition
from .models import (
    APPLICABILITY_STATE_ORDER,
    MAX_EXCERPT_LENGTH,
    MAX_TITLE_LENGTH,
    MAX_VERIFICATION_EXCERPT_LENGTH,
    SOURCE_ID_PATTERN,
    ApplicabilityState,
    Edition,
    EvidenceLevel,
    RetrievalMode,
    _validate_canonical_url,
)

__all__ = [
    "APPLICABILITY_STATE_ORDER",
    "ApplicabilityState",
    "EvidenceLevel",
    "EvidenceReference",
    "GuidanceEvidence",
    "ReleaseOverlay",
]


class ReleaseOverlay(BaseModel):
    """A Git-tracked, PR-reviewed release-note/errata entry that may
    supersede a `DocumentSource` or another `ReleaseOverlay` (ADR-018
    Finding 6) -- same trust model as `DocumentSource`: never
    constructed from request-time input, same bounded-field/
    allow-listed-host discipline.

    Same 2026-08-22 provenance revision as `DocumentSource`: `caveat_summary`
    is project-authored (never a quotation of a release note); a short,
    genuinely verbatim `source_verification_excerpt` exists solely for the
    maintainer-only corpus-drift audit. Currently no entries exist in
    `_OVERLAY_REGISTRY`, so no prior verbatim content needed migrating --
    this shape applies from the first real entry onward.
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
    caveat_summary: str = Field(max_length=MAX_EXCERPT_LENGTH)
    caveat_summary_hash: str
    source_verification_excerpt: str = Field(max_length=MAX_VERIFICATION_EXCERPT_LENGTH)
    source_verification_hash: str
    canonical_url: str

    @field_validator("canonical_url")
    @classmethod
    def _check_canonical_url(cls, value: str) -> str:
        return _validate_canonical_url(value)

    @field_validator("caveat_summary_hash", "source_verification_hash")
    @classmethod
    def _check_hash_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("hash fields must be a lowercase hex sha256 digest")
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

    Same 2026-08-22 provenance revision: `summary`/`summary_hash` replace
    `content_excerpt`/`content_hash` -- project-authored, never a
    quotation. `source_verification_excerpt` is deliberately not a field
    here (maintainer-audit-only, `DocumentSource`-internal).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    source_id: str = Field(pattern=SOURCE_ID_PATTERN)
    title: str = Field(max_length=MAX_TITLE_LENGTH)
    canonical_url: str
    summary: str = Field(max_length=MAX_EXCERPT_LENGTH)
    summary_hash: str
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

    @field_validator("summary_hash")
    @classmethod
    def _check_summary_hash_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("summary_hash must be a lowercase hex sha256 digest")
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
