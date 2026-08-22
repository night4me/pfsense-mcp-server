"""Typed, closed-schema shapes for the guidance layer (ADR-017 I1/I3/I4).

`DocumentSource` is registry-authoring input (Git-tracked, PR-reviewed,
never constructed from request-time input -- I2). `GuidanceReference` is
the only shape `lookup_guidance()` ever returns. Neither model has a field
of type capability, endpoint, HTTP method, or confirmation token (G1) --
this is enforced by the closed field list below, not left to convention.

Every free-text field is independently length-bounded (I4); `source_id`
is a constrained slug, not free text; `canonical_url` is validated against
a small, explicit hostname allow-list at construction time (I3). Both
constraints were gaps in this module's first draft, found and fixed by
`reports-ai/reviews/ADR_017_RED_TEAM.md` (Findings 1 and 2).

**Provenance-model revision (2026-08-22, owner-authorized)**: the original
accepted design's `content_excerpt` field held a short *verbatim quotation*
from the official source, hashed by `content_hash`. The owner has since
directed a conservative move away from depending on redistributed Netgate
prose. This revision splits that one field/hash pair into two, each with a
distinct, non-overlapping purpose:

- `summary` / `summary_hash` -- a **project-authored** explanation of the
  capability, independently written (never a quotation, never superficial
  word-substitution of the source text). This is the only content-bearing
  field `GuidanceReference`/`EvidenceReference` ever exposes to a consumer.
  `summary_hash` pins the exact summary text that shipped (drift-detects an
  edit to the summary itself, same mechanical role `content_hash` always
  played -- pin what ships -- now applied to project-authored text instead
  of a quotation).
- `source_verification_excerpt` / `source_verification_hash` -- a short
  (<= `MAX_VERIFICATION_EXCERPT_LENGTH`, far below the old excerpt bound),
  genuinely verbatim anchor phrase drawn from the official source page,
  used **exclusively** by `scripts/guidance_corpus_audit.py`'s maintainer-
  only drift check (substring presence on the live page). This pair exists
  only on `DocumentSource`/`ReleaseOverlay` (registry-authoring input) --
  it is deliberately **not** part of `GuidanceReference`/`EvidenceReference`
  (G1/TB-G2: no reason for any consumer to see a maintainer verification
  anchor, and keeping it out of the consumer-facing schema is itself part
  of minimizing what leaves this layer). Its bound is small specifically
  because its only job is confirming *this page still contains what the
  summary was based on* -- it is not, and must never become, a second
  quotation-sized excerpt.

This keeps ADR-017/018's architecture unchanged (same three-layer
separation, same deterministic registry, same isolation boundaries) -- it
is a field-level provenance refinement, not a redesign.
"""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .appliance_identity import ObservedEdition

#: I3: registry-authoring identifiers are slugs, not free text.
SOURCE_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{2,63}$"

#: I3/TB-G1: the only hostnames a `canonical_url` may point to. Extending
#: this set is a reviewed, deliberate diff -- never a runtime decision.
ALLOWED_DOCUMENT_HOSTS: frozenset[str] = frozenset({"docs.netgate.com"})

#: I4: bounds chosen to keep manual review of the bundled corpus tractable
#: and to limit how much an eventually-reviewed-but-adversarial entry
#: could carry in any one field. Revisit only with a documented reason.
MAX_TITLE_LENGTH = 200
MAX_EXCERPT_LENGTH = 2000
MAX_LICENSE_NOTE_LENGTH = 500

#: Deliberately much smaller than `MAX_EXCERPT_LENGTH`: this bound exists
#: for `source_verification_excerpt`, a maintainer-only drift-detection
#: anchor, never a second quotation-sized excerpt (2026-08-22 provenance
#: revision -- see module docstring).
MAX_VERIFICATION_EXCERPT_LENGTH = 300

#: I3: the only legal `version_applicability` values are this literal and
#: an exact `SystemVersion.version` string -- no ranges, no operators, no
#: grammar to parse (a red-team finding: an earlier draft implied a
#: parseable "expression" without ever defining one).
UNVERSIONED = "unversioned"


class Edition(str, Enum):
    CE = "CE"
    PLUS = "Plus"
    BOTH = "both"


class RetrievalMode(str, Enum):
    BUNDLED_SNAPSHOT = "bundled_snapshot"
    # LIVE_FETCH is deliberately not a member: TB-G3 (live retrieval) is
    # specified but not authorized to build -- see OFFICIAL_GUIDANCE_LAYER.md.


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

    Lives in `models.py`, not `evidence.py` (where ADR-018 Step 2
    originally defined it) -- moved here by the ADR-018 guidance-bridge
    implementation slice so `GuidanceReference` (this module) can use it
    without creating a circular import with `evidence.py` (which already
    depends on `models.py` for `Edition`/`RetrievalMode`/bounded-field
    validators). `evidence.py` re-imports this name unchanged, so every
    existing `from pfsense_mcp.guidance.evidence import EvidenceLevel`
    import continues to work identically -- same class, same identity,
    only its defining module moved.
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
    runs, not represented as an answer a lookup can return.

    Moved here from `evidence.py` for the same circular-import reason as
    `EvidenceLevel` above -- `evidence.py` re-imports this name
    unchanged.
    """

    APPLICABLE = "applicable"
    PARTIALLY_APPLICABLE = "partially_applicable"
    VERSION_UNCONFIRMED = "version_unconfirmed"
    EDITION_MISMATCH = "edition_mismatch"
    STALE = "stale"
    NO_OFFICIAL_GUIDANCE_FOUND = "no_official_guidance_found"


#: Most-favorable to least-favorable, used by
#: `applicability.compute_overall_state()`. Fixed, reviewable, never a
#: runtime heuristic (ADR-018 S5). Moved here from `evidence.py` for the
#: same reason as `ApplicabilityState` above.
APPLICABILITY_STATE_ORDER: tuple[ApplicabilityState, ...] = (
    ApplicabilityState.APPLICABLE,
    ApplicabilityState.PARTIALLY_APPLICABLE,
    ApplicabilityState.VERSION_UNCONFIRMED,
    ApplicabilityState.STALE,
    ApplicabilityState.EDITION_MISMATCH,
    ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND,
)


def excerpt_hash(text: str) -> str:
    """The one hash function this module uses -- sha256 of the exact
    excerpt text, never of any live page (TB-G3's red-team-fixed
    clarification: this hash is not, and cannot be, a live-page
    comparator)."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_canonical_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ValueError(f"canonical_url must be https, got scheme {parts.scheme!r}")
    if parts.hostname not in ALLOWED_DOCUMENT_HOSTS:
        raise ValueError(
            f"canonical_url host {parts.hostname!r} is not in the allow-list {sorted(ALLOWED_DOCUMENT_HOSTS)}"
        )
    return value


class DocumentSource(BaseModel):
    """One Git-tracked, PR-reviewed registry entry (I3). Never constructed
    from a network response, environment variable, or any other
    request-time input (I2).

    `summary` is project-authored (2026-08-22 provenance revision -- see
    module docstring); `source_verification_excerpt` is the only verbatim
    text this model carries, bounded far smaller than the old excerpt,
    used exclusively by the maintainer-only corpus-drift audit.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=SOURCE_ID_PATTERN)
    title: str = Field(max_length=MAX_TITLE_LENGTH)
    canonical_url: str
    pfsense_edition: Edition
    version_applicability: str
    evidence_level: EvidenceLevel
    retrieval_mode: RetrievalMode
    summary: str = Field(max_length=MAX_EXCERPT_LENGTH)
    summary_hash: str
    source_verification_excerpt: str = Field(max_length=MAX_VERIFICATION_EXCERPT_LENGTH)
    source_verification_hash: str
    license_note: str = Field(max_length=MAX_LICENSE_NOTE_LENGTH)

    @field_validator("canonical_url")
    @classmethod
    def _check_canonical_url(cls, value: str) -> str:
        return _validate_canonical_url(value)

    @field_validator("summary_hash", "source_verification_hash")
    @classmethod
    def _check_hash_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("hash fields must be a lowercase hex sha256 digest")
        return value


class GuidanceReference(BaseModel):
    """The only shape `lookup_guidance()` ever returns (G1). No field here
    is a capability, endpoint, HTTP method, or confirmation token -- there
    is nothing in this closed schema an authorization decision could be
    read out of.

    Extended by the ADR-018 guidance-bridge implementation slice
    (2026-08-09): `version_mismatch: bool` (always `False` in the
    original, exclude-only design) is replaced by the five new fields
    below, computed by `applicability.compute_entry_applicability()` and
    assembled by `registry.lookup_guidance()` -- the real behavior
    change ADR-018 S2 and its own "Acceptance record" already named as
    needing separate explicit approval before this signature shipped.
    `trust_label` is unchanged, still present here (only the separate
    `EvidenceReference` type, produced by `bridge.bridge_guidance_reference()`,
    omits it -- see that module for why).

    **Provenance-model revision (2026-08-22)**: `content_excerpt`/
    `content_hash` are replaced by `summary`/`summary_hash` (module
    docstring). `DocumentSource.source_verification_excerpt`/
    `source_verification_hash` are deliberately **not** fields here --
    that pair is maintainer-audit-only and never reaches any consumer.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Capability member name (str), not the enum object: this design's own
    # choice for a JSON-serializable, MCP-schema-safe representation, not
    # an existing convention this codebase already had -- Capability has
    # never appeared in any public schema before this module (verified by
    # `reports-ai/reviews/ADR_017_RED_TEAM.md` Finding 6; do not repeat
    # that claim of precedent elsewhere without re-checking).
    capability: str
    source_id: str = Field(pattern=SOURCE_ID_PATTERN)
    title: str = Field(max_length=MAX_TITLE_LENGTH)
    canonical_url: str
    summary: str = Field(max_length=MAX_EXCERPT_LENGTH)
    summary_hash: str
    pfsense_edition: Edition
    trust_label: str
    applicability: ApplicabilityState
    evidence_level: EvidenceLevel
    applicable_overlay_chain: tuple[str, ...] = Field(
        default=(),
        description="ReleaseOverlay.overlay_id values applicable to this entry, ORDERED "
        "most-superseded first, current-truth last -- never flattened into an unordered set "
        "(ADR-018 Finding 6, at the per-entry level).",
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
