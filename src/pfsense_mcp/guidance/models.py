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
"""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    request-time input (I2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=SOURCE_ID_PATTERN)
    title: str = Field(max_length=MAX_TITLE_LENGTH)
    canonical_url: str
    pfsense_edition: Edition
    version_applicability: str
    retrieval_mode: RetrievalMode
    content_excerpt: str = Field(max_length=MAX_EXCERPT_LENGTH)
    content_hash: str
    license_note: str = Field(max_length=MAX_LICENSE_NOTE_LENGTH)

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


class GuidanceReference(BaseModel):
    """The only shape `lookup_guidance()` ever returns (G1). No field here
    is a capability, endpoint, HTTP method, or confirmation token -- there
    is nothing in this closed schema an authorization decision could be
    read out of."""

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
    content_excerpt: str = Field(max_length=MAX_EXCERPT_LENGTH)
    content_hash: str
    pfsense_edition: Edition
    trust_label: str
    version_mismatch: bool
    snapshot_version: str

    @field_validator("canonical_url")
    @classmethod
    def _check_canonical_url(cls, value: str) -> str:
        return _validate_canonical_url(value)
