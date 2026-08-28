"""Closed, bounded evidence primitives (pfREST_LIVE_GUIDANCE_ARC Phase
2/8). No I/O -- pure data shapes, imported by every other module in
this package.

`GuidanceEvidence` is deliberately one shared shape across all four
`Provenance` values rather than one bespoke schema per source: every
source's content is reduced to a short, ordered list of bounded fact
strings, each still individually attributed to exactly one `provenance`
+ `source` pair. This keeps the composition layer (`composition.py`)
simple and keeps every consumer's per-entry token cost predictable
(Phase 14) without ever concatenating two sources' text into one
string -- the structural separation the mission's Phase 8 requires is
enforced by "one `GuidanceEvidence` per source, never merged", not by
giving each source a different Python type.

`content_hash` is a freshness/cache-key hash of the exact evidence
*returned in this response* -- never a claim that a cached document
equals whatever is live on the upstream site or appliance right now
(the same TB-G3 clarification `pfsense_mcp.guidance.models.excerpt_hash`
already documents for the unrelated bundled-snapshot case). A
`STALE_BUT_USABLE` evidence entry's `content_hash` pins the stale
content, not a promise that live content still matches it.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .provenance import Provenance

MAX_SOURCE_LENGTH = 300
MAX_SUBJECT_LENGTH = 200
MAX_FACT_LENGTH = 400
MAX_FACTS_PER_EVIDENCE = 24
MAX_CAVEAT_LENGTH = 300
MAX_CAVEATS = 8
MAX_EVIDENCE_ENTRIES = 8
MAX_CONFLICTS = 12
MAX_APPLICABILITY_NOTES = 12


class FreshnessState(str, Enum):
    """Cache/retrieval freshness for one `GuidanceEvidence` entry.
    Orthogonal to `Provenance` -- a `PROJECT_AUTHORED` or
    `OFFICIAL_NETGATE` entry is always `NOT_APPLICABLE` (neither is
    ever live-fetched by this package); only `PFREST_UPSTREAM` and
    `LIVE_APPLIANCE_SCHEMA` entries carry a real cache/network state.
    """

    FRESH = "fresh"
    STALE_BUT_USABLE = "stale_but_usable"
    MISS = "miss"
    CORRUPT = "corrupt"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    NOT_APPLICABLE = "not_applicable"


class GuidanceEvidence(BaseModel):
    """One source's bounded, attributed contribution to a
    `CrossSourceGuidance` response. Never contains another source's
    text -- `facts`/`caveats` here are only ever derived from
    `source`/`provenance`'s own material.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    provenance: Provenance
    source: str = Field(
        max_length=MAX_SOURCE_LENGTH,
        description="Human-readable source identifier: a live URL for PFREST_UPSTREAM, a fixed "
        "literal describing the appliance call for LIVE_APPLIANCE_SCHEMA, the canonical Netgate "
        "URL for OFFICIAL_NETGATE (reused from GuidanceReference.canonical_url), or a fixed "
        "literal naming this project for PROJECT_AUTHORED.",
    )
    subject: str = Field(max_length=MAX_SUBJECT_LENGTH, description="What this evidence is about.")
    version: str | None = Field(default=None, description="Version/release evidence, where known. Never guessed.")
    fetched_at: str | None = Field(
        default=None, description="ISO 8601 UTC timestamp of retrieval. None for PROJECT_AUTHORED/OFFICIAL_NETGATE."
    )
    content_hash: str | None = Field(
        default=None,
        description="sha256 of the exact evidence content returned in THIS response -- a freshness/"
        "cache-key hash, never a claim that it equals whatever is live right now.",
    )
    freshness: FreshnessState
    facts: tuple[str, ...] = Field(default=(), max_length=MAX_FACTS_PER_EVIDENCE)
    caveats: tuple[str, ...] = Field(default=(), max_length=MAX_CAVEATS)

    @property
    def fact_lengths_are_bounded(self) -> bool:
        return all(len(fact) <= MAX_FACT_LENGTH for fact in self.facts) and all(
            len(caveat) <= MAX_CAVEAT_LENGTH for caveat in self.caveats
        )


class CrossSourceGuidance(BaseModel):
    """The public composition result: one query, up to
    `MAX_EVIDENCE_ENTRIES` `GuidanceEvidence` entries (each independently
    provenance-labeled), explicit conflicts, explicit applicability
    notes. Never a flattened prose blob -- see `composition.py`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    query: str = Field(max_length=MAX_SUBJECT_LENGTH)
    evidence: tuple[GuidanceEvidence, ...] = Field(default=(), max_length=MAX_EVIDENCE_ENTRIES)
    conflicts: tuple[str, ...] = Field(default=(), max_length=MAX_CONFLICTS)
    applicability_notes: tuple[str, ...] = Field(default=(), max_length=MAX_APPLICABILITY_NOTES)
