"""Deterministic, offline applicability/registry-integrity primitives
(ADR-018, steps 2-3 of its implementation). Pure functions only -- no
I/O, no state, no clock reads except where a caller-supplied timestamp
is compared (none of that exists yet; TB-G3/caching remain
unactivated).

`compute_entry_applicability()` implements the single-entry
`APPLICABLE`/`PARTIALLY_APPLICABLE`/`STALE`/`VERSION_UNCONFIRMED`/
`EDITION_MISMATCH` decision procedure specified in
`docs/VERSION_AWARE_GUIDANCE.md`'s "Single-entry applicability decision
procedure" section (design-and-red-team pass,
`reports-ai/reviews/ADR_018_APPLICABILITY_DECISION_PROCEDURE_RED_TEAM.md`,
verdict ACCEPT WITH CHANGES) and its owner-confirmed edition-`UNKNOWN`
resolution (routes to `VERSION_UNCONFIRMED`) -- this was previously the
deferred question `applicability_state_for_entry_is_not_implemented_here()`
represented; that marker is removed, replaced by the real implementation
below, per explicit owner authorization.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from .appliance_identity import ObservedEdition
from .evidence import ReleaseOverlay
from .models import APPLICABILITY_STATE_ORDER, UNVERSIONED, ApplicabilityState, Edition, EvidenceLevel

#: NEVER instantiate ApplicabilityState.APPLICABLE or
#: .PARTIALLY_APPLICABLE from an entry whose evidence_level is this --
#: ADR-018 Finding 5. This is the entire, complete rule this step
#: implements for evidence-level capping; nothing else about *which*
#: state an entry lands on beyond this cap is decided here.
_LEVELS_THAT_CANNOT_REACH_APPLICABLE = frozenset({EvidenceLevel.INFERRED_FROM_CURRENT_DOCS, EvidenceLevel.UNKNOWN})


def cap_applicability_by_evidence_level(
    evidence_level: EvidenceLevel, computed_state: ApplicabilityState
) -> ApplicabilityState:
    """Apply ADR-018 Finding 5's cap: an entry whose evidence_level is
    INFERRED_FROM_CURRENT_DOCS or UNKNOWN can contribute at most
    VERSION_UNCONFIRMED, regardless of what a fuller decision procedure
    would otherwise have computed. Only APPLICABLE/PARTIALLY_APPLICABLE
    are capped -- a state already no more favorable than
    VERSION_UNCONFIRMED (STALE, EDITION_MISMATCH,
    NO_OFFICIAL_GUIDANCE_FOUND) passes through unchanged; capping never
    makes a state *more* favorable.
    """
    if evidence_level not in _LEVELS_THAT_CANNOT_REACH_APPLICABLE:
        return computed_state
    if computed_state in (ApplicabilityState.APPLICABLE, ApplicabilityState.PARTIALLY_APPLICABLE):
        return ApplicabilityState.VERSION_UNCONFIRMED
    return computed_state


def compute_overall_state(states: Sequence[ApplicabilityState]) -> ApplicabilityState:
    """GuidanceEvidence.overall_state (ADR-018 S5): the least-favorable
    state present, using APPLICABILITY_STATE_ORDER's fixed total
    ordering. Empty input means no guidance was found at all.
    """
    if not states:
        return ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND
    return max(states, key=APPLICABILITY_STATE_ORDER.index)


class _EditionStatus(str, Enum):
    """Step 1 of the accepted decision procedure -- internal, not part
    of the public `ApplicabilityState` vocabulary."""

    MATCH = "match"
    MISMATCH = "mismatch"
    UNCONFIRMED = "unconfirmed"


class _VersionStatus(str, Enum):
    """Step 2 -- exact-match-or-`UNVERSIONED` only, no ranges (the
    accepted schema has no range grammar to evaluate)."""

    MATCH = "match"
    UNCONFIRMED = "unconfirmed"


class _SupersessionStatus(str, Enum):
    """Step 3 -- an entry's relationship to the candidate overlays for
    its capability/observed version/edition."""

    SUPERSEDED = "superseded"
    CAVEATED = "caveated"
    NONE = "none"


def _entry_edition_status(entry_edition: Edition, observed_edition: ObservedEdition) -> _EditionStatus:
    if entry_edition is Edition.BOTH:
        return _EditionStatus.MATCH
    if observed_edition is ObservedEdition.UNKNOWN:
        return _EditionStatus.UNCONFIRMED
    expected = ObservedEdition.KNOWN_CE if entry_edition is Edition.CE else ObservedEdition.KNOWN_PLUS
    return _EditionStatus.MATCH if observed_edition is expected else _EditionStatus.MISMATCH


def _entry_version_status(entry_version_applicability: str, observed_version: str | None) -> _VersionStatus:
    if entry_version_applicability == UNVERSIONED:
        return _VersionStatus.MATCH
    if observed_version is not None and observed_version == entry_version_applicability:
        return _VersionStatus.MATCH
    return _VersionStatus.UNCONFIRMED


def _overlay_is_edition_candidate(overlay_edition: Edition, observed_edition: ObservedEdition) -> bool:
    """Whether an overlay's edition scope is confirmed compatible with
    the observed appliance -- conservative by design: an edition-specific
    overlay is excluded from candidacy (not merely "uncertain") when
    `observed_edition` is `UNKNOWN`, so uncertain overlay evidence can
    never inject STALE/PARTIALLY_APPLICABLE onto an entry whose own
    edition status is independently confirmed."""
    if overlay_edition is Edition.BOTH:
        return True
    if observed_edition is ObservedEdition.UNKNOWN:
        return False
    expected = ObservedEdition.KNOWN_CE if overlay_edition is Edition.CE else ObservedEdition.KNOWN_PLUS
    return observed_edition is expected


def _chain_reaches(start: str | None, target_id: str, overlays_by_id: dict[str, ReleaseOverlay]) -> bool:
    """Walk a `supersedes_id` chain starting at `start`, looking for
    `target_id` -- which may be a `DocumentSource.source_id` (not itself
    a key in `overlays_by_id`) as the final hop, or another overlay_id
    anywhere along the way. Bounded by a visited-set cycle guard; a real
    cycle is a load-time registry-integrity defect
    (`find_supersession_chain_defects()`), not something this function
    is responsible for detecting."""
    current = start
    visited: set[str] = set()
    while current is not None:
        if current == target_id:
            return True
        if current in visited:
            return False
        visited.add(current)
        next_overlay = overlays_by_id.get(current)
        current = next_overlay.supersedes_id if next_overlay is not None else None
    return False


def _entry_supersession_status(
    entry_id: str,
    entry_capability: str,
    observed_edition: ObservedEdition,
    observed_version: str | None,
    all_overlays: Sequence[ReleaseOverlay],
) -> tuple[_SupersessionStatus, tuple[str, ...]]:
    """Step 3: classify `entry_id`'s relationship to `all_overlays`.
    Candidate overlays are those matching the entry's capability, with a
    confirmed-compatible edition (see `_overlay_is_edition_candidate`),
    and an exact-or-UNVERSIONED version match against `observed_version`
    -- the same match rules Step 2 applies to the entry itself, applied
    here to overlays."""
    candidates = [
        overlay
        for overlay in all_overlays
        if overlay.capability == entry_capability
        and _overlay_is_edition_candidate(overlay.applies_to_edition, observed_edition)
        and (overlay.applies_to_version == UNVERSIONED or overlay.applies_to_version == observed_version)
    ]
    if not candidates:
        return _SupersessionStatus.NONE, ()

    overlays_by_id = {overlay.overlay_id: overlay for overlay in all_overlays}
    superseding = [c for c in candidates if _chain_reaches(c.supersedes_id, entry_id, overlays_by_id)]
    if superseding:
        chain_ids = tuple(sorted({c.overlay_id for c in superseding}))
        return _SupersessionStatus.SUPERSEDED, order_overlay_chain(chain_ids, overlays_by_id)

    caveat_ids = tuple(sorted(c.overlay_id for c in candidates))
    return _SupersessionStatus.CAVEATED, caveat_ids


def compute_entry_applicability(
    *,
    entry_id: str,
    entry_capability: str,
    entry_edition: Edition,
    entry_version_applicability: str,
    entry_evidence_level: EvidenceLevel,
    observed_edition: ObservedEdition,
    observed_version: str | None,
    all_overlays: Sequence[ReleaseOverlay] = (),
) -> tuple[ApplicabilityState, tuple[str, ...]]:
    """The accepted single-entry decision procedure
    (`docs/VERSION_AWARE_GUIDANCE.md`'s "Single-entry applicability
    decision procedure" section; owner-authorized implementation,
    replacing the removed `applicability_state_for_entry_is_not_implemented_here()`
    marker). Returns `(state, applicable_overlay_chain)`.

    Priority order, first match wins -- every branch grounded in the
    accepted ADR text, not invented:

    1. Edition MISMATCH -> EDITION_MISMATCH (most definitive "wrong
       document" signal; nothing else evaluated).
    2. SUPERSEDED (a curator-registered overlay's chain reaches this
       entry) -> STALE, ahead of the ordinary match/caveat branches --
       an authoritative, reviewed currency fact, stronger than an
       unresolved version/edition question or a mere caveat.
    3. Either edition or version status is UNCONFIRMED -> VERSION_UNCONFIRMED
       -- edition-UNCONFIRMED (entry is edition-specific, observed
       edition is UNKNOWN) is routed here too, per the owner-confirmed
       resolution of a real gap found while writing this procedure: the
       accepted ADR text's EDITION_MISMATCH/VERSION_UNCONFIRMED
       definitions, read literally, leave edition-UNKNOWN unclassifiable
       by either; VERSION_UNCONFIRMED's evident purpose --
       "insufficient identity information, no affirmative evidence of
       mismatch" -- covers it correctly.
    4. Edition and version both MATCH, and a CAVEATED (non-superseding)
       overlay exists -> PARTIALLY_APPLICABLE -- and only this: overlay-
       caveat existence is the one precise meaning this state carries,
       never partial semantic relevance, partial version overlap, or
       incomplete identity evidence (those are VERSION_UNCONFIRMED's
       job).
    5. Otherwise (edition and version both MATCH, no overlay at all)
       -> APPLICABLE.

    Then, independently, `cap_applicability_by_evidence_level()` is
    applied to every branch's result -- a second, structurally
    independent fail-safe layer: even a hypothetical bug in the
    priority ordering above cannot produce APPLICABLE/PARTIALLY_APPLICABLE
    for an entry whose own `evidence_level` is INFERRED_FROM_CURRENT_DOCS/
    UNKNOWN.

    `applicable_overlay_chain` is reported only for STALE (the
    superseding chain) and post-cap PARTIALLY_APPLICABLE (the caveating
    overlay ids) -- empty for every other final state, including a
    PARTIALLY_APPLICABLE candidate that the evidence-level cap demoted
    to VERSION_UNCONFIRMED (an unconfirmed entry's overlay evidence is
    not meaningfully "applicable" either).
    """
    edition_status = _entry_edition_status(entry_edition, observed_edition)
    version_status = _entry_version_status(entry_version_applicability, observed_version)
    supersession_status, candidate_chain = _entry_supersession_status(
        entry_id, entry_capability, observed_edition, observed_version, all_overlays
    )

    base_state: ApplicabilityState
    chain: tuple[str, ...]
    if edition_status is _EditionStatus.MISMATCH:
        base_state, chain = ApplicabilityState.EDITION_MISMATCH, ()
    elif supersession_status is _SupersessionStatus.SUPERSEDED:
        base_state, chain = ApplicabilityState.STALE, candidate_chain
    elif edition_status is _EditionStatus.UNCONFIRMED or version_status is _VersionStatus.UNCONFIRMED:
        base_state, chain = ApplicabilityState.VERSION_UNCONFIRMED, ()
    elif supersession_status is _SupersessionStatus.CAVEATED:
        base_state, chain = ApplicabilityState.PARTIALLY_APPLICABLE, candidate_chain
    else:
        base_state, chain = ApplicabilityState.APPLICABLE, ()

    final_state = cap_applicability_by_evidence_level(entry_evidence_level, base_state)
    final_chain = chain if final_state in (ApplicabilityState.STALE, ApplicabilityState.PARTIALLY_APPLICABLE) else ()
    return final_state, final_chain


def find_duplicate_scope_conflicts(overlays: Sequence[ReleaseOverlay]) -> list[tuple[str, str]]:
    """ADR-018 Finding 8's duplicate-scope check, independent check (1)
    of 2: flags any two ReleaseOverlay entries that share the same
    capability, edition-compatible scope (identical edition, or either
    is Edition.BOTH), and identical applies_to_version, with **no**
    supersedes_id relationship (direct or transitive, either direction)
    connecting them.

    This is the mechanism ADR-018 Finding 8 fixed to represent
    conflicting official guidance as a detectable, load-time defect --
    the design's answer to "conflicting guidance must remain
    representable as conflict rather than flattened," expressed as a
    registry-integrity violation list rather than a runtime
    ApplicabilityState member (see evidence.py's ApplicabilityState
    docstring for why).

    Returns a list of (overlay_id, overlay_id) pairs, each reported
    once (i < j order). Pure and deterministic: does not consult
    content_hash or caveat_excerpt -- text-similarity "disagreement" is
    not a tractable check and was never claimed to be one.
    """
    ancestry = _ancestor_closure(overlays)
    conflicts: list[tuple[str, str]] = []
    for i, left in enumerate(overlays):
        for right in overlays[i + 1 :]:
            if left.capability != right.capability:
                continue
            if not _edition_compatible(left.applies_to_edition, right.applies_to_edition):
                continue
            if left.applies_to_version != right.applies_to_version:
                continue
            if right.overlay_id in ancestry.get(left.overlay_id, frozenset()):
                continue
            if left.overlay_id in ancestry.get(right.overlay_id, frozenset()):
                continue
            conflicts.append((left.overlay_id, right.overlay_id))
    return conflicts


def find_supersession_chain_defects(overlays: Sequence[ReleaseOverlay]) -> dict[str, str]:
    """ADR-018 Finding 8's chain-integrity check, independent check (2)
    of 2: dangling supersedes_id references (pointing at an unknown
    overlay_id -- source_id/DocumentSource references are out of scope
    for this step, since DocumentSource is not extended here) and
    supersession cycles.

    Returns {overlay_id: defect_description} for every offending entry.
    """
    by_id = {overlay.overlay_id: overlay for overlay in overlays}
    defects: dict[str, str] = {}
    for overlay in overlays:
        target = overlay.supersedes_id
        if target is None:
            continue
        if target not in by_id:
            defects[overlay.overlay_id] = f"supersedes_id {target!r} does not resolve to any known overlay_id"
            continue
        visited = {overlay.overlay_id}
        current: str | None = target
        while current is not None:
            if current in visited:
                defects[overlay.overlay_id] = f"supersedes_id chain cycles back to {current!r}"
                break
            visited.add(current)
            next_overlay = by_id.get(current)
            current = next_overlay.supersedes_id if next_overlay is not None else None
    return defects


def order_overlay_chain(overlay_ids: Sequence[str], overlays_by_id: dict[str, ReleaseOverlay]) -> tuple[str, ...]:
    """Order a set of overlay IDs most-superseded first, current-truth
    last, by walking each entry's supersedes_id chain (ADR-018 Finding
    6). Assumes no cycles/dangling references (verify with
    find_supersession_chain_defects() first -- this function does not
    re-validate that itself, to keep it a pure ordering primitive with
    one job).
    """
    depth: dict[str, int] = {}
    for overlay_id in overlay_ids:
        chain_length = 0
        current = overlays_by_id[overlay_id].supersedes_id
        while current is not None and current in overlays_by_id:
            chain_length += 1
            current = overlays_by_id[current].supersedes_id
        depth[overlay_id] = chain_length
    # depth[x] counts how many steps x's OWN supersedes_id chain takes
    # to terminate. The root/most-superseded entry (e.g. a base release
    # note) has supersedes_id=None -- depth 0. Each entry that
    # supersedes something one step further back has depth one greater
    # than what it supersedes. So depth increases monotonically from
    # oldest/most-superseded (0) to newest/current-truth (highest) --
    # ascending depth is exactly "most-superseded first, current-truth
    # last."
    return tuple(sorted(overlay_ids, key=lambda oid: depth[oid]))


def may_prepare(*, existing_authorization: bool, guidance_required: bool, guidance_check_passes: bool) -> bool:
    """The monotonic guidance-veto property (ADR-018 Finding 7),
    implemented as the exact structural rule the ADR's Trust boundary
    section names: guidance may only ever remove permission from an
    otherwise-authorized baseline, never create it.

        may_prepare = existing_authorization
                      AND (NOT guidance_required OR guidance_check_passes)

    Not called from anywhere -- Tier 1 PREPARE wiring remains
    unactivated. Exists so the structural rule is pinned in code a
    future implementer can import and reuse verbatim, rather than
    re-deriving (and potentially getting wrong) at PREPARE-wiring time.
    """
    return existing_authorization and (not guidance_required or guidance_check_passes)


def _edition_compatible(left: object, right: object) -> bool:
    from .models import Edition

    if left == right:
        return True
    return left == Edition.BOTH or right == Edition.BOTH


def _ancestor_closure(overlays: Sequence[ReleaseOverlay]) -> dict[str, frozenset[str]]:
    """For each overlay_id, the set of overlay_ids reachable by
    following supersedes_id -- used only to decide "is there a
    connecting relationship," never to detect cycles (that is
    find_supersession_chain_defects()'s job; this helper tolerates a
    cycle by bounding the walk to len(overlays) steps rather than
    looping forever, since it may be called on not-yet-validated input).
    """
    by_id = {overlay.overlay_id: overlay for overlay in overlays}
    result: dict[str, frozenset[str]] = {}
    for overlay in overlays:
        ancestors: set[str] = set()
        current = overlay.supersedes_id
        steps = 0
        while current is not None and current in by_id and steps <= len(overlays):
            ancestors.add(current)
            current = by_id[current].supersedes_id
            steps += 1
        result[overlay.overlay_id] = frozenset(ancestors)
    return result
