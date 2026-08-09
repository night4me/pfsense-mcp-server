"""Deterministic, offline applicability/registry-integrity primitives
(ADR-018, step 2). Pure functions only -- no I/O, no state, no clock
reads except where a caller-supplied timestamp is compared (none of
that exists yet; TB-G3/caching remain unactivated).

Implements only the decision rules ADR-018's accepted text already
specifies precisely (the EvidenceLevel cap, the fixed overall-state
ordering, the two-part registry-integrity check, the monotonic
guidance-veto formula). Does **not** implement the deferred
STALE/PARTIALLY_APPLICABLE/APPLICABLE decision procedure for a single
entry given its overlay chain -- ADR-018's acceptance record explicitly
preserves that as an open, non-blocking implementation question; this
module represents that boundary explicitly (see
`applicability_state_for_entry_is_not_implemented_here` below) rather
than inventing a policy for it.
"""

from __future__ import annotations

from collections.abc import Sequence

from .evidence import APPLICABILITY_STATE_ORDER, ApplicabilityState, EvidenceLevel, ReleaseOverlay

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


def applicability_state_for_entry_is_not_implemented_here() -> None:
    """Marker function, never called -- documents, in code a future
    implementer will actually encounter, that this module deliberately
    does not decide how a single EvidenceReference's own `applicability`
    field is chosen among APPLICABLE/PARTIALLY_APPLICABLE/STALE for a
    matching-edition, matching-version entry with an overlay chain.
    ADR-018's acceptance record preserves this as an explicitly deferred,
    owner-accepted-as-non-blocking implementation question. Whichever
    session eventually builds `lookup_guidance()`'s extended behavior
    must resolve this deliberately, not by copying this module's
    presence as if it already had.
    """
    raise NotImplementedError(
        "Deferred by ADR-018's acceptance record -- do not implement without a separate decision."
    )


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
