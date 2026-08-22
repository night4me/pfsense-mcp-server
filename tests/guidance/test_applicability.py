"""ADR-018 step 2: deterministic applicability/registry-integrity
primitives -- cap_applicability_by_evidence_level(), compute_overall_state(),
find_duplicate_scope_conflicts(), find_supersession_chain_defects(),
order_overlay_chain(), may_prepare().
"""

from __future__ import annotations

import itertools

import pytest

from pfsense_mcp.guidance.applicability import (
    cap_applicability_by_evidence_level,
    compute_overall_state,
    find_duplicate_scope_conflicts,
    find_supersession_chain_defects,
    may_prepare,
    order_overlay_chain,
)
from pfsense_mcp.guidance.evidence import ApplicabilityState, EvidenceLevel, ReleaseOverlay
from pfsense_mcp.guidance.models import Edition, excerpt_hash

_VALID_URL = "https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html"


def _overlay(overlay_id: str, **overrides: object) -> ReleaseOverlay:
    summary = overrides.pop("caveat_summary", f"Caveat for {overlay_id}, project-authored summary.")
    verification = overrides.pop("source_verification_excerpt", f"Caveat for {overlay_id}.")
    defaults: dict[str, object] = {
        "overlay_id": overlay_id,
        "capability": "ALIAS_READ",
        "applies_to_version": "26.03.1",
        "applies_to_edition": Edition.BOTH,
        "evidence_level": EvidenceLevel.EXPLICIT_VERSION_SCOPED,
        "supersedes_id": None,
        "caveat_summary": summary,
        "caveat_summary_hash": excerpt_hash(summary),
        "source_verification_excerpt": verification,
        "source_verification_hash": excerpt_hash(verification),
        "canonical_url": _VALID_URL,
    }
    defaults.update(overrides)
    return ReleaseOverlay(**defaults)


# --- cap_applicability_by_evidence_level(): evidence-strength non-escalation ---


@pytest.mark.parametrize(
    ("level", "computed", "expected"),
    [
        (EvidenceLevel.EXPLICIT_VERSION_SCOPED, ApplicabilityState.APPLICABLE, ApplicabilityState.APPLICABLE),
        (
            EvidenceLevel.EXPLICIT_UNVERSIONED,
            ApplicabilityState.PARTIALLY_APPLICABLE,
            ApplicabilityState.PARTIALLY_APPLICABLE,
        ),
        (
            EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
            ApplicabilityState.APPLICABLE,
            ApplicabilityState.VERSION_UNCONFIRMED,
        ),
        (
            EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
            ApplicabilityState.PARTIALLY_APPLICABLE,
            ApplicabilityState.VERSION_UNCONFIRMED,
        ),
        (EvidenceLevel.UNKNOWN, ApplicabilityState.APPLICABLE, ApplicabilityState.VERSION_UNCONFIRMED),
        (EvidenceLevel.UNKNOWN, ApplicabilityState.PARTIALLY_APPLICABLE, ApplicabilityState.VERSION_UNCONFIRMED),
    ],
)
def test_cap_applicability_never_escalates_weak_evidence_to_applicable(
    level: EvidenceLevel, computed: ApplicabilityState, expected: ApplicabilityState
) -> None:
    assert cap_applicability_by_evidence_level(level, computed) is expected


@pytest.mark.parametrize(
    ("level", "state"),
    itertools.product(
        [EvidenceLevel.INFERRED_FROM_CURRENT_DOCS, EvidenceLevel.UNKNOWN],
        [
            ApplicabilityState.VERSION_UNCONFIRMED,
            ApplicabilityState.STALE,
            ApplicabilityState.EDITION_MISMATCH,
            ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND,
        ],
    ),
)
def test_cap_applicability_does_not_touch_states_already_no_more_favorable_than_unconfirmed(
    level: EvidenceLevel, state: ApplicabilityState
) -> None:
    """Capping only ever pulls APPLICABLE/PARTIALLY_APPLICABLE down --
    it must never change an already-weaker-or-equal state (e.g. must not
    "upgrade" EDITION_MISMATCH to VERSION_UNCONFIRMED, which would be
    just as wrong an escalation in the other direction)."""
    assert cap_applicability_by_evidence_level(level, state) is state


@pytest.mark.parametrize(
    ("level", "state"),
    itertools.product(
        [EvidenceLevel.EXPLICIT_VERSION_SCOPED, EvidenceLevel.EXPLICIT_UNVERSIONED],
        list(ApplicabilityState),
    ),
)
def test_cap_applicability_is_a_no_op_for_explicit_evidence_levels(
    level: EvidenceLevel, state: ApplicabilityState
) -> None:
    assert cap_applicability_by_evidence_level(level, state) is state


# --- compute_overall_state(): least-favorable-wins ordering ---


def test_compute_overall_state_empty_input_is_no_official_guidance_found() -> None:
    assert compute_overall_state([]) is ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND


@pytest.mark.parametrize("state", list(ApplicabilityState))
def test_compute_overall_state_single_state_returns_itself(state: ApplicabilityState) -> None:
    assert compute_overall_state([state]) is state


def test_compute_overall_state_picks_least_favorable_of_two() -> None:
    assert (
        compute_overall_state([ApplicabilityState.APPLICABLE, ApplicabilityState.EDITION_MISMATCH])
        is ApplicabilityState.EDITION_MISMATCH
    )


def test_compute_overall_state_picks_least_favorable_regardless_of_input_order() -> None:
    ordered = list(ApplicabilityState)
    for permutation in (ordered, list(reversed(ordered))):
        assert compute_overall_state(permutation) is ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND


@pytest.mark.parametrize(
    ("states", "expected"),
    [
        (
            [ApplicabilityState.APPLICABLE, ApplicabilityState.APPLICABLE],
            ApplicabilityState.APPLICABLE,
        ),
        (
            [ApplicabilityState.APPLICABLE, ApplicabilityState.PARTIALLY_APPLICABLE, ApplicabilityState.STALE],
            ApplicabilityState.STALE,
        ),
        (
            [ApplicabilityState.VERSION_UNCONFIRMED, ApplicabilityState.EDITION_MISMATCH],
            ApplicabilityState.EDITION_MISMATCH,
        ),
    ],
)
def test_compute_overall_state_representative_combinations(
    states: list[ApplicabilityState], expected: ApplicabilityState
) -> None:
    assert compute_overall_state(states) is expected


# --- find_duplicate_scope_conflicts(): conflicting guidance representable ---


def test_no_conflict_for_a_single_overlay() -> None:
    assert find_duplicate_scope_conflicts([_overlay("overlay_single")]) == []


def test_conflict_detected_for_unconnected_overlapping_overlays() -> None:
    a = _overlay("overlay_a")
    b = _overlay("overlay_b")
    conflicts = find_duplicate_scope_conflicts([a, b])
    assert conflicts == [("overlay_a", "overlay_b")]


def test_no_conflict_when_connected_by_supersession() -> None:
    a = _overlay("overlay_a")
    b = _overlay("overlay_b", supersedes_id="overlay_a")
    assert find_duplicate_scope_conflicts([a, b]) == []


def test_no_conflict_for_different_capability() -> None:
    a = _overlay("overlay_a", capability="ALIAS_READ")
    b = _overlay("overlay_b", capability="FIREWALL_READ")
    assert find_duplicate_scope_conflicts([a, b]) == []


def test_no_conflict_for_different_version() -> None:
    a = _overlay("overlay_a", applies_to_version="26.03.1")
    b = _overlay("overlay_b", applies_to_version="25.07.1")
    assert find_duplicate_scope_conflicts([a, b]) == []


def test_no_conflict_for_incompatible_editions() -> None:
    a = _overlay("overlay_a", applies_to_edition=Edition.CE)
    b = _overlay("overlay_b", applies_to_edition=Edition.PLUS)
    assert find_duplicate_scope_conflicts([a, b]) == []


def test_conflict_when_one_edition_is_both() -> None:
    a = _overlay("overlay_a", applies_to_edition=Edition.CE)
    b = _overlay("overlay_b", applies_to_edition=Edition.BOTH)
    assert find_duplicate_scope_conflicts([a, b]) == [("overlay_a", "overlay_b")]


def test_conflict_not_flattened_multiple_pairs_all_reported() -> None:
    a = _overlay("overlay_a")
    b = _overlay("overlay_b")
    c = _overlay("overlay_c")
    conflicts = find_duplicate_scope_conflicts([a, b, c])
    assert set(conflicts) == {("overlay_a", "overlay_b"), ("overlay_a", "overlay_c"), ("overlay_b", "overlay_c")}


# --- find_supersession_chain_defects(): dangling references and cycles ---


def test_no_defects_for_valid_chain() -> None:
    a = _overlay("base_note")
    b = _overlay("errata_one", supersedes_id="base_note")
    assert find_supersession_chain_defects([a, b]) == {}


def test_dangling_reference_is_a_defect() -> None:
    a = _overlay("errata_one", supersedes_id="nonexistent_id")
    defects = find_supersession_chain_defects([a])
    assert "errata_one" in defects
    assert "nonexistent_id" in defects["errata_one"]


def test_direct_cycle_is_a_defect() -> None:
    a = _overlay("overlay_a", supersedes_id="overlay_b")
    b = _overlay("overlay_b", supersedes_id="overlay_a")
    defects = find_supersession_chain_defects([a, b])
    assert defects  # at least one side of the cycle flagged


def test_self_reference_is_a_defect() -> None:
    a = _overlay("overlay_a", supersedes_id="overlay_a")
    defects = find_supersession_chain_defects([a])
    assert "overlay_a" in defects


# --- order_overlay_chain(): errata correction chain preserved, not flattened ---


def test_order_overlay_chain_three_level_errata_correction_chain() -> None:
    """The owner's own example: base doc -> release note -> errata."""
    release_note = _overlay("release_note_one")
    errata = _overlay("errata_one", supersedes_id="release_note_one")
    by_id = {"release_note_one": release_note, "errata_one": errata}
    ordered = order_overlay_chain(["errata_one", "release_note_one"], by_id)
    assert ordered == ("release_note_one", "errata_one")


def test_order_overlay_chain_single_entry() -> None:
    entry = _overlay("solo")
    ordered = order_overlay_chain(["solo"], {"solo": entry})
    assert ordered == ("solo",)


def test_order_overlay_chain_four_level_chain_preserves_full_order() -> None:
    a = _overlay("gen1")
    b = _overlay("gen2", supersedes_id="gen1")
    c = _overlay("gen3", supersedes_id="gen2")
    d = _overlay("gen4", supersedes_id="gen3")
    by_id = {"gen1": a, "gen2": b, "gen3": c, "gen4": d}
    ordered = order_overlay_chain(["gen4", "gen1", "gen3", "gen2"], by_id)
    assert ordered == ("gen1", "gen2", "gen3", "gen4")


# --- may_prepare(): the monotonic guidance-veto property, exhaustive ---


@pytest.mark.parametrize(
    ("guidance_required", "guidance_check_passes"),
    list(itertools.product([True, False], repeat=2)),
)
def test_may_prepare_is_always_false_when_existing_authorization_is_false(
    guidance_required: bool, guidance_check_passes: bool
) -> None:
    """The exact property the owner asked to be proven table-driven,
    not just algebraically re-derived in prose: no assignment of the
    guidance terms rescues an unauthorized operation."""
    assert (
        may_prepare(
            existing_authorization=False,
            guidance_required=guidance_required,
            guidance_check_passes=guidance_check_passes,
        )
        is False
    )


@pytest.mark.parametrize(
    ("guidance_required", "guidance_check_passes", "expected"),
    [
        (False, False, True),
        (False, True, True),
        (True, False, False),
        (True, True, True),
    ],
)
def test_may_prepare_with_existing_authorization_true_depends_only_on_guidance_terms(
    guidance_required: bool, guidance_check_passes: bool, expected: bool
) -> None:
    assert (
        may_prepare(
            existing_authorization=True,
            guidance_required=guidance_required,
            guidance_check_passes=guidance_check_passes,
        )
        is expected
    )


def test_may_prepare_full_truth_table_exhaustive() -> None:
    """All 8 combinations in one place, so the property is visible as a
    complete table, not only scattered across parametrized cases."""
    expected = {
        (False, False, False): False,
        (False, False, True): False,
        (False, True, False): False,
        (False, True, True): False,
        (True, False, False): True,
        (True, False, True): True,
        (True, True, False): False,
        (True, True, True): True,
    }
    for (existing_authorization, guidance_required, guidance_check_passes), outcome in expected.items():
        assert (
            may_prepare(
                existing_authorization=existing_authorization,
                guidance_required=guidance_required,
                guidance_check_passes=guidance_check_passes,
            )
            is outcome
        )


def test_may_prepare_guidance_flipping_from_missing_to_valid_never_creates_authorization() -> None:
    """Direct restatement of the owner's own framing: "changing guidance
    from missing to valid must never make an otherwise unauthorized
    operation authorized." """
    for guidance_required in (True, False):
        missing = may_prepare(
            existing_authorization=False, guidance_required=guidance_required, guidance_check_passes=False
        )
        valid = may_prepare(
            existing_authorization=False, guidance_required=guidance_required, guidance_check_passes=True
        )
        assert missing is False
        assert valid is False
