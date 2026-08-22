"""ADR-018 Step (bridge slice): compute_entry_applicability() -- the
single-entry decision procedure specified in
docs/VERSION_AWARE_GUIDANCE.md's "Single-entry applicability decision
procedure" section, owner-authorized and implemented 2026-08-09.

Every scenario the design's own required-tests list names is its own
test here, not inferred from a happy path: BOTH edition, matching
edition, mismatching edition, UNKNOWN appliance edition for edition-
specific guidance, exact version match, missing appliance version,
differing version, unversioned guidance, superseded guidance, caveated
guidance, deterministic first-match priority, and EvidenceLevel capping.
"""

from __future__ import annotations

from pfsense_mcp.guidance.appliance_identity import ObservedEdition
from pfsense_mcp.guidance.applicability import compute_entry_applicability
from pfsense_mcp.guidance.evidence import ReleaseOverlay
from pfsense_mcp.guidance.models import UNVERSIONED, ApplicabilityState, Edition, EvidenceLevel, excerpt_hash

_VALID_URL = "https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html"


def _entry_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "entry_id": "entry_one",
        "entry_capability": "ALIAS_READ",
        "entry_edition": Edition.CE,
        "entry_version_applicability": "2.7.2",
        "entry_evidence_level": EvidenceLevel.EXPLICIT_VERSION_SCOPED,
        "observed_edition": ObservedEdition.KNOWN_CE,
        "observed_version": "2.7.2",
        "all_overlays": (),
    }
    defaults.update(overrides)
    return defaults


def _overlay(overlay_id: str, **overrides: object) -> ReleaseOverlay:
    summary = overrides.pop("caveat_summary", f"Caveat for {overlay_id}, project-authored summary.")
    verification = overrides.pop("source_verification_excerpt", f"Caveat for {overlay_id}.")
    defaults: dict[str, object] = {
        "overlay_id": overlay_id,
        "capability": "ALIAS_READ",
        "applies_to_version": "2.7.2",
        "applies_to_edition": Edition.CE,
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


# --- Edition dimension ---


def test_both_edition_is_applicable_regardless_of_observed_edition():
    for observed in (ObservedEdition.KNOWN_CE, ObservedEdition.KNOWN_PLUS, ObservedEdition.UNKNOWN):
        state, _ = compute_entry_applicability(
            **_entry_kwargs(
                entry_edition=Edition.BOTH,
                entry_version_applicability=UNVERSIONED,
                entry_evidence_level=EvidenceLevel.EXPLICIT_UNVERSIONED,
                observed_edition=observed,
            )
        )
        assert state is ApplicabilityState.APPLICABLE


def test_matching_edition_is_applicable():
    state, _ = compute_entry_applicability(
        **_entry_kwargs(entry_edition=Edition.CE, observed_edition=ObservedEdition.KNOWN_CE)
    )
    assert state is ApplicabilityState.APPLICABLE


def test_mismatching_edition_is_edition_mismatch():
    state, chain = compute_entry_applicability(
        **_entry_kwargs(entry_edition=Edition.CE, observed_edition=ObservedEdition.KNOWN_PLUS)
    )
    assert state is ApplicabilityState.EDITION_MISMATCH
    assert chain == ()


def test_unknown_appliance_edition_for_edition_specific_guidance_is_version_unconfirmed():
    """The owner-confirmed resolution of the real gap found while
    specifying this procedure: an edition-specific entry when the
    observed edition is UNKNOWN routes to VERSION_UNCONFIRMED, never
    EDITION_MISMATCH and never APPLICABLE."""
    state, _ = compute_entry_applicability(
        **_entry_kwargs(entry_edition=Edition.CE, observed_edition=ObservedEdition.UNKNOWN)
    )
    assert state is ApplicabilityState.VERSION_UNCONFIRMED


# --- Version dimension ---


def test_exact_version_match_is_applicable():
    state, _ = compute_entry_applicability(
        **_entry_kwargs(entry_version_applicability="2.7.2", observed_version="2.7.2")
    )
    assert state is ApplicabilityState.APPLICABLE


def test_missing_appliance_version_is_version_unconfirmed():
    state, _ = compute_entry_applicability(**_entry_kwargs(entry_version_applicability="2.7.2", observed_version=None))
    assert state is ApplicabilityState.VERSION_UNCONFIRMED


def test_differing_version_is_version_unconfirmed_not_edition_mismatch_or_excluded():
    state, _ = compute_entry_applicability(
        **_entry_kwargs(entry_version_applicability="2.7.2", observed_version="2.8.0")
    )
    assert state is ApplicabilityState.VERSION_UNCONFIRMED


def test_unversioned_guidance_is_applicable_regardless_of_observed_version():
    for observed in (None, "2.7.2", "99.99.99"):
        state, _ = compute_entry_applicability(
            **_entry_kwargs(
                entry_version_applicability=UNVERSIONED,
                entry_evidence_level=EvidenceLevel.EXPLICIT_UNVERSIONED,
                observed_version=observed,
            )
        )
        assert state is ApplicabilityState.APPLICABLE


# --- Overlay dimension ---


def test_caveated_entry_is_partially_applicable_with_reported_chain():
    overlay = _overlay("caveat_one")
    state, chain = compute_entry_applicability(**_entry_kwargs(all_overlays=(overlay,)))
    assert state is ApplicabilityState.PARTIALLY_APPLICABLE
    assert chain == ("caveat_one",)


def test_superseded_entry_is_stale_with_reported_chain():
    overlay = _overlay("supersedes_one", supersedes_id="entry_one")
    state, chain = compute_entry_applicability(**_entry_kwargs(all_overlays=(overlay,)))
    assert state is ApplicabilityState.STALE
    assert chain == ("supersedes_one",)


def test_no_matching_overlay_is_applicable_not_partially_applicable():
    unrelated = _overlay("unrelated_overlay", capability="FIREWALL_READ")
    state, chain = compute_entry_applicability(**_entry_kwargs(all_overlays=(unrelated,)))
    assert state is ApplicabilityState.APPLICABLE
    assert chain == ()


def test_overlay_with_unconfirmed_edition_is_not_a_candidate():
    """An edition-specific overlay is excluded from candidacy (not
    merely 'uncertain') when observed_edition is UNKNOWN -- conservative
    by design, so uncertain overlay evidence never injects
    STALE/PARTIALLY_APPLICABLE onto an entry."""
    overlay = _overlay("caveat_one", applies_to_edition=Edition.CE)
    state, chain = compute_entry_applicability(
        **_entry_kwargs(
            entry_edition=Edition.BOTH,
            entry_version_applicability=UNVERSIONED,
            entry_evidence_level=EvidenceLevel.EXPLICIT_UNVERSIONED,
            observed_edition=ObservedEdition.UNKNOWN,
            all_overlays=(overlay,),
        )
    )
    assert state is ApplicabilityState.APPLICABLE
    assert chain == ()


# --- Deterministic first-match priority ---


def test_stale_wins_over_partially_applicable_when_both_conditions_present():
    """A real red-team-named scenario: two different overlays for the
    same entry, one superseding it and one merely caveating it -- STALE
    must win, never PARTIALLY_APPLICABLE."""
    superseding = _overlay("supersedes_one", supersedes_id="entry_one")
    caveating = _overlay("caveat_two")
    state, chain = compute_entry_applicability(**_entry_kwargs(all_overlays=(superseding, caveating)))
    assert state is ApplicabilityState.STALE
    assert chain == ("supersedes_one",)


def test_edition_mismatch_wins_over_stale():
    """EDITION_MISMATCH is checked first, ahead of supersession -- a
    confirmed-wrong-edition document is never reported as merely STALE."""
    overlay = _overlay("supersedes_one", supersedes_id="entry_one", applies_to_edition=Edition.PLUS)
    state, _ = compute_entry_applicability(
        **_entry_kwargs(
            entry_edition=Edition.CE,
            observed_edition=ObservedEdition.KNOWN_PLUS,
            all_overlays=(overlay,),
        )
    )
    assert state is ApplicabilityState.EDITION_MISMATCH


def test_version_unconfirmed_wins_over_partially_applicable():
    """A caveated entry whose own version is unconfirmed must still
    report VERSION_UNCONFIRMED, not PARTIALLY_APPLICABLE -- uncertainty
    is checked ahead of the caveat/applicable branches."""
    overlay = _overlay("caveat_one", applies_to_version=UNVERSIONED)
    state, chain = compute_entry_applicability(**_entry_kwargs(observed_version=None, all_overlays=(overlay,)))
    assert state is ApplicabilityState.VERSION_UNCONFIRMED
    assert chain == ()


# --- EvidenceLevel capping (independent second fail-safe layer) ---


def test_inferred_evidence_level_caps_applicable_to_version_unconfirmed():
    state, _ = compute_entry_applicability(
        **_entry_kwargs(entry_evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS)
    )
    assert state is ApplicabilityState.VERSION_UNCONFIRMED


def test_unknown_evidence_level_caps_partially_applicable_to_version_unconfirmed():
    overlay = _overlay("caveat_one")
    state, chain = compute_entry_applicability(
        **_entry_kwargs(entry_evidence_level=EvidenceLevel.UNKNOWN, all_overlays=(overlay,))
    )
    assert state is ApplicabilityState.VERSION_UNCONFIRMED
    assert chain == (), "a capped-down entry's overlay chain must not be reported as if still applicable"


def test_evidence_level_cap_never_affects_stale_or_edition_mismatch():
    overlay = _overlay("supersedes_one", supersedes_id="entry_one")
    stale_state, stale_chain = compute_entry_applicability(
        **_entry_kwargs(entry_evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS, all_overlays=(overlay,))
    )
    assert stale_state is ApplicabilityState.STALE
    assert stale_chain == ("supersedes_one",)

    mismatch_state, _ = compute_entry_applicability(
        **_entry_kwargs(
            entry_edition=Edition.CE,
            observed_edition=ObservedEdition.KNOWN_PLUS,
            entry_evidence_level=EvidenceLevel.UNKNOWN,
        )
    )
    assert mismatch_state is ApplicabilityState.EDITION_MISMATCH


# --- Determinism ---


def test_identical_inputs_produce_identical_output():
    overlay = _overlay("caveat_one")
    first = compute_entry_applicability(**_entry_kwargs(all_overlays=(overlay,)))
    second = compute_entry_applicability(**_entry_kwargs(all_overlays=(overlay,)))
    assert first == second
