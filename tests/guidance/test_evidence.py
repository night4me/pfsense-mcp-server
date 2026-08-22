"""ADR-018 step 2: EvidenceLevel, ApplicabilityState, ReleaseOverlay,
EvidenceReference, GuidanceEvidence -- construction, validation,
provenance-completeness, and evidence-representation coverage.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pfsense_mcp.guidance.appliance_identity import ObservedEdition
from pfsense_mcp.guidance.evidence import (
    APPLICABILITY_STATE_ORDER,
    ApplicabilityState,
    EvidenceLevel,
    EvidenceReference,
    GuidanceEvidence,
    ReleaseOverlay,
)
from pfsense_mcp.guidance.models import Edition, RetrievalMode, excerpt_hash

_VALID_URL = "https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html"


def _overlay(**overrides: object) -> ReleaseOverlay:
    summary = overrides.pop("caveat_summary", "Behavior changed in this release, per project-authored summary.")
    verification = overrides.pop("source_verification_excerpt", "Behavior changed in this release.")
    defaults: dict[str, object] = {
        "overlay_id": "test_overlay_one",
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


def _evidence_reference(**overrides: object) -> EvidenceReference:
    summary = overrides.pop("summary", "Aliases group ports, hosts, or networks so rules can reference them by name.")
    defaults: dict[str, object] = {
        "capability": "ALIAS_READ",
        "source_id": "netgate_docs_aliases",
        "title": "Aliases",
        "canonical_url": _VALID_URL,
        "summary": summary,
        "summary_hash": excerpt_hash(summary),
        "pfsense_edition": Edition.BOTH,
        "evidence_level": EvidenceLevel.EXPLICIT_VERSION_SCOPED,
        "applicability": ApplicabilityState.APPLICABLE,
        "applicable_overlay_chain": (),
        "observed_edition_used": ObservedEdition.KNOWN_PLUS,
        "observed_version_used": "26.03.1",
        "retrieval_mode": RetrievalMode.BUNDLED_SNAPSHOT,
        "snapshot_version": "guidance-registry-2026-08-09",
    }
    defaults.update(overrides)
    return EvidenceReference(**defaults)


# --- EvidenceLevel: every member constructible and distinct ---


@pytest.mark.parametrize(
    "level",
    [
        EvidenceLevel.EXPLICIT_VERSION_SCOPED,
        EvidenceLevel.EXPLICIT_UNVERSIONED,
        EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
        EvidenceLevel.UNKNOWN,
    ],
)
def test_every_evidence_level_is_constructible_on_a_release_overlay(level: EvidenceLevel) -> None:
    overlay = _overlay(evidence_level=level)
    assert overlay.evidence_level is level


def test_evidence_level_has_exactly_four_members() -> None:
    assert {m.value for m in EvidenceLevel} == {
        "explicit_version_scoped",
        "explicit_unversioned",
        "inferred_from_current_docs",
        "unknown",
    }


# --- ApplicabilityState: every member constructible, closed set ---


@pytest.mark.parametrize(
    "state",
    [
        ApplicabilityState.APPLICABLE,
        ApplicabilityState.PARTIALLY_APPLICABLE,
        ApplicabilityState.VERSION_UNCONFIRMED,
        ApplicabilityState.EDITION_MISMATCH,
        ApplicabilityState.STALE,
        ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND,
    ],
)
def test_every_applicability_state_is_constructible_on_an_evidence_reference(state: ApplicabilityState) -> None:
    ref = _evidence_reference(applicability=state)
    assert ref.applicability is state


def test_applicability_state_is_exactly_six_members_no_conflicting_guidance() -> None:
    """ADR-018's accepted text explicitly excludes CONFLICTING_GUIDANCE
    from this enum -- see evidence.py's ApplicabilityState docstring and
    the implementation report's flagged discrepancy against a later
    informal restatement that named it as a member."""
    assert {s.value for s in ApplicabilityState} == {
        "applicable",
        "partially_applicable",
        "version_unconfirmed",
        "edition_mismatch",
        "stale",
        "no_official_guidance_found",
    }
    assert not hasattr(ApplicabilityState, "CONFLICTING_GUIDANCE")


def test_applicability_state_order_contains_every_member_exactly_once() -> None:
    assert set(APPLICABILITY_STATE_ORDER) == set(ApplicabilityState)
    assert len(APPLICABILITY_STATE_ORDER) == len(set(APPLICABILITY_STATE_ORDER))


# --- ReleaseOverlay: validation / malformed entries ---


def test_release_overlay_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _overlay(unexpected_field="not allowed")


def test_release_overlay_rejects_non_allowlisted_host() -> None:
    with pytest.raises(ValidationError):
        _overlay(canonical_url="https://evil.example.com/aliases.html")


def test_release_overlay_rejects_non_https_scheme() -> None:
    with pytest.raises(ValidationError):
        _overlay(canonical_url="http://docs.netgate.com/aliases.html")


def test_release_overlay_rejects_malformed_caveat_summary_hash() -> None:
    with pytest.raises(ValidationError):
        _overlay(caveat_summary_hash="not-a-hex-digest")


def test_release_overlay_rejects_malformed_verification_hash() -> None:
    with pytest.raises(ValidationError):
        _overlay(source_verification_hash="not-a-hex-digest")


def test_release_overlay_rejects_oversized_summary() -> None:
    with pytest.raises(ValidationError):
        _overlay(caveat_summary="x" * 2001, caveat_summary_hash=excerpt_hash("x" * 2001))


def test_release_overlay_rejects_oversized_verification_excerpt() -> None:
    with pytest.raises(ValidationError):
        _overlay(source_verification_excerpt="x" * 301, source_verification_hash=excerpt_hash("x" * 301))


def test_release_overlay_rejects_malformed_overlay_id() -> None:
    with pytest.raises(ValidationError):
        _overlay(overlay_id="NOT-A-VALID-SLUG!")


def test_release_overlay_rejects_malformed_supersedes_id() -> None:
    with pytest.raises(ValidationError):
        _overlay(supersedes_id="not a valid slug")


def test_release_overlay_accepts_valid_supersedes_id() -> None:
    overlay = _overlay(overlay_id="errata_one", supersedes_id="release_note_one")
    assert overlay.supersedes_id == "release_note_one"


def test_release_overlay_is_frozen() -> None:
    overlay = _overlay()
    with pytest.raises(ValidationError):
        overlay.applies_to_version = "changed"  # type: ignore[misc]


# --- EvidenceReference: provenance completeness ---


def test_evidence_reference_requires_every_provenance_field() -> None:
    """No optional gap in the required-field set -- pydantic enforces
    this structurally; this test asserts the actual required-field list
    matches what ADR-018 specifies, not merely "some fields are
    required."""
    required = {name for name, field in EvidenceReference.model_fields.items() if field.is_required()}
    assert required == {
        "capability",
        "source_id",
        "title",
        "canonical_url",
        "summary",
        "summary_hash",
        "pfsense_edition",
        "evidence_level",
        "applicability",
        "observed_edition_used",
        "observed_version_used",
        "retrieval_mode",
        "snapshot_version",
    }


def test_evidence_reference_applicable_overlay_chain_defaults_to_empty_tuple() -> None:
    ref = _evidence_reference()
    assert ref.applicable_overlay_chain == ()


def test_evidence_reference_preserves_ordered_overlay_chain_not_a_set() -> None:
    """The exact class of bug the acceptance review found once already
    (Finding 6, applied incompletely on first pass) -- explicit
    regression coverage at the per-EvidenceReference level."""
    ordered = ("release_note_one", "errata_one")
    ref = _evidence_reference(applicable_overlay_chain=ordered)
    assert ref.applicable_overlay_chain == ordered
    assert isinstance(ref.applicable_overlay_chain, tuple)


def test_evidence_reference_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _evidence_reference(unexpected_field="nope")


def test_evidence_reference_no_field_named_or_typed_like_authorization() -> None:
    """Structural G1-style check: no field name suggests capability,
    endpoint, method, or confirmation-token semantics."""
    disallowed_substrings = ("endpoint", "method", "confirmation_token", "capability_grant", "authoriz")
    for field_name in EvidenceReference.model_fields:
        lowered = field_name.lower()
        assert not any(bad in lowered for bad in disallowed_substrings), field_name


# --- GuidanceEvidence: aggregate composition ---


def test_guidance_evidence_preserves_ordered_overlay_chain_not_a_set() -> None:
    ordered = ("release_note_one", "errata_one", "errata_two")
    evidence = GuidanceEvidence(
        capability="ALIAS_READ",
        observed_edition=ObservedEdition.KNOWN_PLUS,
        observed_version="26.03.1",
        appliance_identity_source="SystemVersion.base (pfsense_get_system_version)",
        guidance=(_evidence_reference(),),
        overlay_chain=ordered,
        overall_state=ApplicabilityState.APPLICABLE,
    )
    assert evidence.overlay_chain == ordered


def test_guidance_evidence_no_official_guidance_found_with_empty_guidance_tuple() -> None:
    evidence = GuidanceEvidence(
        capability="SOME_UNREGISTERED_CAPABILITY",
        observed_edition=ObservedEdition.UNKNOWN,
        observed_version=None,
        appliance_identity_source="SystemVersion.base (pfsense_get_system_version)",
        guidance=(),
        overlay_chain=(),
        overall_state=ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND,
    )
    assert evidence.guidance == ()
    assert evidence.overall_state is ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND


def test_guidance_evidence_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        GuidanceEvidence(
            capability="ALIAS_READ",
            observed_edition=ObservedEdition.UNKNOWN,
            observed_version=None,
            appliance_identity_source="x",
            guidance=(),
            overlay_chain=(),
            overall_state=ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND,
            live_page_text="should never be a field",  # type: ignore[call-arg]
        )


def test_guidance_evidence_has_no_field_carrying_arbitrary_live_page_text() -> None:
    disallowed_substrings = ("page_text", "raw_html", "live_content", "full_page")
    for field_name in GuidanceEvidence.model_fields:
        lowered = field_name.lower()
        assert not any(bad in lowered for bad in disallowed_substrings), field_name


def test_guidance_evidence_keeps_observed_state_and_guidance_as_separate_typed_fields() -> None:
    """The structural OBSERVED FACT / OFFICIAL GUIDANCE / MODEL
    INFERENCE separation ADR-018 S8 asks for, verified directly against
    the model's own field types rather than asserted in prose."""
    fields = GuidanceEvidence.model_fields
    assert fields["observed_edition"].annotation is ObservedEdition
    assert fields["observed_version"].annotation == (str | None)
    assert "EvidenceReference" in str(fields["guidance"].annotation)
    assert fields["overall_state"].annotation is ApplicabilityState
