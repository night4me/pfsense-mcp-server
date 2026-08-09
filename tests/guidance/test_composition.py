"""ADR-018 Step 3: compose_guidance_evidence() -- assembly correctness,
fail-closed validation, and the evidence-level-cap defensive property.
"""

from __future__ import annotations

import pytest

from pfsense_mcp.guidance.appliance_identity import ApplianceIdentity, ObservedEdition
from pfsense_mcp.guidance.composition import compose_guidance_evidence
from pfsense_mcp.guidance.evidence import ApplicabilityState, EvidenceLevel, EvidenceReference
from pfsense_mcp.guidance.models import Edition, RetrievalMode, excerpt_hash

_VALID_URL = "https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html"


def _identity(**overrides: object) -> ApplianceIdentity:
    defaults: dict[str, object] = {
        "observed_edition": ObservedEdition.KNOWN_PLUS,
        "observed_version": "26.03.1",
        "identity_source": "SystemVersion.base (pfsense_get_system_version)",
        "resolved_at": "2026-08-09T00:00:00+00:00",
    }
    defaults.update(overrides)
    return ApplianceIdentity(**defaults)


def _reference(**overrides: object) -> EvidenceReference:
    excerpt = overrides.pop("content_excerpt", "Aliases define groups of ports, hosts, or networks.")
    defaults: dict[str, object] = {
        "capability": "ALIAS_READ",
        "source_id": "netgate_docs_aliases",
        "title": "Aliases",
        "canonical_url": _VALID_URL,
        "content_excerpt": excerpt,
        "content_hash": excerpt_hash(excerpt),
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


# --- Basic assembly ---


def test_composes_identity_fields_verbatim() -> None:
    identity = _identity()
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(_reference(),))

    assert evidence.capability == "ALIAS_READ"
    assert evidence.observed_edition is identity.observed_edition
    assert evidence.observed_version == identity.observed_version
    assert evidence.appliance_identity_source == identity.identity_source


def test_guidance_tuple_preserves_input_references_unmodified() -> None:
    identity = _identity()
    ref = _reference()
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(ref,))

    assert evidence.guidance == (ref,)
    assert evidence.guidance[0] is ref


def test_empty_guidance_yields_no_official_guidance_found() -> None:
    identity = _identity()
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=())

    assert evidence.overall_state is ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND
    assert evidence.guidance == ()


def test_overall_state_is_least_favorable_among_entries() -> None:
    identity = _identity()
    applicable = _reference(source_id="doc_one", applicability=ApplicabilityState.APPLICABLE)
    stale = _reference(source_id="doc_two", applicability=ApplicabilityState.STALE)
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(applicable, stale))

    assert evidence.overall_state is ApplicabilityState.STALE


# --- Fail-closed validation ---


def test_rejects_mismatched_capability() -> None:
    identity = _identity()
    mismatched = _reference(capability="FIREWALL_READ")
    with pytest.raises(ValueError, match="capability"):
        compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(mismatched,))


def test_rejects_mismatched_observed_edition() -> None:
    identity = _identity(observed_edition=ObservedEdition.KNOWN_CE, observed_version="2.7.2")
    mismatched = _reference(observed_edition_used=ObservedEdition.KNOWN_PLUS, observed_version_used="2.7.2")
    with pytest.raises(ValueError, match="observed_edition_used"):
        compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(mismatched,))


def test_rejects_mismatched_observed_version() -> None:
    identity = _identity(observed_version="26.03.1")
    mismatched = _reference(observed_version_used="26.03.0")
    with pytest.raises(ValueError, match="observed_version_used"):
        compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(mismatched,))


def test_rejects_mismatched_observed_version_when_identity_version_is_none() -> None:
    identity = _identity(observed_version=None, observed_edition=ObservedEdition.UNKNOWN)
    mismatched = _reference(
        observed_edition_used=ObservedEdition.UNKNOWN,
        observed_version_used="26.03.1",
    )
    with pytest.raises(ValueError, match="observed_version_used"):
        compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(mismatched,))


def test_accepts_matching_none_observed_version() -> None:
    """The None-vs-None edge case: an UNKNOWN-edition appliance with no
    observed version must not spuriously trip the mismatch check just
    because both sides are None."""
    identity = _identity(observed_version=None, observed_edition=ObservedEdition.UNKNOWN)
    matching = _reference(observed_edition_used=ObservedEdition.UNKNOWN, observed_version_used=None)
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(matching,))
    assert evidence.observed_version is None


def test_input_list_mutation_after_the_call_does_not_affect_the_result() -> None:
    """Defensive-copy property: guidance is converted to a tuple before
    storage, so mutating the caller's original list afterward cannot
    silently change an already-returned GuidanceEvidence."""
    identity = _identity()
    ref = _reference()
    mutable_list = [ref]
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=mutable_list)

    mutable_list.append(_reference(source_id="doc_two"))
    mutable_list.clear()

    assert evidence.guidance == (ref,)


# --- Defensive evidence-level cap ---


def test_inconsistent_applicability_is_capped_for_overall_state_but_not_stored() -> None:
    """A caller-supplied EvidenceReference whose applicability is
    inconsistent with its own evidence_level (should never happen
    upstream, but this function does not trust that) must not make
    overall_state more favorable than the evidence actually supports --
    while the stored EvidenceReference itself remains exactly as given,
    since it is frozen and this function never mutates it."""
    identity = _identity()
    inconsistent = _reference(
        evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
        applicability=ApplicabilityState.APPLICABLE,
    )
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(inconsistent,))

    assert evidence.overall_state is ApplicabilityState.VERSION_UNCONFIRMED
    assert evidence.guidance[0].applicability is ApplicabilityState.APPLICABLE, "stored evidence must be untouched"


def test_cap_does_not_affect_already_unfavorable_states() -> None:
    identity = _identity()
    ref = _reference(evidence_level=EvidenceLevel.UNKNOWN, applicability=ApplicabilityState.EDITION_MISMATCH)
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(ref,))

    assert evidence.overall_state is ApplicabilityState.EDITION_MISMATCH


# --- overlay_chain ---


def test_overlay_chain_defaults_to_union_of_entries_deduplicated_in_order() -> None:
    identity = _identity()
    first = _reference(source_id="doc_one", applicable_overlay_chain=("release_note_one", "errata_one"))
    second = _reference(source_id="doc_two", applicable_overlay_chain=("errata_one", "errata_two"))
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=(first, second))

    assert evidence.overlay_chain == ("release_note_one", "errata_one", "errata_two")


def test_overlay_chain_explicit_override_bypasses_default() -> None:
    identity = _identity()
    ref = _reference(applicable_overlay_chain=("release_note_one",))
    evidence = compose_guidance_evidence(
        capability="ALIAS_READ",
        identity=identity,
        guidance=(ref,),
        overlay_chain=("a_different_order",),
    )

    assert evidence.overlay_chain == ("a_different_order",)


def test_overlay_chain_defaults_to_empty_tuple_with_no_entries() -> None:
    identity = _identity()
    evidence = compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=())
    assert evidence.overlay_chain == ()
