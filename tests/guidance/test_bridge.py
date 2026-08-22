"""bridge_guidance_reference(): GuidanceReference -> EvidenceReference,
per docs/VERSION_AWARE_GUIDANCE.md's "GuidanceReference -> EvidenceReference
bridge" section, owner-authorized and implemented 2026-08-09.
"""

from __future__ import annotations

import pytest

from pfsense_mcp.guidance.appliance_identity import ObservedEdition
from pfsense_mcp.guidance.bridge import bridge_guidance_reference
from pfsense_mcp.guidance.models import (
    ApplicabilityState,
    Edition,
    EvidenceLevel,
    GuidanceReference,
    RetrievalMode,
    excerpt_hash,
)

_VALID_URL = "https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html"
_VALID_SUMMARY = "Aliases group ports, hosts, or networks so rules can reference them by name."


def _reference(**overrides: object) -> GuidanceReference:
    defaults: dict[str, object] = {
        "capability": "ALIAS_READ",
        "source_id": "netgate_docs_aliases",
        "title": "Aliases",
        "canonical_url": _VALID_URL,
        "summary": _VALID_SUMMARY,
        "summary_hash": excerpt_hash(_VALID_SUMMARY),
        "pfsense_edition": Edition.BOTH,
        "trust_label": "pinned-summary",
        "applicability": ApplicabilityState.APPLICABLE,
        "evidence_level": EvidenceLevel.EXPLICIT_UNVERSIONED,
        "applicable_overlay_chain": (),
        "observed_edition_used": ObservedEdition.KNOWN_PLUS,
        "observed_version_used": "26.03.1",
        "retrieval_mode": RetrievalMode.BUNDLED_SNAPSHOT,
        "snapshot_version": "guidance-registry-2026-08-08",
    }
    defaults.update(overrides)
    return GuidanceReference(**defaults)


def test_bridge_copies_every_field_except_trust_label_exactly():
    ref = _reference(applicable_overlay_chain=("release_note_one", "errata_one"))
    result = bridge_guidance_reference(ref)

    assert result.capability == ref.capability
    assert result.source_id == ref.source_id
    assert result.title == ref.title
    assert result.canonical_url == ref.canonical_url
    assert result.summary == ref.summary
    assert result.summary_hash == ref.summary_hash
    assert result.pfsense_edition == ref.pfsense_edition
    assert result.evidence_level == ref.evidence_level
    assert result.applicability == ref.applicability
    assert result.applicable_overlay_chain == ref.applicable_overlay_chain
    assert result.observed_edition_used == ref.observed_edition_used
    assert result.observed_version_used == ref.observed_version_used
    assert result.retrieval_mode == ref.retrieval_mode
    assert result.snapshot_version == ref.snapshot_version


def test_bridge_result_has_no_trust_label_field():
    result = bridge_guidance_reference(_reference())
    assert "trust_label" not in type(result).model_fields


def test_bridge_intentional_trust_label_omission_matches_documented_assumption():
    """The one judgment this function makes about its input: for the
    only retrieval_mode that exists today (BUNDLED_SNAPSHOT), trust_label
    must already equal the documented constant 'pinned-summary' -- this
    test locks that assumption down explicitly, matching the
    task's own instruction to test the intentional omission, not just
    assert the field is absent from the output."""
    ref = _reference(retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT, trust_label="pinned-summary")
    bridge_guidance_reference(ref)  # must not raise


def test_bridge_raises_if_trust_label_diverges_from_the_bundled_snapshot_assumption():
    """If this ever fires in real use, it means a future retrieval mode
    broke the trust_label/retrieval_mode equivalence this bridge relies
    on to omit trust_label safely -- it must fail loudly, not silently
    keep dropping provenance."""
    ref = _reference(retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT, trust_label="something-else")
    with pytest.raises(ValueError, match="trust_label"):
        bridge_guidance_reference(ref)


def test_bridge_does_not_filter_by_applicability():
    """A bridge that filters is a bridge making a policy decision it has
    no business making -- every applicability state, including the least
    favorable, must still produce exactly one EvidenceReference."""
    for state in ApplicabilityState:
        if state is ApplicabilityState.NO_OFFICIAL_GUIDANCE_FOUND:
            continue  # not a per-entry state; never appears on a real GuidanceReference
        ref = _reference(applicability=state)
        result = bridge_guidance_reference(ref)
        assert result.applicability is state


def test_bridge_is_deterministic():
    ref = _reference()
    first = bridge_guidance_reference(ref)
    second = bridge_guidance_reference(ref)
    assert first == second


def test_bridge_does_not_mutate_its_input():
    ref = _reference()
    bridge_guidance_reference(ref)
    # GuidanceReference is frozen -- if the bridge somehow tried to
    # mutate it, pydantic itself would already have raised; this test
    # documents that expectation directly against the source object.
    assert ref.applicability is ApplicabilityState.APPLICABLE
