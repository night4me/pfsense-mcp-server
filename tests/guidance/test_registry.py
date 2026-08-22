"""OFFICIAL_GUIDANCE_LAYER.md / VERSION_AWARE_GUIDANCE.md Required tests:
registry integrity and deterministic-mapping tests (I5/I6), each
ambiguity/absence case as its own explicit test, not inferred from one
happy-path test.

Rewritten by the ADR-018 guidance-bridge implementation slice
(2026-08-09) for the accepted inclusion-with-state policy:
`lookup_guidance()` no longer excludes non-matching entries -- every
registered entry is returned, carrying its own computed
`ApplicabilityState`. The exclusion-branch tests this file previously
had are now inclusion-branch tests asserting the *specific* state each
scenario produces, not merely that an entry disappears.
"""

from __future__ import annotations

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.guidance import registry as registry_module
from pfsense_mcp.guidance.appliance_identity import ObservedEdition
from pfsense_mcp.guidance.evidence import ReleaseOverlay
from pfsense_mcp.guidance.models import (
    ApplicabilityState,
    DocumentSource,
    Edition,
    EvidenceLevel,
    RetrievalMode,
    excerpt_hash,
)
from pfsense_mcp.guidance.registry import _REGISTRY, lookup_guidance


def test_registry_entries_pass_their_own_summary_and_verification_hash_check():
    # Re-asserts the same check registry.py performs at import time (which
    # already ran once, successfully, for this test to even collect), so a
    # future regression is CI-visible as a named test failure, not just an
    # import-time crash.
    for entries in _REGISTRY.values():
        for entry in entries:
            assert entry.summary_hash == excerpt_hash(entry.summary)
            assert entry.source_verification_hash == excerpt_hash(entry.source_verification_excerpt)


def test_lookup_returns_entry_for_registered_capability_both_edition_unversioned():
    result = lookup_guidance(Capability.ALIAS_READ, observed_version=None, observed_edition=ObservedEdition.UNKNOWN)
    assert len(result) == 1
    reference = result[0]
    assert reference.capability == "ALIAS_READ"
    assert reference.source_id == "netgate_docs_aliases"
    assert reference.pfsense_edition is Edition.BOTH
    assert reference.trust_label == "pinned-summary"
    # The real, seed _ALIAS_DOC entry is INFERRED_FROM_CURRENT_DOCS (an
    # undated /latest/ page, not an explicit version-independence claim)
    # -- capped to VERSION_UNCONFIRMED, never APPLICABLE, by design.
    assert reference.applicability is ApplicabilityState.VERSION_UNCONFIRMED
    assert reference.evidence_level is EvidenceLevel.INFERRED_FROM_CURRENT_DOCS


def test_real_registry_entries_are_project_authored_not_verbatim_quotations():
    """2026-08-22 provenance-conversion regression test: every real,
    shipped `_REGISTRY` entry's `summary` must differ from its own
    `source_verification_excerpt` -- proof the split is real end-to-end
    (a project-authored summary, distinct from the short verbatim anchor),
    not merely a schema-level rename with the same text duplicated into
    both fields.
    """
    for entries in _REGISTRY.values():
        for entry in entries:
            assert entry.summary != entry.source_verification_excerpt
            assert entry.source_verification_excerpt not in entry.summary, (
                f"{entry.source_id}: verification anchor appears verbatim inside the summary -- "
                "the summary must be independently authored, not built around the quoted anchor"
            )


def test_real_registry_lookup_result_carries_summary_not_verification_excerpt():
    """End-to-end: what `lookup_guidance()` actually returns for a real
    entry is the project-authored summary, and the GuidanceReference type
    has no field the maintainer-only verification anchor could travel
    through even if someone tried.
    """
    result = lookup_guidance(Capability.ALIAS_READ, observed_version=None, observed_edition=ObservedEdition.UNKNOWN)
    reference = result[0]
    assert reference.summary == _REGISTRY[Capability.ALIAS_READ][0].summary
    assert "source_verification_excerpt" not in type(reference).model_fields


def test_lookup_is_deterministic_for_identical_inputs():
    first = lookup_guidance(Capability.ALIAS_READ, observed_version="2.7.2", observed_edition=ObservedEdition.KNOWN_CE)
    second = lookup_guidance(Capability.ALIAS_READ, observed_version="2.7.2", observed_edition=ObservedEdition.KNOWN_CE)
    assert first == second


def test_lookup_returns_empty_for_unregistered_capability():
    assert (
        lookup_guidance(Capability.SERVICE_READ, observed_version=None, observed_edition=ObservedEdition.UNKNOWN) == ()
    )


def test_lookup_still_returns_the_unversioned_entry_regardless_of_observed_version():
    # ALIAS_READ's only registered entry is UNVERSIONED/BOTH, so an
    # observed version/edition should not change eligibility (it is
    # always returned) -- this asserts that fact directly.
    result = lookup_guidance(
        Capability.ALIAS_READ, observed_version="9.9.9", observed_edition=ObservedEdition.KNOWN_PLUS
    )
    assert len(result) == 1


def test_lookup_never_raises_for_a_capability_with_no_registry_entry():
    # I6: absence must resolve to an empty tuple, never an exception.
    for capability in Capability:
        lookup_guidance(capability, observed_version=None, observed_edition=ObservedEdition.UNKNOWN)


def _synthetic_entry(**overrides: object) -> DocumentSource:
    summary = "Synthetic entry for applicability-branch testing only."
    verification = "Synthetic verification anchor."
    kwargs: dict[str, object] = {
        "source_id": "synthetic_entry",
        "title": "Synthetic",
        "canonical_url": "https://docs.netgate.com/synthetic",
        "pfsense_edition": Edition.CE,
        "version_applicability": "2.7.2",
        "evidence_level": EvidenceLevel.EXPLICIT_VERSION_SCOPED,
        "retrieval_mode": RetrievalMode.BUNDLED_SNAPSHOT,
        "summary": summary,
        "summary_hash": excerpt_hash(summary),
        "source_verification_excerpt": verification,
        "source_verification_hash": excerpt_hash(verification),
        "license_note": "Synthetic, test-only.",
    }
    kwargs.update(overrides)
    return DocumentSource(**kwargs)


@pytest.fixture
def synthetic_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercises the applicability branches directly, without adding a fake
    # entry to the real, curated registry those branches would otherwise
    # never trigger against (the real registry's one entry is
    # UNVERSIONED/BOTH, which never takes any of these branches).
    monkeypatch.setitem(registry_module._REGISTRY, Capability.SYSTEM_READ, (_synthetic_entry(),))


def test_version_specific_entry_is_version_unconfirmed_when_observed_version_is_none(synthetic_registry: None):
    result = lookup_guidance(Capability.SYSTEM_READ, observed_version=None, observed_edition=ObservedEdition.KNOWN_CE)
    assert len(result) == 1
    assert result[0].applicability is ApplicabilityState.VERSION_UNCONFIRMED


def test_version_specific_entry_is_version_unconfirmed_on_version_mismatch(synthetic_registry: None):
    result = lookup_guidance(
        Capability.SYSTEM_READ, observed_version="2.8.0", observed_edition=ObservedEdition.KNOWN_CE
    )
    assert len(result) == 1
    assert result[0].applicability is ApplicabilityState.VERSION_UNCONFIRMED


def test_version_specific_entry_is_applicable_on_exact_version_match(synthetic_registry: None):
    result = lookup_guidance(
        Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=ObservedEdition.KNOWN_CE
    )
    assert len(result) == 1
    assert result[0].applicability is ApplicabilityState.APPLICABLE


def test_edition_specific_entry_is_version_unconfirmed_when_observed_edition_is_unknown(synthetic_registry: None):
    result = lookup_guidance(Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=ObservedEdition.UNKNOWN)
    assert len(result) == 1
    assert result[0].applicability is ApplicabilityState.VERSION_UNCONFIRMED


def test_edition_specific_entry_is_edition_mismatch_on_edition_difference(synthetic_registry: None):
    result = lookup_guidance(
        Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=ObservedEdition.KNOWN_PLUS
    )
    assert len(result) == 1
    assert result[0].applicability is ApplicabilityState.EDITION_MISMATCH


def test_lookup_reports_observed_identity_used_on_every_reference(synthetic_registry: None):
    result = lookup_guidance(
        Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=ObservedEdition.KNOWN_CE
    )
    assert result[0].observed_edition_used is ObservedEdition.KNOWN_CE
    assert result[0].observed_version_used == "2.7.2"


def _synthetic_overlay(**overrides: object) -> ReleaseOverlay:
    summary = overrides.pop("caveat_summary", "Behavior changed for this release, per project-authored summary.")
    verification = overrides.pop("source_verification_excerpt", "Behavior changed for this release.")
    kwargs: dict[str, object] = {
        "overlay_id": "synthetic_overlay_one",
        "capability": "SYSTEM_READ",
        "applies_to_version": "2.7.2",
        "applies_to_edition": Edition.CE,
        "evidence_level": EvidenceLevel.EXPLICIT_VERSION_SCOPED,
        "supersedes_id": None,
        "caveat_summary": summary,
        "caveat_summary_hash": excerpt_hash(summary),
        "source_verification_excerpt": verification,
        "source_verification_hash": excerpt_hash(verification),
        "canonical_url": "https://docs.netgate.com/synthetic-overlay",
    }
    kwargs.update(overrides)
    return ReleaseOverlay(**kwargs)


@pytest.fixture
def synthetic_registry_with_caveat_overlay(synthetic_registry: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(registry_module._OVERLAY_REGISTRY, Capability.SYSTEM_READ, (_synthetic_overlay(),))


def test_caveated_entry_is_partially_applicable(synthetic_registry_with_caveat_overlay: None):
    result = lookup_guidance(
        Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=ObservedEdition.KNOWN_CE
    )
    assert len(result) == 1
    assert result[0].applicability is ApplicabilityState.PARTIALLY_APPLICABLE
    assert result[0].applicable_overlay_chain == ("synthetic_overlay_one",)


@pytest.fixture
def synthetic_registry_with_superseding_overlay(synthetic_registry: None, monkeypatch: pytest.MonkeyPatch) -> None:
    superseding = _synthetic_overlay(overlay_id="synthetic_overlay_supersedes", supersedes_id="synthetic_entry")
    monkeypatch.setitem(registry_module._OVERLAY_REGISTRY, Capability.SYSTEM_READ, (superseding,))


def test_superseded_entry_is_stale(synthetic_registry_with_superseding_overlay: None):
    result = lookup_guidance(
        Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=ObservedEdition.KNOWN_CE
    )
    assert len(result) == 1
    assert result[0].applicability is ApplicabilityState.STALE
    assert result[0].applicable_overlay_chain == ("synthetic_overlay_supersedes",)


def test_registry_integrity_check_rejects_duplicate_scope_overlays(monkeypatch: pytest.MonkeyPatch):
    left = _synthetic_overlay(overlay_id="dup_overlay_one")
    right = _synthetic_overlay(overlay_id="dup_overlay_two")
    monkeypatch.setitem(registry_module._OVERLAY_REGISTRY, Capability.SYSTEM_READ, (left, right))
    with pytest.raises(ValueError, match="duplicate-scope"):
        registry_module._check_registry_integrity()


def test_registry_integrity_check_rejects_dangling_supersedes_id(monkeypatch: pytest.MonkeyPatch):
    dangling = _synthetic_overlay(overlay_id="dangling_overlay", supersedes_id="nonexistent_target")
    monkeypatch.setitem(registry_module._OVERLAY_REGISTRY, Capability.SYSTEM_READ, (dangling,))
    with pytest.raises(ValueError, match="chain defects"):
        registry_module._check_registry_integrity()


def test_registry_integrity_check_rejects_overlay_caveat_summary_hash_mismatch(monkeypatch: pytest.MonkeyPatch):
    tampered = _synthetic_overlay(overlay_id="tampered_overlay", caveat_summary_hash="0" * 64)
    monkeypatch.setitem(registry_module._OVERLAY_REGISTRY, Capability.SYSTEM_READ, (tampered,))
    with pytest.raises(ValueError, match="caveat_summary_hash"):
        registry_module._check_registry_integrity()


def test_registry_integrity_check_rejects_overlay_verification_hash_mismatch(monkeypatch: pytest.MonkeyPatch):
    tampered = _synthetic_overlay(overlay_id="tampered_overlay_2", source_verification_hash="0" * 64)
    monkeypatch.setitem(registry_module._OVERLAY_REGISTRY, Capability.SYSTEM_READ, (tampered,))
    with pytest.raises(ValueError, match="source_verification_hash"):
        registry_module._check_registry_integrity()


def test_real_registry_still_passes_integrity_check_unmodified():
    # No monkeypatch here -- the real, shipped _REGISTRY/_OVERLAY_REGISTRY
    # must still pass, exactly as it already did once at import time.
    registry_module._check_registry_integrity()
