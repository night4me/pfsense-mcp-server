"""OFFICIAL_GUIDANCE_LAYER.md Required tests: schema-closure, excerpt/
title/license_note bounds, source_id pattern, and canonical_url
allow-list -- each independently, per Findings 1 and 2 of
`reports-ai/reviews/ADR_017_RED_TEAM.md`, which is exactly why this test
module exercises each field on its own rather than only a happy path.
"""

import pytest
from pydantic import ValidationError

from pfsense_mcp.guidance.appliance_identity import ObservedEdition
from pfsense_mcp.guidance.models import (
    MAX_EXCERPT_LENGTH,
    MAX_LICENSE_NOTE_LENGTH,
    MAX_TITLE_LENGTH,
    UNVERSIONED,
    ApplicabilityState,
    DocumentSource,
    Edition,
    EvidenceLevel,
    GuidanceReference,
    RetrievalMode,
    excerpt_hash,
)

_VALID_URL = "https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html"
_VALID_EXCERPT = "Aliases define groups of ports, hosts, or networks."


def _valid_source_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "source_id": "netgate_docs_aliases",
        "title": "Aliases",
        "canonical_url": _VALID_URL,
        "pfsense_edition": Edition.BOTH,
        "version_applicability": UNVERSIONED,
        "evidence_level": EvidenceLevel.EXPLICIT_UNVERSIONED,
        "retrieval_mode": RetrievalMode.BUNDLED_SNAPSHOT,
        "content_excerpt": _VALID_EXCERPT,
        "content_hash": excerpt_hash(_VALID_EXCERPT),
        "license_note": "Short quotation, contextual reference only.",
    }
    kwargs.update(overrides)
    return kwargs


def test_document_source_accepts_a_valid_entry():
    DocumentSource(**_valid_source_kwargs())


def test_document_source_rejects_extra_field():
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(), unexpected="value")  # type: ignore[arg-type]


def test_document_source_rejects_non_allowlisted_host():
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(canonical_url="https://docs-netgate.example.net/aliases"))


def test_document_source_rejects_non_https_scheme():
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(canonical_url="http://docs.netgate.com/aliases"))


@pytest.mark.parametrize(
    "source_id",
    ["AB", "has space", "-leadinghyphen", "x" * 65, ""],
)
def test_document_source_rejects_invalid_source_id(source_id: str):
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(source_id=source_id))


def test_document_source_rejects_oversized_title():
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(title="x" * (MAX_TITLE_LENGTH + 1)))


def test_document_source_rejects_oversized_excerpt():
    oversized = "x" * (MAX_EXCERPT_LENGTH + 1)
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(content_excerpt=oversized, content_hash=excerpt_hash(oversized)))


def test_document_source_rejects_oversized_license_note():
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(license_note="x" * (MAX_LICENSE_NOTE_LENGTH + 1)))


def test_document_source_rejects_malformed_content_hash():
    with pytest.raises(ValidationError):
        DocumentSource(**_valid_source_kwargs(content_hash="not-a-hash"))


def test_document_source_is_frozen():
    source = DocumentSource(**_valid_source_kwargs())
    with pytest.raises(ValidationError):
        source.title = "Changed"  # type: ignore[misc]


def test_document_source_evidence_level_is_required_with_no_default():
    field = DocumentSource.model_fields["evidence_level"]
    assert field.is_required()


def test_document_source_accepts_every_evidence_level_value():
    for level in EvidenceLevel:
        DocumentSource(**_valid_source_kwargs(evidence_level=level))


def _valid_reference_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "capability": "ALIAS_READ",
        "source_id": "netgate_docs_aliases",
        "title": "Aliases",
        "canonical_url": _VALID_URL,
        "content_excerpt": _VALID_EXCERPT,
        "content_hash": excerpt_hash(_VALID_EXCERPT),
        "pfsense_edition": Edition.BOTH,
        "trust_label": "pinned-snapshot",
        "applicability": ApplicabilityState.APPLICABLE,
        "evidence_level": EvidenceLevel.EXPLICIT_UNVERSIONED,
        "applicable_overlay_chain": (),
        "observed_edition_used": ObservedEdition.KNOWN_PLUS,
        "observed_version_used": "26.03.1",
        "retrieval_mode": RetrievalMode.BUNDLED_SNAPSHOT,
        "snapshot_version": "guidance-registry-2026-08-08",
    }
    kwargs.update(overrides)
    return kwargs


def test_guidance_reference_accepts_a_valid_entry():
    GuidanceReference(**_valid_reference_kwargs())


def test_guidance_reference_rejects_extra_field():
    with pytest.raises(ValidationError):
        GuidanceReference(**_valid_reference_kwargs(), unexpected="value")  # type: ignore[arg-type]


def test_guidance_reference_applicable_overlay_chain_defaults_to_empty_tuple():
    kwargs = _valid_reference_kwargs()
    del kwargs["applicable_overlay_chain"]
    reference = GuidanceReference(**kwargs)
    assert reference.applicable_overlay_chain == ()


def test_guidance_reference_preserves_ordered_overlay_chain_not_a_set():
    ordered = ("release_note_one", "errata_one")
    reference = GuidanceReference(**_valid_reference_kwargs(applicable_overlay_chain=ordered))
    assert reference.applicable_overlay_chain == ordered
    assert isinstance(reference.applicable_overlay_chain, tuple)


def test_guidance_reference_has_no_capability_selection_field():
    # G1: the only fields present are the closed set below -- an addition
    # needs its own reviewed diff, not a silent extension.
    assert set(GuidanceReference.model_fields) == {
        "capability",
        "source_id",
        "title",
        "canonical_url",
        "content_excerpt",
        "content_hash",
        "pfsense_edition",
        "trust_label",
        "applicability",
        "evidence_level",
        "applicable_overlay_chain",
        "observed_edition_used",
        "observed_version_used",
        "retrieval_mode",
        "snapshot_version",
    }
    forbidden_names = {"endpoint", "method", "http_method", "confirmation_token", "confirmation", "signature"}
    assert forbidden_names.isdisjoint(GuidanceReference.model_fields)
