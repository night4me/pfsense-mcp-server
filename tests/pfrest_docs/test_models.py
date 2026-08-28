from __future__ import annotations

import pytest
from pydantic import ValidationError

from pfsense_mcp.pfrest_docs.models import (
    MAX_CONFLICTS,
    MAX_EVIDENCE_ENTRIES,
    CrossSourceGuidance,
    FreshnessState,
    GuidanceEvidence,
)
from pfsense_mcp.pfrest_docs.provenance import Provenance


def _evidence(**overrides) -> GuidanceEvidence:
    defaults = {
        "provenance": Provenance.PFREST_UPSTREAM,
        "source": "https://pfrest.org/api-docs/openapi.json",
        "subject": "GET /api/v2/firewall/alias",
        "version": None,
        "fetched_at": None,
        "content_hash": None,
        "freshness": FreshnessState.FRESH,
        "facts": ("a fact",),
    }
    defaults.update(overrides)
    return GuidanceEvidence(**defaults)


def test_guidance_evidence_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        GuidanceEvidence(
            provenance=Provenance.PROJECT_AUTHORED,
            source="x",
            subject="y",
            freshness=FreshnessState.NOT_APPLICABLE,
            unexpected_field="nope",
        )


def test_guidance_evidence_is_frozen():
    evidence = _evidence()
    with pytest.raises(ValidationError):
        evidence.subject = "changed"


def test_cross_source_guidance_bounds_evidence_entries():
    evidence = [_evidence(subject=f"s{i}") for i in range(MAX_EVIDENCE_ENTRIES + 5)]
    with pytest.raises(ValidationError):
        CrossSourceGuidance(query="q", evidence=tuple(evidence))


def test_cross_source_guidance_bounds_conflicts():
    with pytest.raises(ValidationError):
        CrossSourceGuidance(query="q", conflicts=tuple(f"c{i}" for i in range(MAX_CONFLICTS + 5)))


def test_cross_source_guidance_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        CrossSourceGuidance(query="q", extra_field="nope")


def test_no_field_is_capability_endpoint_method_or_confirmation_shaped():
    """G1-style closed-schema check, mirrored from the guidance package's
    own precedent: nothing in this model's field names suggests an
    authorization-relevant shape."""
    forbidden_substrings = ("capability", "confirmation_token", "authorization", "privilege_grant")
    for model in (GuidanceEvidence, CrossSourceGuidance):
        for name in model.model_fields:
            lowered = name.lower()
            assert not any(bad in lowered for bad in forbidden_substrings), (
                f"{model.__name__}.{name} looks authorization-shaped"
            )


def test_provenance_is_a_closed_four_member_enum():
    from pfsense_mcp.pfrest_docs.provenance import Provenance as P

    assert {member.value for member in P} == {
        "PROJECT_AUTHORED",
        "PFREST_UPSTREAM",
        "LIVE_APPLIANCE_SCHEMA",
        "OFFICIAL_NETGATE",
    }
