from __future__ import annotations

from pfsense_mcp.pfrest_docs.composition import build_cross_source_guidance
from pfsense_mcp.pfrest_docs.models import MAX_CONFLICTS, MAX_EVIDENCE_ENTRIES, FreshnessState, GuidanceEvidence
from pfsense_mcp.pfrest_docs.provenance import Provenance


def _evidence(provenance: Provenance, subject: str) -> GuidanceEvidence:
    return GuidanceEvidence(
        provenance=provenance,
        source="x",
        subject=subject,
        freshness=FreshnessState.FRESH,
        facts=("fact",),
    )


def test_build_preserves_each_source_independently():
    evidence = [
        _evidence(Provenance.PROJECT_AUTHORED, "tool"),
        _evidence(Provenance.PFREST_UPSTREAM, "endpoint"),
        _evidence(Provenance.LIVE_APPLIANCE_SCHEMA, "endpoint"),
    ]
    result = build_cross_source_guidance(query="q", evidence=evidence)
    assert len(result.evidence) == 3
    provenances = [e.provenance for e in result.evidence]
    assert provenances == [Provenance.PROJECT_AUTHORED, Provenance.PFREST_UPSTREAM, Provenance.LIVE_APPLIANCE_SCHEMA]


def test_build_truncates_evidence_to_bound():
    evidence = [_evidence(Provenance.PFREST_UPSTREAM, f"s{i}") for i in range(MAX_EVIDENCE_ENTRIES + 10)]
    result = build_cross_source_guidance(query="q", evidence=evidence)
    assert len(result.evidence) == MAX_EVIDENCE_ENTRIES


def test_build_truncates_conflicts_to_bound():
    conflicts = [f"c{i}" for i in range(MAX_CONFLICTS + 10)]
    result = build_cross_source_guidance(query="q", evidence=[], conflicts=conflicts)
    assert len(result.conflicts) == MAX_CONFLICTS


def test_build_never_flattens_facts_across_sources():
    evidence = [
        _evidence(Provenance.PFREST_UPSTREAM, "shared-subject"),
        _evidence(Provenance.LIVE_APPLIANCE_SCHEMA, "shared-subject"),
    ]
    result = build_cross_source_guidance(query="q", evidence=evidence)
    # Each entry keeps its own facts tuple; nothing is merged into one string.
    assert result.evidence[0].facts == ("fact",)
    assert result.evidence[1].facts == ("fact",)
    assert result.evidence[0] is not result.evidence[1]
