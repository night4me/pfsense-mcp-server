"""Cross-source composition (pfREST_LIVE_GUIDANCE_ARC Phase 8/9).

Deliberately thin: this module only assembles an already-bounded list
of `GuidanceEvidence` entries into one `CrossSourceGuidance`, truncating
to `MAX_EVIDENCE_ENTRIES` if a caller somehow produced more. It does
NOT import `pfsense_mcp.guidance` -- this package stays fully decoupled
from the OFFICIAL_NETGATE registry; the one reviewed module allowed to
import both this package and `pfsense_mcp.guidance` is the
`pfsense_get_api_guidance` tool itself
(`tools/read/api_guidance.py`), which is where the actual per-source
semantic comparison (does PFREST_UPSTREAM disagree with
LIVE_APPLIANCE_SCHEMA about whether something exists?) happens, using
each source's own fully-typed result -- not by trying to infer meaning
back out of this module's already-flattened `GuidanceEvidence.facts`
strings.
"""

from __future__ import annotations

from collections.abc import Sequence

from .models import MAX_APPLICABILITY_NOTES, MAX_CONFLICTS, MAX_EVIDENCE_ENTRIES, CrossSourceGuidance, GuidanceEvidence


def build_cross_source_guidance(
    *,
    query: str,
    evidence: Sequence[GuidanceEvidence],
    conflicts: Sequence[str] = (),
    applicability_notes: Sequence[str] = (),
) -> CrossSourceGuidance:
    return CrossSourceGuidance(
        query=query,
        evidence=tuple(evidence)[:MAX_EVIDENCE_ENTRIES],
        conflicts=tuple(conflicts)[:MAX_CONFLICTS],
        applicability_notes=tuple(applicability_notes)[:MAX_APPLICABILITY_NOTES],
    )
