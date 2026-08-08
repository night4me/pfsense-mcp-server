"""Official pfSense/Netgate documentation guidance layer (inert, ADR-017).

Not imported by `Application`, `factory`, `server`, `ToolRegistry`,
`pfsense_mcp.tier1`, or any READ tool. Provides a deterministic,
capability-keyed lookup over a Git-tracked, PR-reviewed bundled-snapshot
document registry -- structurally incapable of supplying a capability,
endpoint, method, or confirmation token (see `GuidanceReference` in
`models.py`). See docs/adr/ADR-017-official-guidance-layer.md and
docs/OFFICIAL_GUIDANCE_LAYER.md for the full specification. No consumer
is wired to this package yet; it exists to be tested in isolation, not to
be called from production.
"""

from __future__ import annotations

from .models import DocumentSource, Edition, GuidanceReference, RetrievalMode
from .registry import lookup_guidance

__all__ = [
    "DocumentSource",
    "Edition",
    "GuidanceReference",
    "RetrievalMode",
    "lookup_guidance",
]
