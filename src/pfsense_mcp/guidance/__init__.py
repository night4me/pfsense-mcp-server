"""Official pfSense/Netgate documentation guidance layer (ADR-017/018).

Provides a deterministic, capability-keyed lookup over a Git-tracked,
PR-reviewed bundled-snapshot document registry -- structurally incapable
of supplying a capability, endpoint, method, or confirmation token (see
`GuidanceReference` in `models.py`). See
docs/adr/ADR-017-official-guidance-layer.md and
docs/OFFICIAL_GUIDANCE_LAYER.md for the full specification. As of
2026-08-22, exactly one production module,
`src/pfsense_mcp/tools/read/official_guidance.py`, consumes this package
(`pfsense_get_official_guidance`, owner-authorized) -- see that module's
docstring; every other production module is still isolated from it,
enforced by `tests/guidance/test_isolation.py`.

`lookup_guidance` is exposed via a lazy `__getattr__` (PEP 562), not a
plain eager import, so that importing anything else from this package
(e.g. just `models.GuidanceReference`, needed at module level for
`OfficialGuidanceResult`'s own Pydantic field type) does not also force
`registry.py`'s import -- and with it, `registry.py`'s load-time
`_check_registry_integrity()` self-check -- as an unavoidable side
effect. `registry.py`'s own integrity check is correct and desired; what
must not happen is putting it on the *server-startup* path merely
because `tools/registry.py` imports `official_guidance.py` at its own
top level to register every tool. A caller doing
`from pfsense_mcp.guidance import lookup_guidance` (or
`pfsense_mcp.guidance.lookup_guidance(...)`) sees no behavioral
difference at all -- this is purely about *when* `registry.py` is first
imported, never about the public API shape.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import DocumentSource, Edition, GuidanceReference, RetrievalMode

if TYPE_CHECKING:
    from .registry import lookup_guidance as lookup_guidance

__all__ = [
    "DocumentSource",
    "Edition",
    "GuidanceReference",
    "RetrievalMode",
    "lookup_guidance",
]


def __getattr__(name: str) -> object:
    if name == "lookup_guidance":
        from .registry import lookup_guidance

        return lookup_guidance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
