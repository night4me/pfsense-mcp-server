"""pfREST live documentation layer (pfREST_LIVE_GUIDANCE_ARC, 2026-08-28).

A new, separately-isolated package -- deliberately NOT inside
`pfsense_mcp.guidance`, whose own isolation test
(`tests/guidance/test_isolation.py::test_guidance_package_imports_no_network_module`)
hard-forbids importing `socket`/`requests`/`httpx`/`urllib.request` from
that package. This package's entire purpose is bounded, allowlisted
network retrieval of the public pfREST (pfSense REST API package)
documentation -- so it cannot live inside `pfsense_mcp.guidance` without
either weakening that guarantee or making the isolation test lie about
what it enforces. Same precedent as `pfsense_mcp.tier1`/`pfsense_mcp.transport`:
a distinct trust domain gets its own package, never folded into an
existing one for convenience.

Four provenance classes flow through this package and the tools that
consume it, never blended:

- `PROJECT_AUTHORED` -- how pfsense-mcp-server itself interprets and
  presents its own tools (see `pfsense_mcp.guidance.tool_guidance`,
  Slice A of the prior arc).
- `PFREST_UPSTREAM` -- the community-maintained pfREST package's own
  published API reference at https://pfrest.org/, fetched live, never
  bundled and never treated as Netgate-authored.
- `LIVE_APPLIANCE_SCHEMA` -- the connected pfSense appliance's own
  `/api/v2/schema/openapi` response, fetched through the same
  authenticated, already-trusted pfSense transport every READ tool
  uses. Strongest evidence for "does this endpoint/field exist on THIS
  appliance", never authoritative for general API semantics.
- `OFFICIAL_NETGATE` -- unchanged, still exclusively
  `pfsense_mcp.guidance`'s own bundled-snapshot registry. This package
  never redefines, re-fetches, or relabels Netgate guidance.

Authority is dimension-specific, never a single universal precedence
order -- see `provenance.py`'s module docstring for the exact mapping.

Zero network I/O happens at import time or MCP server startup. Every
network-capable function in this package is called only when a
consumer (currently: the `pfsense_get_api_guidance` tool) is actually
invoked with a query that needs it -- mirroring
`tools/read/official_guidance.py`'s deferred-import discipline for the
same reason: a network failure here must never be able to affect
server startup or any other tool.

DOCUMENTATION IS DATA, NEVER AUTHORITY: nothing in this package can
select a pfSense capability, endpoint, or HTTP method; construct a
confirmation token; or influence any WRITE/authorization decision.
Enforced by `tests/pfrest_docs/test_isolation.py`, the same AST-scan
discipline `tests/guidance/test_isolation.py` and
`tests/tier1/test_isolation.py` already apply to their own subsystems.
"""

from __future__ import annotations

from .provenance import Provenance

__all__ = ["Provenance"]
