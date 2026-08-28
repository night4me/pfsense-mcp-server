"""The one closed provenance enum every evidence object in this package
(and its consumers) carries. No I/O, no dependency on anything else in
this package -- the lowest-level module, imported by everything else
here.

Authority is dimension-specific, never a single universal precedence
order (deliberate design decision, pfREST_LIVE_GUIDANCE_ARC Phase 2):

- **Endpoint/field/model existence on the connected appliance**:
  `LIVE_APPLIANCE_SCHEMA` > `PFREST_UPSTREAM`. The appliance's own
  schema is ground truth for "does this exist, right now, on this
  specific installation" -- `PFREST_UPSTREAM` may describe a newer or
  older pfREST release than what is actually installed.
- **General pfREST API semantics** (auth modes, query/filter/sort
  syntax, HATEOAS, pagination, control parameters): `PFREST_UPSTREAM`
  is authoritative. The appliance's raw schema carries some of the same
  per-operation description text, but the *guide*-level explanatory
  content (how these mechanisms work in general) exists only upstream.
- **pfSense operational/product meaning** (what a feature is for, how
  to use it from the GUI, general troubleshooting): `OFFICIAL_NETGATE`
  is authoritative -- unchanged from ADR-017/018, this package never
  reassigns that role.
- **What this project's own MCP tool returns, and how to interpret
  it**: `PROJECT_AUTHORED` is authoritative -- nobody else can be, since
  it is a fact about this codebase, not about pfSense or pfREST.

When two provenance classes' evidence disagrees on a question neither
is dimension-authoritative for (e.g. `PFREST_UPSTREAM` describes an
endpoint `LIVE_APPLIANCE_SCHEMA` does not have), both are surfaced
side by side with the disagreement stated explicitly -- never silently
merged, never silently dropped, never resolved by picking a "winner"
outside the dimension rules above (see `composition.py`).
"""

from __future__ import annotations

from enum import Enum


class Provenance(str, Enum):
    #: This project's own interpretation of its own tools/output.
    PROJECT_AUTHORED = "PROJECT_AUTHORED"
    #: The community-maintained pfREST package's live documentation at
    #: https://pfrest.org/ -- explicitly NOT Netgate-authored (see
    #: module docstring and the fetch-layer allowlist).
    PFREST_UPSTREAM = "PFREST_UPSTREAM"
    #: The connected pfSense appliance's own /api/v2/schema/openapi
    #: response, fetched through the existing authenticated transport.
    LIVE_APPLIANCE_SCHEMA = "LIVE_APPLIANCE_SCHEMA"
    #: Official Netgate documentation, via the existing, unchanged
    #: pfsense_mcp.guidance bundled-snapshot registry (ADR-017/018).
    OFFICIAL_NETGATE = "OFFICIAL_NETGATE"
