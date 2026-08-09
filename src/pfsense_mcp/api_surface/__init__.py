"""Endpoint Catalogue (inert, ADR-019, Accepted -- vocabulary and
evaluation only; this package is the first authorized implementation
slice, Endpoint Catalogue side only).

Not imported by `Application`, `factory`, `server`, `ToolRegistry`,
`pfsense_mcp.tier1`, `pfsense_mcp.guidance`, or any READ tool. A
catalogue entry has no runtime effect and cannot, by construction (see
`catalogue.CatalogueEntry`'s own docstring), represent a claim about
whether a path is typed, implemented, capability-mapped, authorized, or
exposed as an MCP tool. No consumer is wired to this package; it exists
to be tested in isolation, not to be called from production. See
`docs/adr/ADR-019-api-surface-capability-discovery-and-extension-architecture.md`
and `docs/API_SURFACE_ARCHITECTURE.md` for the full specification.
`FeatureCapabilityState` (Part 2) is explicitly not implemented here.
"""

from __future__ import annotations

from .catalogue import (
    ENDPOINT_CATALOGUE_STATE_ORDER,
    CatalogueEntry,
    EndpointCatalogue,
    EndpointCatalogueState,
    IntendedUse,
)
from .store import load_catalogue, save_catalogue

__all__ = [
    "ENDPOINT_CATALOGUE_STATE_ORDER",
    "CatalogueEntry",
    "EndpointCatalogue",
    "EndpointCatalogueState",
    "IntendedUse",
    "load_catalogue",
    "save_catalogue",
]
