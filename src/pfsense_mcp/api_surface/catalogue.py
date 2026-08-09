"""Endpoint Catalogue types (ADR-019, Accepted -- vocabulary and
evaluation only; this module is the first authorized implementation
slice: the Endpoint Catalogue side only. `FeatureCapabilityState` is
explicitly NOT implemented here -- see `docs/API_SURFACE_ARCHITECTURE.md`
Part 2, still design-only.

These types give the accepted `DISCOVERED -> CATALOGUED -> TYPED ->
IMPLEMENTED -> CAPABILITY-MAPPED -> AUTHORIZED -> MCP_EXPOSED` sequence
(`docs/API_SURFACE_ARCHITECTURE.md` Part 1) a real, importable,
independently testable representation. `EndpointCatalogueState` exists
for documentation/typing purposes -- it is never consulted at runtime by
any production code path and no function anywhere computes it
automatically from schema data (see the module docstring on
`CatalogueEntry` below for why).

`EndpointInfo.verified` (`pfsense_mcp.endpoints`) is not redefined,
overloaded, or referenced by this module at all. This module knows
nothing about `pfsense_mcp.endpoints`, `pfsense_mcp.capabilities`, or
`pfsense_mcp.tools.registry` -- promotion beyond `CATALOGUED` is
determined by inspecting those registries directly (a separate, future,
explicitly out-of-scope concern for this slice), never inferred by
anything in this package.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_SUMMARY_LENGTH = 300
MAX_DESCRIPTION_LENGTH = 2000
MAX_TAG_LENGTH = 80
MAX_PATH_LENGTH = 300

#: OpenAPI paths are always absolute and use curly-brace path parameters
#: (e.g. "/firewall/alias/{id}"); this is a structural sanity bound, not
#: an attempt to validate pfSense's own path grammar.
_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9/_\-{}.]*$")


class EndpointCatalogueState(str, Enum):
    """The accepted seven-state Endpoint Catalogue sequence
    (`docs/API_SURFACE_ARCHITECTURE.md` Part 1, `CAPABILITY_MAPPED`/
    `AUTHORIZED` split by the ADR-019 acceptance-track review). Listed in
    dependency order; nothing later is implied by anything earlier.

    Documentation/typing only -- no function in this codebase computes an
    entry's state and returns this type. A `CatalogueEntry` (below)
    reaching `CATALOGUED` is a fact about *this* package (a human
    recorded it in the committed artifact); whether it has gone further
    is a fact about `pfsense_mcp.endpoints`/`pfsense_mcp.capabilities`/
    `pfsense_mcp.tools.registry`, entirely outside this package's
    knowledge, by design.
    """

    DISCOVERED = "discovered"
    CATALOGUED = "catalogued"
    TYPED = "typed"
    IMPLEMENTED = "implemented"
    CAPABILITY_MAPPED = "capability_mapped"
    AUTHORIZED = "authorized"
    MCP_EXPOSED = "mcp_exposed"


#: Dependency order, most-preliminary first. Used only by tests asserting
#: the enum's shape; not consulted by any runtime code.
ENDPOINT_CATALOGUE_STATE_ORDER: tuple[EndpointCatalogueState, ...] = (
    EndpointCatalogueState.DISCOVERED,
    EndpointCatalogueState.CATALOGUED,
    EndpointCatalogueState.TYPED,
    EndpointCatalogueState.IMPLEMENTED,
    EndpointCatalogueState.CAPABILITY_MAPPED,
    EndpointCatalogueState.AUTHORIZED,
    EndpointCatalogueState.MCP_EXPOSED,
)


class IntendedUse(str, Enum):
    """A human's own classification of a catalogued entry -- never
    inferred, never defaulted to anything but `NONE` by tooling."""

    NONE = "none"
    CANDIDATE = "candidate"
    IMPLEMENTED_ELSEWHERE = "implemented_elsewhere"


class CatalogueEntry(BaseModel):
    """One `DISCOVERED`+`CATALOGUED`-layer record of a pfSense API GET
    operation. Deliberately carries NO field representing `TYPED`,
    `IMPLEMENTED`, `CAPABILITY_MAPPED`, `AUTHORIZED`, or `MCP_EXPOSED` --
    this is a structural enforcement of ADR-019's "do not infer later
    states merely from endpoint discovery or OpenAPI presence" rule: this
    type cannot represent a later-stage claim even by mistake, because
    the field to hold one does not exist. A reader who wants to know
    whether a catalogued path has gone further must independently
    consult `pfsense_mcp.endpoints`/`pfsense_mcp.capabilities`/
    `pfsense_mcp.tools.registry` -- this package does not, and structurally
    cannot, answer that question.

    `intended_use` is the one human-authored judgment this record type
    carries; every other field is a direct, mechanical transcription of
    what the OpenAPI schema itself says about the operation -- never
    interpreted, augmented, or overridden by anything in this package.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(max_length=MAX_PATH_LENGTH)
    method: str = Field(pattern=r"^get$", description="Scoped to GET operations only in this implementation slice.")
    tags: tuple[str, ...] = Field(default=())
    summary: str | None = Field(default=None, max_length=MAX_SUMMARY_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    mutating_methods_exist: bool = Field(
        description="Whether a sibling non-GET method exists on this same path in the schema -- "
        "informational only, never itself a claim about this entry's own catalogue state."
    )
    intended_use: IntendedUse = Field(
        default=IntendedUse.NONE,
        description="Human-authored classification, set only by editing the committed catalogue file "
        "through ordinary code review -- never auto-assigned to anything but NONE by tooling.",
    )

    @field_validator("path")
    @classmethod
    def _check_path_shape(cls, value: str) -> str:
        if not _PATH_PATTERN.fullmatch(value):
            raise ValueError("path must be an absolute OpenAPI-style path")
        return value

    @field_validator("tags")
    @classmethod
    def _check_tag_lengths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for tag in value:
            if len(tag) > MAX_TAG_LENGTH:
                raise ValueError(f"tag exceeds {MAX_TAG_LENGTH} characters: {tag!r}")
        return value


class EndpointCatalogue(BaseModel):
    """The committed, offline catalogue artifact as a whole. Pure data --
    no method on this type performs I/O, network access, or consults any
    other `pfsense_mcp` module."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    generated_at: str | None = Field(
        default=None,
        description="Informational timestamp from the last regeneration run -- never authoritative, "
        "never consulted for freshness/expiry logic by this package.",
    )
    entries: tuple[CatalogueEntry, ...] = Field(default=())

    @field_validator("entries")
    @classmethod
    def _check_no_duplicate_path(cls, value: tuple[CatalogueEntry, ...]) -> tuple[CatalogueEntry, ...]:
        seen: set[tuple[str, str]] = set()
        for entry in value:
            key = (entry.path, entry.method)
            if key in seen:
                raise ValueError(f"duplicate catalogue entry for {entry.method.upper()} {entry.path}")
            seen.add(key)
        return value
