"""ADR-019 Endpoint Catalogue: EndpointCatalogueState, IntendedUse,
CatalogueEntry, EndpointCatalogue -- construction, validation, and the
structural "cannot represent a later-stage claim" guarantee.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pfsense_mcp.api_surface.catalogue import (
    ENDPOINT_CATALOGUE_STATE_ORDER,
    CatalogueEntry,
    EndpointCatalogue,
    EndpointCatalogueState,
    IntendedUse,
)


def _entry(**overrides: object) -> CatalogueEntry:
    defaults: dict[str, object] = {
        "path": "/api/v2/firewall/alias",
        "method": "get",
        "tags": ("Firewall",),
        "summary": "List firewall aliases",
        "description": None,
        "mutating_methods_exist": True,
    }
    defaults.update(overrides)
    return CatalogueEntry(**defaults)


# --- EndpointCatalogueState / IntendedUse: closed sets ---


def test_endpoint_catalogue_state_has_exactly_seven_members_in_dependency_order() -> None:
    assert [s.value for s in EndpointCatalogueState] == [
        "discovered",
        "catalogued",
        "typed",
        "implemented",
        "capability_mapped",
        "authorized",
        "mcp_exposed",
    ]
    assert list(ENDPOINT_CATALOGUE_STATE_ORDER) == list(EndpointCatalogueState)


def test_intended_use_has_exactly_three_members() -> None:
    assert {u.value for u in IntendedUse} == {"none", "candidate", "implemented_elsewhere"}


# --- CatalogueEntry: the structural "no later-state field" guarantee ---


def test_catalogue_entry_has_no_field_for_any_later_catalogue_state() -> None:
    """The core structural invariant: this type must be physically
    incapable of claiming TYPED/IMPLEMENTED/CAPABILITY_MAPPED/AUTHORIZED/
    MCP_EXPOSED for an entry, regardless of what any future author
    intends -- checked by asserting no such field name exists at all,
    not by trusting a docstring."""
    forbidden_field_names = {
        s.value
        for s in EndpointCatalogueState
        if s not in (EndpointCatalogueState.DISCOVERED, EndpointCatalogueState.CATALOGUED)
    }
    assert forbidden_field_names.isdisjoint(CatalogueEntry.model_fields)


def test_catalogue_entry_required_field_set_is_exact() -> None:
    required = {name for name, field in CatalogueEntry.model_fields.items() if field.is_required()}
    assert required == {"path", "method", "mutating_methods_exist"}


def test_catalogue_entry_defaults() -> None:
    entry = _entry(tags=(), summary=None, mutating_methods_exist=False)
    assert entry.tags == ()
    assert entry.summary is None
    assert entry.description is None
    assert entry.intended_use is IntendedUse.NONE


def test_catalogue_entry_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _entry(unexpected_field="nope")


def test_catalogue_entry_rejects_non_get_method() -> None:
    with pytest.raises(ValidationError):
        _entry(method="post")


def test_catalogue_entry_rejects_relative_path() -> None:
    with pytest.raises(ValidationError):
        _entry(path="api/v2/firewall/alias")


def test_catalogue_entry_rejects_oversized_path() -> None:
    with pytest.raises(ValidationError):
        _entry(path="/" + "a" * 400)


def test_catalogue_entry_rejects_oversized_tag() -> None:
    with pytest.raises(ValidationError):
        _entry(tags=("x" * 200,))


def test_catalogue_entry_is_frozen() -> None:
    entry = _entry()
    with pytest.raises(ValidationError):
        entry.path = "/changed"  # type: ignore[misc]


def test_catalogue_entry_accepts_every_intended_use_value() -> None:
    for use in IntendedUse:
        entry = _entry(intended_use=use)
        assert entry.intended_use is use


# --- EndpointCatalogue: aggregate ---


def test_endpoint_catalogue_defaults_to_empty_entries() -> None:
    catalogue = EndpointCatalogue(schema_version=1)
    assert catalogue.entries == ()
    assert catalogue.generated_at is None


def test_endpoint_catalogue_rejects_duplicate_path_method_pair() -> None:
    with pytest.raises(ValidationError):
        EndpointCatalogue(schema_version=1, entries=(_entry(), _entry()))


def test_endpoint_catalogue_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EndpointCatalogue(schema_version=1, entries=(), unexpected_field="nope")  # type: ignore[call-arg]


def test_endpoint_catalogue_is_frozen() -> None:
    catalogue = EndpointCatalogue(schema_version=1)
    with pytest.raises(ValidationError):
        catalogue.schema_version = 2  # type: ignore[misc]


def test_endpoint_catalogue_accepts_distinct_paths_and_methods() -> None:
    other = _entry(path="/api/v2/firewall/rule", mutating_methods_exist=False)
    catalogue = EndpointCatalogue(schema_version=1, entries=(_entry(), other))
    assert len(catalogue.entries) == 2
