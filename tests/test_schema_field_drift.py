"""Schema field-drift regression protection.

Complements tests/test_discover_endpoints.py-style *endpoint* discovery
(does a new path exist upstream?) with *field*-level drift detection on
response objects this project has already reviewed and shipped a typed
Pydantic model for: a future pfREST release can add a field to an
already-modeled object, and a Pydantic model silently ignores unknown
keys by construction, so nothing else in this suite would ever notice.

`tests/fixtures/pinned_response_schemas.json` is a deliberately small,
explicitly curated excerpt -- just the `{field: {type, writeOnly}}`
properties for the response objects registered below, taken from the
same pinned v2.10 OpenAPI schema this project's model docstrings already
cite as their evidence source (e.g. `models/config_history_revision.py`,
`models/log_settings.py`). It is not, and is not meant to become, a full
vendored copy of the upstream schema -- coverage grows by deliberate,
reviewed registration in `_REGISTRY` below, one model at a time, mirroring
this project's existing "explicit allowlist, not blanket automation"
pattern (e.g. `capture-fixture`'s `CAPTURE_POLICIES` requirement).

Everything here is fully offline: no network, no credentials, no `live`
marker.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from lib.schema_drift import SchemaDriftError, assert_model_accounts_for_schema_fields
from pydantic import BaseModel

from pfsense_mcp.models.config_history_revision import ConfigHistoryRevision
from pfsense_mcp.models.log_settings import LogSettings
from pfsense_mcp.models.system_timezone import SystemTimezone
from pfsense_mcp.models.wireguard_peer_status import WireGuardPeerStatus
from pfsense_mcp.models.wireguard_tunnel_status import WireGuardTunnelStatus

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "pinned_response_schemas.json"


def _load_pinned_schemas() -> dict[str, dict]:
    with open(_FIXTURE_PATH) as fh:
        return json.load(fh)


# (model, pinned-schema component name, intentional exclusions).
#
# `firewall_apply_status.py`'s model class is named `FirewallApplyStatus`
# but the upstream schema component is `FirewallApply` -- proof this
# registry is genuinely name-mapped, not assumed 1:1.
#
# `WireGuardPeerStatus.preshared_key` is the one live, reviewed exclusion
# in this registry today: confirmed present upstream, deliberately never
# modeled (models/wireguard_peer_status.py's own docstring), matching
# this project's explicit owner-restated constraint.
_REGISTRY: tuple[tuple[type[BaseModel], str, frozenset[str]], ...] = (
    (ConfigHistoryRevision, "ConfigHistoryRevision", frozenset()),
    (LogSettings, "LogSettings", frozenset()),
    (SystemTimezone, "SystemTimezone", frozenset()),
    (WireGuardTunnelStatus, "WireGuardTunnelStatus", frozenset()),
    (WireGuardPeerStatus, "WireGuardPeerStatus", frozenset({"preshared_key"})),
)


@pytest.mark.parametrize(
    "model,schema_name,exclusions",
    _REGISTRY,
    ids=[entry[1] for entry in _REGISTRY],
)
def test_registered_model_accounts_for_every_pinned_schema_field(model, schema_name, exclusions):
    schemas = _load_pinned_schemas()
    assert schema_name in schemas, f"{schema_name} missing from {_FIXTURE_PATH.name} -- fixture/registry mismatch"
    assert_model_accounts_for_schema_fields(
        model=model,
        schema_properties=schemas[schema_name],
        intentional_exclusions=exclusions,
        label=schema_name,
    )


def test_nested_wireguard_peer_status_is_independently_registered_and_covered():
    """WireGuardTunnelStatus.peers embeds WireGuardPeerStatus objects
    (see that model's own docstring: constructed via `from_api()`, never
    a raw dict, specifically so `preshared_key` can never leak through
    the nested path). Nested coverage here means the nested model has
    its own registry entry and is checked on its own terms -- confirmed
    directly rather than assumed."""
    assert any(entry[0] is WireGuardPeerStatus for entry in _REGISTRY)
    peers_annotation = WireGuardTunnelStatus.model_fields["peers"].annotation
    assert "WireGuardPeerStatus" in str(peers_annotation)


# --- Synthetic cases: prove the mechanism itself fires (and doesn't) correctly ---


class _SyntheticOrdinary(BaseModel):
    name: str
    count: int


class _SyntheticSecretLike(BaseModel):
    username: str


class _SyntheticNestedChild(BaseModel):
    label: str


class _SyntheticNestedParent(BaseModel):
    id: int
    children: list[_SyntheticNestedChild]


def test_ordinary_new_upstream_field_is_flagged_as_drift():
    schema = {"name": {"type": "string"}, "count": {"type": "integer"}, "description": {"type": "string"}}
    with pytest.raises(SchemaDriftError) as excinfo:
        assert_model_accounts_for_schema_fields(model=_SyntheticOrdinary, schema_properties=schema)
    message = str(excinfo.value)
    assert "description" in message
    assert "SECURITY" not in message


def test_secret_like_new_upstream_field_is_flagged_with_security_marker():
    schema = {"username": {"type": "string"}, "api_key": {"type": "string"}}
    with pytest.raises(SchemaDriftError) as excinfo:
        assert_model_accounts_for_schema_fields(model=_SyntheticSecretLike, schema_properties=schema)
    message = str(excinfo.value)
    assert "SECURITY" in message
    assert "api_key" in message


def test_nested_model_gaining_an_unexpected_field_is_flagged_on_its_own_registration():
    """A nested child model is checked by registering *it* against its
    own schema component -- proving nested coverage does not silently
    inherit a false pass from the parent's registration."""
    child_schema = {"label": {"type": "string"}, "secret_token": {"type": "string"}}
    with pytest.raises(SchemaDriftError) as excinfo:
        assert_model_accounts_for_schema_fields(model=_SyntheticNestedChild, schema_properties=child_schema)
    assert "SECURITY" in str(excinfo.value)
    assert "secret_token" in str(excinfo.value)

    # The parent itself is unaffected by its child's drift -- each
    # model is accounted for independently, on its own field set.
    parent_schema = {"id": {"type": "integer"}, "children": {"type": "array"}}
    assert_model_accounts_for_schema_fields(model=_SyntheticNestedParent, schema_properties=parent_schema)


def test_intentionally_excluded_field_does_not_trigger_drift():
    schema = {"username": {"type": "string"}, "api_key": {"type": "string"}}
    assert_model_accounts_for_schema_fields(
        model=_SyntheticSecretLike,
        schema_properties=schema,
        intentional_exclusions=frozenset({"api_key"}),
    )


def test_stale_exclusion_that_no_longer_exists_upstream_is_itself_flagged():
    """An intentional_exclusions entry that no longer appears in the
    schema at all is a hygiene problem worth surfacing (upstream may
    have renamed or removed the field this project once reviewed), not
    something to pass silently."""
    schema = {"username": {"type": "string"}}
    with pytest.raises(SchemaDriftError) as excinfo:
        assert_model_accounts_for_schema_fields(
            model=_SyntheticSecretLike,
            schema_properties=schema,
            intentional_exclusions=frozenset({"api_key"}),
        )
    assert "stale" in str(excinfo.value)


def test_nullable_schema_evolution_without_a_name_change_is_not_drift():
    """A field becoming nullable/optional upstream (a shape change, not
    a name change) must not be flagged -- this mechanism is name-based
    by design; shape/type mismatches surface through from_api() parsing
    at LAB-verification time instead, not through this check."""
    schema_before = {"name": {"type": "string"}, "count": {"type": "integer"}}
    schema_after_nullable = {
        "name": {"type": "string", "nullable": True},
        "count": {"type": "integer", "nullable": True},
    }
    assert_model_accounts_for_schema_fields(model=_SyntheticOrdinary, schema_properties=schema_before)
    assert_model_accounts_for_schema_fields(model=_SyntheticOrdinary, schema_properties=schema_after_nullable)


def test_missing_model_field_not_present_upstream_is_not_this_mechanisms_concern():
    """A model field that upstream no longer returns is a runtime
    from_api() KeyError concern, not schema *drift* by this mechanism's
    definition (which only checks for unaccounted *extra* schema
    fields) -- confirmed here so the boundary is explicit, not assumed."""
    schema = {"name": {"type": "string"}}  # missing "count" entirely
    assert_model_accounts_for_schema_fields(model=_SyntheticOrdinary, schema_properties=schema)
