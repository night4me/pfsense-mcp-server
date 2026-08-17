"""Phase D: the first Nexus adapter with a concrete implementation.
Adversarial coverage for `normalize_carp_status`/`NexusCarpStatusReader`,
matching the rigor `pfsense_client.py`'s own object-response parsing
gets, plus the specific "absent, not just false" ambiguity Nexus's own
generated client (`bool | Unset`) revealed for this endpoint.
"""

from __future__ import annotations

import pytest

from pfsense_mcp.backends.nexus.carp_status import NexusCarpStatusReader, normalize_carp_status
from pfsense_mcp.backends.ports import CarpStatusReader
from pfsense_mcp.errors import PfSenseResponseShapeError
from pfsense_mcp.models.carp_status import CarpStatus


def test_normalizes_both_enabled():
    result = normalize_carp_status({"enabled": True, "maintenancemode_enabled": True})
    assert result == CarpStatus(enable=True, maintenance_mode=True)


def test_normalizes_both_disabled():
    result = normalize_carp_status({"enabled": False, "maintenancemode_enabled": False})
    assert result == CarpStatus(enable=False, maintenance_mode=False)


def test_normalizes_enabled_without_maintenance_mode():
    result = normalize_carp_status({"enabled": True, "maintenancemode_enabled": False})
    assert result == CarpStatus(enable=True, maintenance_mode=False)


def test_extra_nexus_only_fields_are_ignored():
    """my_hostid/state_sync_hostids/vips are richer Nexus-only fields
    with no community counterpart -- present or absent, they must not
    affect normalization."""

    result = normalize_carp_status(
        {
            "enabled": True,
            "maintenancemode_enabled": False,
            "my_hostid": "abc123",
            "state_sync_hostids": ["abc123", "def456"],
            "vips": [{"interface": "wan", "vhid": 1}],
        }
    )
    assert result == CarpStatus(enable=True, maintenance_mode=False)


def test_missing_enabled_key_fails_closed():
    """Nexus's own official generated client types `enabled` as
    `bool | Unset` -- genuinely possibly absent, not merely nullable.
    Must never be treated as False."""

    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({"maintenancemode_enabled": True})


def test_missing_maintenancemode_enabled_key_fails_closed():
    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({"enabled": True})


def test_both_keys_missing_fails_closed():
    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({})


def test_empty_response_body_fails_closed():
    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({"my_hostid": "abc123"})


def test_wrong_type_for_enabled_fails_closed():
    # "true"/"false" strings are accepted by CarpStatus's own lax bool
    # coercion (pre-existing, shared with the community backend -- not
    # something this adapter adds) -- use a value neither backend's
    # model could ever legitimately coerce.
    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({"enabled": [1, 2], "maintenancemode_enabled": False})


def test_wrong_type_for_maintenancemode_enabled_fails_closed():
    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({"enabled": True, "maintenancemode_enabled": {"nested": "object"}})


def test_null_enabled_fails_closed():
    """Nexus could plausibly send an explicit JSON null rather than
    omitting the key -- must not be coerced to False either."""

    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({"enabled": None, "maintenancemode_enabled": True})


def test_null_maintenancemode_enabled_fails_closed():
    with pytest.raises(PfSenseResponseShapeError):
        normalize_carp_status({"enabled": True, "maintenancemode_enabled": None})


def test_reader_calls_injected_fetch_and_normalizes():
    calls = []

    def fetch_raw():
        calls.append(1)
        return {"enabled": True, "maintenancemode_enabled": False}

    reader = NexusCarpStatusReader(fetch_raw)
    result = reader.get_carp_status()

    assert result == CarpStatus(enable=True, maintenance_mode=False)
    assert len(calls) == 1


def test_reader_propagates_fail_closed_error_from_malformed_fetch():
    reader = NexusCarpStatusReader(lambda: {"enabled": True})

    with pytest.raises(PfSenseResponseShapeError):
        reader.get_carp_status()


def test_reader_satisfies_carp_status_reader_protocol():
    reader: CarpStatusReader = NexusCarpStatusReader(lambda: {"enabled": True, "maintenancemode_enabled": True})
    assert reader.get_carp_status() == CarpStatus(enable=True, maintenance_mode=True)


def test_reader_does_not_fetch_eagerly():
    """Constructing the reader must not itself call fetch_raw -- only
    get_carp_status() should trigger it, so a caller can construct
    readers speculatively without side effects."""

    def fetch_raw():
        raise AssertionError("fetch_raw must not be called by __init__")

    NexusCarpStatusReader(fetch_raw)
