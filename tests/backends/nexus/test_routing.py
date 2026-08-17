"""Phase E (ADR-032): adversarial coverage for build_device_base_path,
the one piece of the specified Nexus transport that is real, tested
code this phase -- proving malformed device_type/device_id values are
rejected before any URL is ever constructed, not silently encoded
around.
"""

from __future__ import annotations

import pytest

from pfsense_mcp.backends.nexus.routing import build_device_base_path


def test_builds_expected_path_for_confirmed_pfsense_device_type():
    assert build_device_base_path("pfsense", "abc123") == "/api/device/pfsense/abc123/api"


def test_accepts_uuid_shaped_device_id():
    device_id = "550e8400-e29b-41d4-a716-446655440000"
    assert build_device_base_path("pfsense", device_id) == f"/api/device/pfsense/{device_id}/api"


def test_accepts_alphanumeric_with_underscore_and_dot():
    assert build_device_base_path("pfsense", "dev.id_1") == "/api/device/pfsense/dev.id_1/api"


@pytest.mark.parametrize(
    "device_id",
    [
        "",
        "../etc/passwd",
        "a/b",
        "a b",
        "a?b=c",
        "a#fragment",
        "a%2e%2e",
        "a\nb",
        "a\tb",
        "a" * 129,
    ],
)
def test_rejects_malformed_device_id(device_id):
    with pytest.raises(ValueError, match="device_id"):
        build_device_base_path("pfsense", device_id)


@pytest.mark.parametrize(
    "device_type",
    [
        "",
        "../pfsense",
        "pf/sense",
        "pf sense",
        "pfsense?x=1",
    ],
)
def test_rejects_malformed_device_type(device_type):
    with pytest.raises(ValueError, match="device_type"):
        build_device_base_path(device_type, "abc123")


def test_rejects_non_string_device_id():
    with pytest.raises(ValueError):
        build_device_base_path("pfsense", 12345)  # type: ignore[arg-type]


def test_rejects_none_device_id():
    with pytest.raises(ValueError):
        build_device_base_path("pfsense", None)  # type: ignore[arg-type]


def test_does_not_hardcode_pfsense_as_the_only_device_type():
    """device_type has no enum constraint in the official schema
    (ADR-032 Section 2) -- must remain a caller-supplied value, not a
    hardcoded constant, even though every known example uses
    "pfsense"."""

    assert build_device_base_path("othertype", "abc123") == "/api/device/othertype/abc123/api"
