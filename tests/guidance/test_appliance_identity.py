"""ADR-018 Appliance Identity: ObservedEdition, infer_edition_from_version_base(),
ApplianceIdentity, resolve_appliance_identity(). Exhaustive deterministic
classification-boundary coverage -- the invariant under test throughout
is "unknown input -> UNKNOWN", never "unknown input -> best guess".
"""

from __future__ import annotations

import json

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.guidance.appliance_identity import (
    ApplianceIdentity,
    ObservedEdition,
    infer_edition_from_version_base,
    resolve_appliance_identity,
)
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.mock import MockTransport

# --- Representative CE versions (documented range: major 1-2, 1.2.x through 2.9.x) ---


@pytest.mark.parametrize(
    "base",
    ["1.2.3", "2.0.0", "2.4.5", "2.6.0", "2.7.2", "2.8.0", "2.8.1", "2.9.0"],
)
def test_representative_ce_versions_classify_known_ce(base: str) -> None:
    assert infer_edition_from_version_base(base) is ObservedEdition.KNOWN_CE


# --- Representative Plus versions (documented range: year >= 21, began 21.02) ---


@pytest.mark.parametrize(
    "base",
    ["21.02", "22.01", "23.05.1", "24.11", "25.07", "25.07.1", "26.03", "26.03.1"],
)
def test_representative_plus_versions_classify_known_plus(base: str) -> None:
    assert infer_edition_from_version_base(base) is ObservedEdition.KNOWN_PLUS


# --- Boundary cases between the known CE and Plus schemes ---


def test_ce_upper_boundary_major_9_is_known_ce() -> None:
    assert infer_edition_from_version_base("9.9.9") is ObservedEdition.KNOWN_CE


def test_plus_lower_boundary_major_21_is_known_plus() -> None:
    assert infer_edition_from_version_base("21.0") is ObservedEdition.KNOWN_PLUS


@pytest.mark.parametrize("base", ["10.0", "15.5", "20.12", "20.99"])
def test_dead_zone_between_known_schemes_is_unknown(base: str) -> None:
    """Major 10-20 is not a documented CE or Plus range -- must fail
    closed to UNKNOWN, not guess toward whichever range is "closer"."""
    assert infer_edition_from_version_base(base) is ObservedEdition.UNKNOWN


def test_plus_upper_boundary_major_99_is_known_plus() -> None:
    assert infer_edition_from_version_base("99.12") is ObservedEdition.KNOWN_PLUS


# --- Future-looking / out-of-range unknown forms ---


@pytest.mark.parametrize("base", ["100.1", "150.03", "1000.1.1"])
def test_future_out_of_range_major_is_unknown(base: str) -> None:
    """A value that would only occur if Netgate's numbering scheme
    changes again in the future -- must not be guessed into either
    known range."""
    assert infer_edition_from_version_base(base) is ObservedEdition.UNKNOWN


def test_major_zero_is_unknown() -> None:
    """No pfSense CE release has ever used major version 0 -- not a
    documented range, must fail closed."""
    assert infer_edition_from_version_base("0.5.0") is ObservedEdition.UNKNOWN


# --- Malformed / empty / non-numeric inputs ---


@pytest.mark.parametrize(
    "base",
    [
        "not-a-version",
        "",
        "abc.123",
        ".",
        "..",
        "RELEASE-26.03",
        "v2.7.2",
        "-1.0",
    ],
)
def test_malformed_or_non_numeric_input_is_unknown(base: str) -> None:
    assert infer_edition_from_version_base(base) is ObservedEdition.UNKNOWN


def test_bare_integer_with_no_dot_uses_whole_string_as_leading_component() -> None:
    """base.split(".", 1)[0] on a dot-free string returns the whole
    string -- exercised explicitly, not merely implied by the malformed
    cases above."""
    assert infer_edition_from_version_base("2") is ObservedEdition.KNOWN_CE
    assert infer_edition_from_version_base("26") is ObservedEdition.KNOWN_PLUS


# --- Prerelease/beta/RC forms, only to the extent evidence supports them ---


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("26.03-BETA", ObservedEdition.KNOWN_PLUS),
        ("2.8-RC1", ObservedEdition.KNOWN_CE),
        ("25.07.1-BETA", ObservedEdition.KNOWN_PLUS),
    ],
)
def test_prerelease_suffix_on_a_later_component_does_not_affect_classification(
    base: str, expected: ObservedEdition
) -> None:
    """SystemVersion.base is documented as patch-stripped for both
    editions; no prerelease/beta/RC form has been observed in this
    field specifically. This test does not assert that pfSense
    populates base this way -- it documents that IF a suffix trails the
    leading major/year component, classification is unaffected, since
    only the leading component is ever inspected (by construction, not
    by a special case added for this)."""
    assert infer_edition_from_version_base(base) is expected


def test_prerelease_marker_in_the_leading_component_itself_is_unknown() -> None:
    """The one prerelease shape this function cannot safely classify --
    a marker fused into the leading component itself, not a documented
    or observed pattern. Must fail closed, not guess."""
    assert infer_edition_from_version_base("RC26.03") is ObservedEdition.UNKNOWN


# --- ApplianceIdentity / resolve_appliance_identity() ---


def _client_with_version(base: str | None) -> PfSenseClient:
    transport = MockTransport()
    body = {"data": {"base": base, "buildtime": "20260101-0000", "patch": "0", "version": f"{base}-RELEASE"}}
    transport.register("GET", "/api/v2/system/version", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="test-identity", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client)


def test_resolve_appliance_identity_known_plus() -> None:
    client = _client_with_version("26.03.1")
    identity = resolve_appliance_identity(client)
    assert identity.observed_edition is ObservedEdition.KNOWN_PLUS
    assert identity.observed_version == "26.03.1"
    assert identity.identity_source == "SystemVersion.base (pfsense_get_system_version)"
    assert identity.resolved_at  # non-empty ISO8601 timestamp


def test_resolve_appliance_identity_known_ce() -> None:
    client = _client_with_version("2.7.2")
    identity = resolve_appliance_identity(client)
    assert identity.observed_edition is ObservedEdition.KNOWN_CE
    assert identity.observed_version == "2.7.2"


def test_resolve_appliance_identity_null_base_is_unknown_not_a_crash() -> None:
    client = _client_with_version(None)
    identity = resolve_appliance_identity(client)
    assert identity.observed_edition is ObservedEdition.UNKNOWN
    assert identity.observed_version is None


def test_appliance_identity_is_frozen_and_rejects_extra_fields() -> None:
    identity = ApplianceIdentity(
        observed_edition=ObservedEdition.UNKNOWN,
        observed_version=None,
        identity_source="SystemVersion.base (pfsense_get_system_version)",
        resolved_at="2026-08-09T00:00:00+00:00",
    )
    with pytest.raises(Exception):
        identity.observed_version = "changed"  # type: ignore[misc]

    with pytest.raises(Exception):
        ApplianceIdentity(
            observed_edition=ObservedEdition.UNKNOWN,
            observed_version=None,
            identity_source="x",
            resolved_at="x",
            hostname="should-not-be-allowed",  # type: ignore[call-arg]
        )


def test_appliance_identity_carries_no_disallowed_fields() -> None:
    """Structural check that the model's own field set matches ADR-018's
    accepted minimal shape -- no hostname, serial, MAC, IP, credential,
    or installation identifier field exists to populate, not merely
    "unused"."""
    disallowed_substrings = ("host", "serial", "mac", "ip_", "credential", "install", "uid", "netgate_id")
    fields = set(ApplianceIdentity.model_fields)
    assert fields == {"observed_edition", "observed_version", "identity_source", "resolved_at"}
    for field_name in fields:
        lowered = field_name.lower()
        assert not any(bad in lowered for bad in disallowed_substrings), field_name
