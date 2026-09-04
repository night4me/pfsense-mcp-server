from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

#: ADR-037 Batch 1 (2026-09-04, owner) raised this from one to exactly six
#: entries -- see write_endpoints.py's own module docstring.
_EXPECTED_ENTRIES = frozenset(
    {
        "FIREWALL_ALIAS_DESCRIPTION",
        "NTP_TIME_SERVER_PREFER",
        "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
        "LOG_DISPLAY_PREFERENCES",
        "LOG_RETENTION_SETTINGS",
        "SYSTEM_TIMEZONE",
    }
)


def test_write_endpoints_has_exactly_the_accepted_entries_in_this_build():
    entries = {name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)}
    assert entries == _EXPECTED_ENTRIES
    # verified=True since 2026-08-16 -- see write_endpoints.py's own module
    # docstring for the exact live-evidence chain (ADR-026 rows 6/17/18).
    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified is True
    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.http_method == "PATCH"
    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.path_suffix == "/firewall/alias"
    # Every ADR-037 Batch 1 entry is verified=False -- no LAB evidence yet.
    for name, path_suffix in (
        ("NTP_TIME_SERVER_PREFER", "/services/ntp/time_server"),
        ("NTP_SETTINGS_OBSERVABILITY_TOGGLES", "/services/ntp/settings"),
        ("LOG_DISPLAY_PREFERENCES", "/status/logs/settings"),
        ("LOG_RETENTION_SETTINGS", "/status/logs/settings"),
        ("SYSTEM_TIMEZONE", "/system/timezone"),
    ):
        entry = getattr(WriteEndpoints, name)
        assert entry.verified is False, name
        assert entry.http_method == "PATCH"
        assert entry.path_suffix == path_suffix
        assert entry.reversible is True
        assert entry.dry_run_supported is True


def test_active_entries_matches_the_manual_vars_scan():
    manual = [name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)]
    assert set(WriteEndpoints.active_entries()) == set(manual)
    assert set(WriteEndpoints.active_entries()) == _EXPECTED_ENTRIES


def test_write_endpoint_info_is_frozen_and_constructible():
    from pfsense_mcp.api_version import ApiVersion

    entry = WriteEndpointInfo(
        path_suffix="/example",
        http_method="POST",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
    )
    assert entry.http_method == "POST"
    assert entry.verified is False
