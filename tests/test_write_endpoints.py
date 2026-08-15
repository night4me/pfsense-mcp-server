from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints


def test_write_endpoints_has_exactly_the_accepted_entry_in_this_build():
    # Through W3 Slice 3, WriteEndpoints was empty. W3 Slice 4 added
    # exactly the one accepted first-WRITE entry -- scripts/write_allow_list_check.py
    # mechanically enforces this stays exact, not merely non-empty.
    entries = [name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)]
    assert entries == ["FIREWALL_ALIAS_DESCRIPTION"]
    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified is False
    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.http_method == "PATCH"
    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.path_suffix == "/firewall/alias"


def test_active_entries_matches_the_manual_vars_scan():
    manual = [name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)]
    assert WriteEndpoints.active_entries() == manual
    assert WriteEndpoints.active_entries() == ["FIREWALL_ALIAS_DESCRIPTION"]


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
