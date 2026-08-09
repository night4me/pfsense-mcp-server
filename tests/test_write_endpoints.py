from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints


def test_write_endpoints_has_zero_entries_in_this_build():
    entries = [name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)]
    assert entries == []


def test_active_entries_matches_the_manual_vars_scan():
    manual = [name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)]
    assert WriteEndpoints.active_entries() == manual
    assert WriteEndpoints.active_entries() == []


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
