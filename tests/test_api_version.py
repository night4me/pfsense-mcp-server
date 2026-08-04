from pfsense_mcp.api_version import ApiVersion, version_at_least


def test_v2_is_at_least_v2():
    assert version_at_least(ApiVersion.V2, ApiVersion.V2) is True
