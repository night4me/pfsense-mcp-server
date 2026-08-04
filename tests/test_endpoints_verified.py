"""Every declared endpoint must be marked verified=True only for
endpoints that have actually been checked against the live instance.
This test does not prove correctness — it just prevents unverified
endpoints from being declared silently as verified=True by mistake."""

from pfsense_mcp.endpoints import Endpoints


def test_system_status_is_declared_verified():
    assert Endpoints.SYSTEM_STATUS.verified is True


def test_system_status_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_STATUS.path_suffix.startswith("/api")


def test_status_interfaces_is_declared_verified():
    assert Endpoints.STATUS_INTERFACES.verified is True


def test_status_interfaces_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_INTERFACES.path_suffix.startswith("/api")


def test_status_interfaces_does_not_expose_config_endpoint():
    # INTERFACE_READ must use the status/stats endpoint, never the
    # mutable /api/v2/interfaces config endpoint.
    assert Endpoints.STATUS_INTERFACES.path_suffix == "/status/interfaces"
