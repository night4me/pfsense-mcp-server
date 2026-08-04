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


def test_routing_gateways_is_declared_verified():
    assert Endpoints.ROUTING_GATEWAYS.verified is True


def test_routing_gateways_path_suffix_has_no_api_prefix():
    assert not Endpoints.ROUTING_GATEWAYS.path_suffix.startswith("/api")


def test_routing_gateways_path_suffix_is_the_plural_list_endpoint():
    # GATEWAY_READ must use the plural gateways list, never the
    # singular id-scoped /api/v2/routing/gateway endpoint.
    assert Endpoints.ROUTING_GATEWAYS.path_suffix == "/routing/gateways"


def test_status_gateways_is_declared_verified():
    assert Endpoints.STATUS_GATEWAYS.verified is True


def test_status_gateways_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_GATEWAYS.path_suffix.startswith("/api")


def test_status_gateways_path_suffix_is_the_status_endpoint():
    assert Endpoints.STATUS_GATEWAYS.path_suffix == "/status/gateways"
