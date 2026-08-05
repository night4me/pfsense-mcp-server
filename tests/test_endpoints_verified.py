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


def test_firewall_rules_is_declared_verified():
    assert Endpoints.FIREWALL_RULES.verified is True


def test_firewall_rules_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_RULES.path_suffix.startswith("/api")


def test_firewall_rules_path_suffix_is_the_plural_list_endpoint():
    # FIREWALL_READ must use the plural rules list, never the
    # singular id-scoped /api/v2/firewall/rule endpoint.
    assert Endpoints.FIREWALL_RULES.path_suffix == "/firewall/rules"


def test_firewall_states_is_declared_verified():
    assert Endpoints.FIREWALL_STATES.verified is True


def test_firewall_states_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_STATES.path_suffix.startswith("/api")


def test_firewall_states_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.FIREWALL_STATES.path_suffix == "/firewall/states"


def test_firewall_states_size_is_declared_verified():
    assert Endpoints.FIREWALL_STATES_SIZE.verified is True


def test_firewall_states_size_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_STATES_SIZE.path_suffix.startswith("/api")


def test_firewall_states_size_path_suffix_is_correct():
    assert Endpoints.FIREWALL_STATES_SIZE.path_suffix == "/firewall/states/size"


def test_firewall_apply_status_is_declared_verified():
    assert Endpoints.FIREWALL_APPLY_STATUS.verified is True


def test_firewall_apply_status_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_APPLY_STATUS.path_suffix.startswith("/api")


def test_firewall_apply_status_path_suffix_is_correct():
    assert Endpoints.FIREWALL_APPLY_STATUS.path_suffix == "/firewall/apply"


def test_firewall_aliases_is_declared_verified():
    assert Endpoints.FIREWALL_ALIASES.verified is True


def test_firewall_aliases_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_ALIASES.path_suffix.startswith("/api")


def test_firewall_aliases_path_suffix_is_the_plural_list_endpoint():
    # FIREWALL_ALIAS_READ must use the plural aliases list, never the
    # singular id-scoped /api/v2/firewall/alias endpoint.
    assert Endpoints.FIREWALL_ALIASES.path_suffix == "/firewall/aliases"


def test_status_services_is_declared_verified():
    assert Endpoints.STATUS_SERVICES.verified is True


def test_status_services_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_SERVICES.path_suffix.startswith("/api")


def test_status_services_path_suffix_is_correct():
    assert Endpoints.STATUS_SERVICES.path_suffix == "/status/services"


def test_system_version_is_declared_verified():
    assert Endpoints.SYSTEM_VERSION.verified is True


def test_system_version_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_VERSION.path_suffix.startswith("/api")


def test_system_version_path_suffix_is_correct():
    assert Endpoints.SYSTEM_VERSION.path_suffix == "/system/version"


def test_interfaces_is_declared_verified():
    assert Endpoints.INTERFACES.verified is True


def test_interfaces_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACES.path_suffix.startswith("/api")


def test_interfaces_path_suffix_is_correct():
    assert Endpoints.INTERFACES.path_suffix == "/interfaces"


def test_firewall_nat_port_forwards_is_declared_verified():
    assert Endpoints.FIREWALL_NAT_PORT_FORWARDS.verified is True


def test_firewall_nat_port_forwards_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_NAT_PORT_FORWARDS.path_suffix.startswith("/api")


def test_firewall_nat_port_forwards_path_suffix_is_correct():
    assert Endpoints.FIREWALL_NAT_PORT_FORWARDS.path_suffix == "/firewall/nat/port_forwards"


def test_firewall_nat_outbound_mode_is_declared_verified():
    assert Endpoints.FIREWALL_NAT_OUTBOUND_MODE.verified is True


def test_firewall_nat_outbound_mode_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_NAT_OUTBOUND_MODE.path_suffix.startswith("/api")


def test_firewall_nat_outbound_mode_path_suffix_is_correct():
    assert Endpoints.FIREWALL_NAT_OUTBOUND_MODE.path_suffix == "/firewall/nat/outbound/mode"


def test_users_is_declared_verified():
    assert Endpoints.USERS.verified is True


def test_users_path_suffix_has_no_api_prefix():
    assert not Endpoints.USERS.path_suffix.startswith("/api")


def test_users_path_suffix_is_correct():
    assert Endpoints.USERS.path_suffix == "/users"


def test_system_certificates_is_declared_verified():
    assert Endpoints.SYSTEM_CERTIFICATES.verified is True


def test_system_certificates_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_CERTIFICATES.path_suffix.startswith("/api")


def test_system_certificates_path_suffix_is_correct():
    assert Endpoints.SYSTEM_CERTIFICATES.path_suffix == "/system/certificates"


def test_firewall_read_does_not_expose_alias_or_log_endpoints():
    # FIREWALL_READ is scoped to rules/states/states-size/apply-status
    # only. Aliases and logs are separate, not-yet-implemented
    # capabilities and must never be declared here.
    declared_suffixes = {
        Endpoints.FIREWALL_RULES.path_suffix,
        Endpoints.FIREWALL_STATES.path_suffix,
        Endpoints.FIREWALL_STATES_SIZE.path_suffix,
        Endpoints.FIREWALL_APPLY_STATUS.path_suffix,
    }
    assert "/firewall/alias" not in declared_suffixes
    assert "/firewall/aliases" not in declared_suffixes
    assert "/status/logs/firewall" not in declared_suffixes
