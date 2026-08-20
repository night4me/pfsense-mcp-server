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


def test_user_groups_is_declared_verified():
    assert Endpoints.USER_GROUPS.verified is True


def test_user_groups_path_suffix_has_no_api_prefix():
    assert not Endpoints.USER_GROUPS.path_suffix.startswith("/api")


def test_user_groups_path_suffix_is_correct():
    assert Endpoints.USER_GROUPS.path_suffix == "/user/groups"


def test_config_history_revisions_is_declared_verified():
    assert Endpoints.DIAGNOSTICS_CONFIG_HISTORY_REVISIONS.verified is True


def test_config_history_revisions_path_suffix_has_no_api_prefix():
    assert not Endpoints.DIAGNOSTICS_CONFIG_HISTORY_REVISIONS.path_suffix.startswith("/api")


def test_config_history_revisions_path_suffix_is_correct():
    assert Endpoints.DIAGNOSTICS_CONFIG_HISTORY_REVISIONS.path_suffix == "/diagnostics/config_history/revisions"


def test_status_dhcp_leases_is_declared_verified():
    assert Endpoints.STATUS_DHCP_LEASES.verified is True


def test_status_dhcp_leases_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_DHCP_LEASES.path_suffix.startswith("/api")


def test_status_dhcp_leases_path_suffix_is_correct():
    assert Endpoints.STATUS_DHCP_LEASES.path_suffix == "/status/dhcp_server/leases"


def test_dhcp_server_static_mappings_is_declared_verified():
    assert Endpoints.DHCP_SERVER_STATIC_MAPPINGS.verified is True


def test_dhcp_server_static_mappings_path_suffix_has_no_api_prefix():
    assert not Endpoints.DHCP_SERVER_STATIC_MAPPINGS.path_suffix.startswith("/api")


def test_dhcp_server_static_mappings_path_suffix_is_correct():
    assert Endpoints.DHCP_SERVER_STATIC_MAPPINGS.path_suffix == "/services/dhcp_server/static_mappings"


def test_dhcp_servers_is_declared_verified():
    assert Endpoints.DHCP_SERVERS.verified is True


def test_dhcp_servers_path_suffix_has_no_api_prefix():
    assert not Endpoints.DHCP_SERVERS.path_suffix.startswith("/api")


def test_dhcp_servers_path_suffix_is_correct():
    assert Endpoints.DHCP_SERVERS.path_suffix == "/services/dhcp_servers"


def test_interface_bridges_is_declared_verified():
    assert Endpoints.INTERFACE_BRIDGES.verified is True


def test_interface_bridges_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACE_BRIDGES.path_suffix.startswith("/api")


def test_interface_bridges_path_suffix_is_correct():
    assert Endpoints.INTERFACE_BRIDGES.path_suffix == "/interface/bridges"


def test_status_carp_is_declared_verified():
    assert Endpoints.STATUS_CARP.verified is True


def test_status_carp_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_CARP.path_suffix.startswith("/api")


def test_status_carp_path_suffix_is_correct():
    assert Endpoints.STATUS_CARP.path_suffix == "/status/carp"


def test_system_restapi_settings_is_declared_verified():
    assert Endpoints.SYSTEM_RESTAPI_SETTINGS.verified is True


def test_system_restapi_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_RESTAPI_SETTINGS.path_suffix.startswith("/api")


def test_system_restapi_settings_path_suffix_is_correct():
    assert Endpoints.SYSTEM_RESTAPI_SETTINGS.path_suffix == "/system/restapi/settings"


def test_system_hasync_is_declared_verified():
    assert Endpoints.SYSTEM_HASYNC.verified is True


def test_system_hasync_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_HASYNC.path_suffix.startswith("/api")


def test_system_hasync_path_suffix_is_correct():
    assert Endpoints.SYSTEM_HASYNC.path_suffix == "/system/hasync"


def test_dns_resolver_host_overrides_is_declared_verified():
    assert Endpoints.DNS_RESOLVER_HOST_OVERRIDES.verified is True


def test_dns_resolver_host_overrides_path_suffix_has_no_api_prefix():
    assert not Endpoints.DNS_RESOLVER_HOST_OVERRIDES.path_suffix.startswith("/api")


def test_dns_resolver_host_overrides_path_suffix_is_correct():
    assert Endpoints.DNS_RESOLVER_HOST_OVERRIDES.path_suffix == "/services/dns_resolver/host_overrides"


def test_dns_resolver_settings_is_declared_verified():
    assert Endpoints.DNS_RESOLVER_SETTINGS.verified is True


def test_dns_resolver_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.DNS_RESOLVER_SETTINGS.path_suffix.startswith("/api")


def test_dns_resolver_settings_path_suffix_is_correct():
    assert Endpoints.DNS_RESOLVER_SETTINGS.path_suffix == "/services/dns_resolver/settings"


def test_diagnostics_arp_table_is_declared_verified():
    assert Endpoints.DIAGNOSTICS_ARP_TABLE.verified is True


def test_diagnostics_arp_table_path_suffix_has_no_api_prefix():
    assert not Endpoints.DIAGNOSTICS_ARP_TABLE.path_suffix.startswith("/api")


def test_diagnostics_arp_table_path_suffix_is_correct():
    assert Endpoints.DIAGNOSTICS_ARP_TABLE.path_suffix == "/diagnostics/arp_table"


def test_firewall_traffic_shaper_limiters_is_declared_verified():
    assert Endpoints.FIREWALL_TRAFFIC_SHAPER_LIMITERS.verified is True


def test_firewall_traffic_shaper_limiters_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_TRAFFIC_SHAPER_LIMITERS.path_suffix.startswith("/api")


def test_firewall_traffic_shaper_limiters_path_suffix_is_correct():
    assert Endpoints.FIREWALL_TRAFFIC_SHAPER_LIMITERS.path_suffix == "/firewall/traffic_shaper/limiters"


def test_firewall_advanced_settings_is_declared_verified():
    assert Endpoints.FIREWALL_ADVANCED_SETTINGS.verified is True


def test_firewall_advanced_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_ADVANCED_SETTINGS.path_suffix.startswith("/api")


def test_firewall_advanced_settings_path_suffix_is_correct():
    assert Endpoints.FIREWALL_ADVANCED_SETTINGS.path_suffix == "/firewall/advanced_settings"


def test_system_packages_is_declared_verified():
    assert Endpoints.SYSTEM_PACKAGES.verified is True


def test_system_packages_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_PACKAGES.path_suffix.startswith("/api")


def test_system_packages_path_suffix_is_correct():
    assert Endpoints.SYSTEM_PACKAGES.path_suffix == "/system/packages"


def test_system_tunables_is_declared_verified():
    assert Endpoints.SYSTEM_TUNABLES.verified is True


def test_system_tunables_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_TUNABLES.path_suffix.startswith("/api")


def test_system_tunables_path_suffix_is_correct():
    assert Endpoints.SYSTEM_TUNABLES.path_suffix == "/system/tunables"


def test_system_notifications_email_settings_is_declared_verified():
    assert Endpoints.SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS.verified is True


def test_system_notifications_email_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS.path_suffix.startswith("/api")


def test_system_notifications_email_settings_path_suffix_is_correct():
    assert Endpoints.SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS.path_suffix == "/system/notifications/email_settings"


def test_bind_settings_is_declared_verified():
    assert Endpoints.BIND_SETTINGS.verified is True


def test_bind_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.BIND_SETTINGS.path_suffix.startswith("/api")


def test_bind_settings_path_suffix_is_correct():
    assert Endpoints.BIND_SETTINGS.path_suffix == "/services/bind/settings"


def test_ntp_settings_is_declared_verified():
    assert Endpoints.NTP_SETTINGS.verified is True


def test_ntp_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.NTP_SETTINGS.path_suffix.startswith("/api")


def test_ntp_settings_path_suffix_is_correct():
    assert Endpoints.NTP_SETTINGS.path_suffix == "/services/ntp/settings"


def test_ntp_time_servers_is_declared_verified():
    assert Endpoints.NTP_TIME_SERVERS.verified is True


def test_ntp_time_servers_path_suffix_has_no_api_prefix():
    assert not Endpoints.NTP_TIME_SERVERS.path_suffix.startswith("/api")


def test_ntp_time_servers_path_suffix_is_correct():
    assert Endpoints.NTP_TIME_SERVERS.path_suffix == "/services/ntp/time_servers"


def test_services_ssh_is_declared_verified():
    assert Endpoints.SERVICES_SSH.verified is True


def test_services_ssh_path_suffix_has_no_api_prefix():
    assert not Endpoints.SERVICES_SSH.path_suffix.startswith("/api")


def test_services_ssh_path_suffix_is_correct():
    assert Endpoints.SERVICES_SSH.path_suffix == "/services/ssh"


def test_cron_jobs_is_declared_verified():
    assert Endpoints.CRON_JOBS.verified is True


def test_cron_jobs_path_suffix_has_no_api_prefix():
    assert not Endpoints.CRON_JOBS.path_suffix.startswith("/api")


def test_cron_jobs_path_suffix_is_correct():
    assert Endpoints.CRON_JOBS.path_suffix == "/services/cron/jobs"


def test_acme_settings_is_declared_verified():
    assert Endpoints.ACME_SETTINGS.verified is True


def test_acme_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.ACME_SETTINGS.path_suffix.startswith("/api")


def test_acme_settings_path_suffix_is_correct():
    assert Endpoints.ACME_SETTINGS.path_suffix == "/services/acme/settings"


def test_freeradius_eap_is_declared_verified():
    assert Endpoints.FREERADIUS_EAP.verified is True


def test_freeradius_eap_path_suffix_has_no_api_prefix():
    assert not Endpoints.FREERADIUS_EAP.path_suffix.startswith("/api")


def test_freeradius_eap_path_suffix_is_correct():
    assert Endpoints.FREERADIUS_EAP.path_suffix == "/services/freeradius/eap"


def test_diagnostics_tables_is_declared_verified():
    assert Endpoints.DIAGNOSTICS_TABLES.verified is True


def test_diagnostics_tables_path_suffix_has_no_api_prefix():
    assert not Endpoints.DIAGNOSTICS_TABLES.path_suffix.startswith("/api")


def test_diagnostics_tables_path_suffix_is_correct():
    assert Endpoints.DIAGNOSTICS_TABLES.path_suffix == "/diagnostics/tables"


def test_auth_keys_is_declared_verified():
    assert Endpoints.AUTH_KEYS.verified is True


def test_auth_keys_path_suffix_has_no_api_prefix():
    assert not Endpoints.AUTH_KEYS.path_suffix.startswith("/api")


def test_auth_keys_path_suffix_is_correct():
    assert Endpoints.AUTH_KEYS.path_suffix == "/auth/keys"


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


def test_firewall_nat_outbound_mappings_is_declared_verified():
    # Live-verified 2026-08-20 against the production appliance -- see
    # Endpoints.FIREWALL_NAT_OUTBOUND_MAPPINGS's own comment for the
    # exact verification method (zero live records; schema-level exact
    # match used for field-type/nullability confidence instead).
    assert Endpoints.FIREWALL_NAT_OUTBOUND_MAPPINGS.verified is True


def test_firewall_nat_outbound_mappings_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_NAT_OUTBOUND_MAPPINGS.path_suffix.startswith("/api")


def test_firewall_nat_outbound_mappings_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.FIREWALL_NAT_OUTBOUND_MAPPINGS.path_suffix == "/firewall/nat/outbound/mappings"


def test_firewall_nat_one_to_one_mappings_is_declared_verified():
    assert Endpoints.FIREWALL_NAT_ONE_TO_ONE_MAPPINGS.verified is True


def test_firewall_nat_one_to_one_mappings_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_NAT_ONE_TO_ONE_MAPPINGS.path_suffix.startswith("/api")


def test_firewall_nat_one_to_one_mappings_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.FIREWALL_NAT_ONE_TO_ONE_MAPPINGS.path_suffix == "/firewall/nat/one_to_one/mappings"


def test_interface_vlans_is_declared_verified():
    # LAB-verified 2026-08-20 (owner-authorized Phase 8) -- see
    # Endpoints.INTERFACE_VLANS's own comment for the exact verification
    # method (LAB identity confirmed, REST API v2.10 exact schema match,
    # zero live records; schema-level match used for field-type
    # confidence instead).
    assert Endpoints.INTERFACE_VLANS.verified is True


def test_interface_vlans_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACE_VLANS.path_suffix.startswith("/api")


def test_interface_vlans_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.INTERFACE_VLANS.path_suffix == "/interface/vlans"


def test_routing_static_routes_is_declared_verified():
    assert Endpoints.ROUTING_STATIC_ROUTES.verified is True


def test_routing_static_routes_path_suffix_has_no_api_prefix():
    assert not Endpoints.ROUTING_STATIC_ROUTES.path_suffix.startswith("/api")


def test_routing_static_routes_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.ROUTING_STATIC_ROUTES.path_suffix == "/routing/static_routes"


def test_interface_groups_is_declared_verified():
    assert Endpoints.INTERFACE_GROUPS.verified is True


def test_interface_groups_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACE_GROUPS.path_suffix.startswith("/api")


def test_interface_groups_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.INTERFACE_GROUPS.path_suffix == "/interface/groups"


def test_firewall_schedules_is_declared_verified():
    assert Endpoints.FIREWALL_SCHEDULES.verified is True


def test_firewall_schedules_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_SCHEDULES.path_suffix.startswith("/api")


def test_firewall_schedules_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.FIREWALL_SCHEDULES.path_suffix == "/firewall/schedules"


def test_system_restapi_version_is_declared_verified():
    assert Endpoints.SYSTEM_RESTAPI_VERSION.verified is True


def test_system_restapi_version_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_RESTAPI_VERSION.path_suffix.startswith("/api")


def test_system_restapi_version_path_suffix_is_the_singular_endpoint():
    assert Endpoints.SYSTEM_RESTAPI_VERSION.path_suffix == "/system/restapi/version"


def test_firewall_virtual_ips_is_declared_verified():
    assert Endpoints.FIREWALL_VIRTUAL_IPS.verified is True


def test_firewall_virtual_ips_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_VIRTUAL_IPS.path_suffix.startswith("/api")


def test_firewall_virtual_ips_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.FIREWALL_VIRTUAL_IPS.path_suffix == "/firewall/virtual_ips"


def test_system_certificate_authorities_is_declared_verified():
    assert Endpoints.SYSTEM_CERTIFICATE_AUTHORITIES.verified is True


def test_system_certificate_authorities_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_CERTIFICATE_AUTHORITIES.path_suffix.startswith("/api")


def test_system_certificate_authorities_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.SYSTEM_CERTIFICATE_AUTHORITIES.path_suffix == "/system/certificate_authorities"
