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


def test_bind_access_lists_is_declared_verified():
    assert Endpoints.BIND_ACCESS_LISTS.verified is True


def test_bind_access_lists_path_suffix_has_no_api_prefix():
    assert not Endpoints.BIND_ACCESS_LISTS.path_suffix.startswith("/api")


def test_bind_access_lists_path_suffix_is_correct():
    assert Endpoints.BIND_ACCESS_LISTS.path_suffix == "/services/bind/access_lists"


def test_bind_sync_settings_is_declared_verified():
    assert Endpoints.BIND_SYNC_SETTINGS.verified is True


def test_bind_sync_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.BIND_SYNC_SETTINGS.path_suffix.startswith("/api")


def test_bind_sync_settings_path_suffix_is_correct():
    assert Endpoints.BIND_SYNC_SETTINGS.path_suffix == "/services/bind/sync/settings"


def test_bind_views_is_declared_verified():
    assert Endpoints.BIND_VIEWS.verified is True


def test_bind_views_path_suffix_has_no_api_prefix():
    assert not Endpoints.BIND_VIEWS.path_suffix.startswith("/api")


def test_bind_views_path_suffix_is_correct():
    assert Endpoints.BIND_VIEWS.path_suffix == "/services/bind/views"


def test_bind_zones_is_declared_verified():
    assert Endpoints.BIND_ZONES.verified is True


def test_bind_zones_path_suffix_has_no_api_prefix():
    assert not Endpoints.BIND_ZONES.path_suffix.startswith("/api")


def test_bind_zones_path_suffix_is_correct():
    assert Endpoints.BIND_ZONES.path_suffix == "/services/bind/zones"


def test_bind_zone_record_is_declared_verified():
    """Live-ceremony evidence differs from the other 4 BIND endpoints:
    with no zone configured (BIND absent), this returned a well-formed
    HTTP 404 rather than 200 -- verified on reachability + correct-shape
    error, not on having observed a populated record."""
    assert Endpoints.BIND_ZONE_RECORD.verified is True


def test_bind_zone_record_path_suffix_has_no_api_prefix():
    assert not Endpoints.BIND_ZONE_RECORD.path_suffix.startswith("/api")


def test_bind_zone_record_path_suffix_is_correct():
    assert Endpoints.BIND_ZONE_RECORD.path_suffix == "/services/bind/zone/record"


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


def test_status_ipsec_sas_is_declared_verified():
    assert Endpoints.STATUS_IPSEC_SAS.verified is True


def test_status_ipsec_sas_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_IPSEC_SAS.path_suffix.startswith("/api")


def test_status_ipsec_sas_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_IPSEC_SAS.path_suffix == "/status/ipsec/sas"


def test_status_ipsec_child_sas_is_declared_verified():
    assert Endpoints.STATUS_IPSEC_CHILD_SAS.verified is True


def test_status_ipsec_child_sas_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_IPSEC_CHILD_SAS.path_suffix.startswith("/api")


def test_status_ipsec_child_sas_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_IPSEC_CHILD_SAS.path_suffix == "/status/ipsec/child_sas"


def test_status_wireguard_tunnels_is_declared_verified():
    assert Endpoints.STATUS_WIREGUARD_TUNNELS.verified is True


def test_status_wireguard_tunnels_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_WIREGUARD_TUNNELS.path_suffix.startswith("/api")


def test_status_wireguard_tunnels_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_WIREGUARD_TUNNELS.path_suffix == "/status/wireguard/tunnels"


def test_status_wireguard_peers_is_declared_verified():
    assert Endpoints.STATUS_WIREGUARD_PEERS.verified is True


def test_status_wireguard_peers_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_WIREGUARD_PEERS.path_suffix.startswith("/api")


def test_status_wireguard_peers_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_WIREGUARD_PEERS.path_suffix == "/status/wireguard/peers"


def test_status_openvpn_servers_is_declared_verified():
    assert Endpoints.STATUS_OPENVPN_SERVERS.verified is True


def test_status_openvpn_servers_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_OPENVPN_SERVERS.path_suffix.startswith("/api")


def test_status_openvpn_servers_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_OPENVPN_SERVERS.path_suffix == "/status/openvpn/servers"


def test_status_openvpn_clients_is_declared_verified():
    assert Endpoints.STATUS_OPENVPN_CLIENTS.verified is True


def test_status_openvpn_clients_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_OPENVPN_CLIENTS.path_suffix.startswith("/api")


def test_status_openvpn_clients_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_OPENVPN_CLIENTS.path_suffix == "/status/openvpn/clients"


def test_status_openvpn_server_connections_is_declared_verified():
    assert Endpoints.STATUS_OPENVPN_SERVER_CONNECTIONS.verified is True


def test_status_openvpn_server_connections_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_OPENVPN_SERVER_CONNECTIONS.path_suffix.startswith("/api")


def test_status_openvpn_server_connections_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_OPENVPN_SERVER_CONNECTIONS.path_suffix == "/status/openvpn/server/connections"


def test_status_openvpn_server_routes_is_declared_verified():
    assert Endpoints.STATUS_OPENVPN_SERVER_ROUTES.verified is True


def test_status_openvpn_server_routes_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_OPENVPN_SERVER_ROUTES.path_suffix.startswith("/api")


def test_status_openvpn_server_routes_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.STATUS_OPENVPN_SERVER_ROUTES.path_suffix == "/status/openvpn/server/routes"


def test_dns_forwarder_host_overrides_is_declared_verified():
    assert Endpoints.DNS_FORWARDER_HOST_OVERRIDES.verified is True


def test_dns_forwarder_host_overrides_path_suffix_has_no_api_prefix():
    assert not Endpoints.DNS_FORWARDER_HOST_OVERRIDES.path_suffix.startswith("/api")


def test_dns_forwarder_host_overrides_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.DNS_FORWARDER_HOST_OVERRIDES.path_suffix == "/services/dns_forwarder/host_overrides"


def test_dns_resolver_domain_overrides_is_declared_verified():
    assert Endpoints.DNS_RESOLVER_DOMAIN_OVERRIDES.verified is True


def test_dns_resolver_domain_overrides_path_suffix_has_no_api_prefix():
    assert not Endpoints.DNS_RESOLVER_DOMAIN_OVERRIDES.path_suffix.startswith("/api")


def test_dns_resolver_domain_overrides_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.DNS_RESOLVER_DOMAIN_OVERRIDES.path_suffix == "/services/dns_resolver/domain_overrides"


def test_dns_resolver_access_lists_is_declared_verified():
    assert Endpoints.DNS_RESOLVER_ACCESS_LISTS.verified is True


def test_dns_resolver_access_lists_path_suffix_has_no_api_prefix():
    assert not Endpoints.DNS_RESOLVER_ACCESS_LISTS.path_suffix.startswith("/api")


def test_dns_resolver_access_lists_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.DNS_RESOLVER_ACCESS_LISTS.path_suffix == "/services/dns_resolver/access_lists"


def test_interface_available_interfaces_is_declared_verified():
    assert Endpoints.INTERFACE_AVAILABLE_INTERFACES.verified is True


def test_interface_available_interfaces_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACE_AVAILABLE_INTERFACES.path_suffix.startswith("/api")


def test_interface_available_interfaces_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.INTERFACE_AVAILABLE_INTERFACES.path_suffix == "/interface/available_interfaces"


def test_interface_gres_is_declared_verified():
    assert Endpoints.INTERFACE_GRES.verified is True


def test_interface_gres_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACE_GRES.path_suffix.startswith("/api")


def test_interface_gres_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.INTERFACE_GRES.path_suffix == "/interface/gres"


def test_interface_laggs_is_declared_verified():
    assert Endpoints.INTERFACE_LAGGS.verified is True


def test_interface_laggs_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACE_LAGGS.path_suffix.startswith("/api")


def test_interface_laggs_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.INTERFACE_LAGGS.path_suffix == "/interface/laggs"


def test_routing_gateway_groups_is_declared_verified():
    assert Endpoints.ROUTING_GATEWAY_GROUPS.verified is True


def test_routing_gateway_groups_path_suffix_has_no_api_prefix():
    assert not Endpoints.ROUTING_GATEWAY_GROUPS.path_suffix.startswith("/api")


def test_routing_gateway_groups_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.ROUTING_GATEWAY_GROUPS.path_suffix == "/routing/gateway/groups"


def test_routing_gateway_default_is_declared_verified():
    assert Endpoints.ROUTING_GATEWAY_DEFAULT.verified is True


def test_routing_gateway_default_path_suffix_has_no_api_prefix():
    assert not Endpoints.ROUTING_GATEWAY_DEFAULT.path_suffix.startswith("/api")


def test_routing_gateway_default_path_suffix_is_correct():
    assert Endpoints.ROUTING_GATEWAY_DEFAULT.path_suffix == "/routing/gateway/default"


def test_dhcp_relay_is_declared_verified():
    assert Endpoints.DHCP_RELAY.verified is True


def test_dhcp_relay_path_suffix_has_no_api_prefix():
    assert not Endpoints.DHCP_RELAY.path_suffix.startswith("/api")


def test_dhcp_relay_path_suffix_is_correct():
    assert Endpoints.DHCP_RELAY.path_suffix == "/services/dhcp_relay"


def test_dhcp_server_address_pools_is_declared_verified():
    assert Endpoints.DHCP_SERVER_ADDRESS_POOLS.verified is True


def test_dhcp_server_address_pools_path_suffix_has_no_api_prefix():
    assert not Endpoints.DHCP_SERVER_ADDRESS_POOLS.path_suffix.startswith("/api")


def test_dhcp_server_address_pools_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.DHCP_SERVER_ADDRESS_POOLS.path_suffix == "/services/dhcp_server/address_pools"


def test_dhcp_server_custom_options_is_declared_verified():
    assert Endpoints.DHCP_SERVER_CUSTOM_OPTIONS.verified is True


def test_dhcp_server_custom_options_path_suffix_has_no_api_prefix():
    assert not Endpoints.DHCP_SERVER_CUSTOM_OPTIONS.path_suffix.startswith("/api")


def test_dhcp_server_custom_options_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.DHCP_SERVER_CUSTOM_OPTIONS.path_suffix == "/services/dhcp_server/custom_options"


def test_system_hostname_is_declared_verified():
    assert Endpoints.SYSTEM_HOSTNAME.verified is True


def test_system_hostname_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_HOSTNAME.path_suffix.startswith("/api")


def test_system_hostname_path_suffix_is_correct():
    assert Endpoints.SYSTEM_HOSTNAME.path_suffix == "/system/hostname"


def test_system_timezone_is_declared_verified():
    assert Endpoints.SYSTEM_TIMEZONE.verified is True


def test_system_timezone_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_TIMEZONE.path_suffix.startswith("/api")


def test_system_timezone_path_suffix_is_correct():
    assert Endpoints.SYSTEM_TIMEZONE.path_suffix == "/system/timezone"


def test_system_dns_is_declared_verified():
    assert Endpoints.SYSTEM_DNS.verified is True


def test_system_dns_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_DNS.path_suffix.startswith("/api")


def test_system_dns_path_suffix_is_correct():
    assert Endpoints.SYSTEM_DNS.path_suffix == "/system/dns"


def test_system_console_is_declared_verified():
    assert Endpoints.SYSTEM_CONSOLE.verified is True


def test_system_console_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_CONSOLE.path_suffix.startswith("/api")


def test_system_console_path_suffix_is_correct():
    assert Endpoints.SYSTEM_CONSOLE.path_suffix == "/system/console"


def test_system_webgui_settings_is_declared_verified():
    assert Endpoints.SYSTEM_WEBGUI_SETTINGS.verified is True


def test_system_webgui_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_WEBGUI_SETTINGS.path_suffix.startswith("/api")


def test_system_webgui_settings_path_suffix_is_correct():
    assert Endpoints.SYSTEM_WEBGUI_SETTINGS.path_suffix == "/system/webgui/settings"


def test_system_restapi_access_list_is_declared_verified():
    assert Endpoints.SYSTEM_RESTAPI_ACCESS_LIST.verified is True


def test_system_restapi_access_list_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_RESTAPI_ACCESS_LIST.path_suffix.startswith("/api")


def test_system_restapi_access_list_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.SYSTEM_RESTAPI_ACCESS_LIST.path_suffix == "/system/restapi/access_list"


def test_system_crls_is_declared_verified():
    assert Endpoints.SYSTEM_CRLS.verified is True


def test_system_crls_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_CRLS.path_suffix.startswith("/api")


def test_system_crls_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.SYSTEM_CRLS.path_suffix == "/system/crls"


def test_system_package_available_is_declared_verified():
    assert Endpoints.SYSTEM_PACKAGE_AVAILABLE.verified is True


def test_system_package_available_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_PACKAGE_AVAILABLE.path_suffix.startswith("/api")


def test_system_package_available_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.SYSTEM_PACKAGE_AVAILABLE.path_suffix == "/system/package/available"


def test_firewall_traffic_shapers_is_declared_verified():
    assert Endpoints.FIREWALL_TRAFFIC_SHAPERS.verified is True


def test_firewall_traffic_shapers_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_TRAFFIC_SHAPERS.path_suffix.startswith("/api")


def test_firewall_traffic_shapers_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.FIREWALL_TRAFFIC_SHAPERS.path_suffix == "/firewall/traffic_shapers"


def test_services_freeradius_interfaces_is_not_yet_declared_verified():
    assert Endpoints.SERVICES_FREERADIUS_INTERFACES.verified is False


def test_services_freeradius_interfaces_path_suffix_has_no_api_prefix():
    assert not Endpoints.SERVICES_FREERADIUS_INTERFACES.path_suffix.startswith("/api")


def test_services_freeradius_interfaces_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.SERVICES_FREERADIUS_INTERFACES.path_suffix == "/services/freeradius/interfaces"


def test_services_freeradius_macs_is_not_yet_declared_verified():
    assert Endpoints.SERVICES_FREERADIUS_MACS.verified is False


def test_services_freeradius_macs_path_suffix_has_no_api_prefix():
    assert not Endpoints.SERVICES_FREERADIUS_MACS.path_suffix.startswith("/api")


def test_services_freeradius_macs_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.SERVICES_FREERADIUS_MACS.path_suffix == "/services/freeradius/macs"


def test_services_service_watchdogs_is_declared_verified():
    assert Endpoints.SERVICES_SERVICE_WATCHDOGS.verified is True


def test_services_service_watchdogs_path_suffix_has_no_api_prefix():
    assert not Endpoints.SERVICES_SERVICE_WATCHDOGS.path_suffix.startswith("/api")


def test_services_service_watchdogs_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.SERVICES_SERVICE_WATCHDOGS.path_suffix == "/services/service_watchdogs"


def test_vpn_ipsec_phase2s_is_declared_verified():
    assert Endpoints.VPN_IPSEC_PHASE2S.verified is True


def test_vpn_ipsec_phase2s_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_IPSEC_PHASE2S.path_suffix.startswith("/api")


def test_vpn_ipsec_phase2s_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_IPSEC_PHASE2S.path_suffix == "/vpn/ipsec/phase2s"


def test_vpn_ipsec_phase1_encryptions_is_declared_verified():
    assert Endpoints.VPN_IPSEC_PHASE1_ENCRYPTIONS.verified is True


def test_vpn_ipsec_phase1_encryptions_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_IPSEC_PHASE1_ENCRYPTIONS.path_suffix.startswith("/api")


def test_vpn_ipsec_phase1_encryptions_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_IPSEC_PHASE1_ENCRYPTIONS.path_suffix == "/vpn/ipsec/phase1/encryptions"


def test_vpn_ipsec_phase1s_is_declared_verified():
    assert Endpoints.VPN_IPSEC_PHASE1S.verified is True


def test_vpn_ipsec_phase1s_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_IPSEC_PHASE1S.path_suffix.startswith("/api")


def test_vpn_ipsec_phase1s_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_IPSEC_PHASE1S.path_suffix == "/vpn/ipsec/phase1s"


def test_vpn_ipsec_phase2_encryptions_is_declared_verified():
    assert Endpoints.VPN_IPSEC_PHASE2_ENCRYPTIONS.verified is True


def test_vpn_ipsec_phase2_encryptions_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_IPSEC_PHASE2_ENCRYPTIONS.path_suffix.startswith("/api")


def test_vpn_ipsec_phase2_encryptions_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_IPSEC_PHASE2_ENCRYPTIONS.path_suffix == "/vpn/ipsec/phase2/encryptions"


def test_vpn_openvpn_servers_is_declared_verified():
    assert Endpoints.VPN_OPENVPN_SERVERS.verified is True


def test_vpn_openvpn_servers_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_OPENVPN_SERVERS.path_suffix.startswith("/api")


def test_vpn_openvpn_servers_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_OPENVPN_SERVERS.path_suffix == "/vpn/openvpn/servers"


def test_vpn_openvpn_csos_is_declared_verified():
    assert Endpoints.VPN_OPENVPN_CSOS.verified is True


def test_vpn_openvpn_csos_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_OPENVPN_CSOS.path_suffix.startswith("/api")


def test_vpn_openvpn_csos_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_OPENVPN_CSOS.path_suffix == "/vpn/openvpn/csos"


def test_vpn_openvpn_clients_is_declared_verified():
    assert Endpoints.VPN_OPENVPN_CLIENTS.verified is True


def test_vpn_openvpn_clients_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_OPENVPN_CLIENTS.path_suffix.startswith("/api")


def test_vpn_openvpn_clients_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_OPENVPN_CLIENTS.path_suffix == "/vpn/openvpn/clients"


def test_status_logs_settings_is_verified():
    """v0.6.0 Phase B completion: LAB-verified FIELD_MODEL_LIVE_VERIFIED
    2026-08-22 after the read-only LAB service account was synced to
    the current required privilege set -- 200, exact 34-key match."""
    assert Endpoints.STATUS_LOGS_SETTINGS.verified is True


def test_status_logs_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.STATUS_LOGS_SETTINGS.path_suffix.startswith("/api")


def test_status_logs_settings_path_suffix_is_the_singular_settings_endpoint():
    assert Endpoints.STATUS_LOGS_SETTINGS.path_suffix == "/status/logs/settings"


def test_firewall_virtual_ip_apply_is_verified():
    assert Endpoints.FIREWALL_VIRTUAL_IP_APPLY.verified is True


def test_firewall_virtual_ip_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.FIREWALL_VIRTUAL_IP_APPLY.path_suffix.startswith("/api")


def test_firewall_virtual_ip_apply_path_suffix_is_correct():
    assert Endpoints.FIREWALL_VIRTUAL_IP_APPLY.path_suffix == "/firewall/virtual_ip/apply"


def test_interface_apply_is_verified():
    assert Endpoints.INTERFACE_APPLY.verified is True


def test_interface_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.INTERFACE_APPLY.path_suffix.startswith("/api")


def test_interface_apply_path_suffix_is_correct():
    assert Endpoints.INTERFACE_APPLY.path_suffix == "/interface/apply"


def test_routing_apply_is_verified():
    assert Endpoints.ROUTING_APPLY.verified is True


def test_routing_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.ROUTING_APPLY.path_suffix.startswith("/api")


def test_routing_apply_path_suffix_is_correct():
    assert Endpoints.ROUTING_APPLY.path_suffix == "/routing/apply"


def test_dhcp_server_apply_is_verified():
    assert Endpoints.DHCP_SERVER_APPLY.verified is True


def test_dhcp_server_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.DHCP_SERVER_APPLY.path_suffix.startswith("/api")


def test_dhcp_server_apply_path_suffix_is_correct():
    assert Endpoints.DHCP_SERVER_APPLY.path_suffix == "/services/dhcp_server/apply"


def test_dns_forwarder_apply_is_verified():
    assert Endpoints.DNS_FORWARDER_APPLY.verified is True


def test_dns_forwarder_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.DNS_FORWARDER_APPLY.path_suffix.startswith("/api")


def test_dns_forwarder_apply_path_suffix_is_correct():
    assert Endpoints.DNS_FORWARDER_APPLY.path_suffix == "/services/dns_forwarder/apply"


def test_dns_resolver_apply_is_verified():
    assert Endpoints.DNS_RESOLVER_APPLY.verified is True


def test_dns_resolver_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.DNS_RESOLVER_APPLY.path_suffix.startswith("/api")


def test_dns_resolver_apply_path_suffix_is_correct():
    assert Endpoints.DNS_RESOLVER_APPLY.path_suffix == "/services/dns_resolver/apply"


def test_vpn_ipsec_apply_is_verified():
    assert Endpoints.VPN_IPSEC_APPLY.verified is True


def test_vpn_ipsec_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_IPSEC_APPLY.path_suffix.startswith("/api")


def test_vpn_ipsec_apply_path_suffix_is_correct():
    assert Endpoints.VPN_IPSEC_APPLY.path_suffix == "/vpn/ipsec/apply"


def test_vpn_wireguard_apply_is_verified():
    assert Endpoints.VPN_WIREGUARD_APPLY.verified is True


def test_vpn_wireguard_apply_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_WIREGUARD_APPLY.path_suffix.startswith("/api")


def test_vpn_wireguard_apply_path_suffix_is_correct():
    assert Endpoints.VPN_WIREGUARD_APPLY.path_suffix == "/vpn/wireguard/apply"


def test_vpn_wireguard_tunnels_is_declared_verified():
    assert Endpoints.VPN_WIREGUARD_TUNNELS.verified is True


def test_vpn_wireguard_tunnels_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_WIREGUARD_TUNNELS.path_suffix.startswith("/api")


def test_vpn_wireguard_tunnels_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_WIREGUARD_TUNNELS.path_suffix == "/vpn/wireguard/tunnels"


def test_vpn_wireguard_peers_is_declared_verified():
    assert Endpoints.VPN_WIREGUARD_PEERS.verified is True


def test_vpn_wireguard_peers_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_WIREGUARD_PEERS.path_suffix.startswith("/api")


def test_vpn_wireguard_peers_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_WIREGUARD_PEERS.path_suffix == "/vpn/wireguard/peers"


def test_vpn_wireguard_tunnel_addresses_is_verified():
    """v0.6.0 Phase B completion: LAB-verified ENDPOINT_VERIFIED
    2026-08-22 -- 200, {"data": []}, no WireGuard tunnel addresses
    configured on this LAB."""
    assert Endpoints.VPN_WIREGUARD_TUNNEL_ADDRESSES.verified is True


def test_vpn_wireguard_tunnel_addresses_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_WIREGUARD_TUNNEL_ADDRESSES.path_suffix.startswith("/api")


def test_vpn_wireguard_tunnel_addresses_path_suffix_is_the_plural_list_endpoint():
    assert Endpoints.VPN_WIREGUARD_TUNNEL_ADDRESSES.path_suffix == "/vpn/wireguard/tunnel/addresses"


def test_vpn_wireguard_settings_is_declared_verified():
    assert Endpoints.VPN_WIREGUARD_SETTINGS.verified is True


def test_vpn_wireguard_settings_path_suffix_has_no_api_prefix():
    assert not Endpoints.VPN_WIREGUARD_SETTINGS.path_suffix.startswith("/api")


def test_vpn_wireguard_settings_path_suffix_is_correct():
    assert Endpoints.VPN_WIREGUARD_SETTINGS.path_suffix == "/vpn/wireguard/settings"


def test_system_schema_openapi_is_verified():
    """pfREST_LIVE_GUIDANCE_ARC (2026-08-28): LAB-verified via an
    authenticated GET against https://pfsense-test.lab.invalid -- 200,
    raw unwrapped OpenAPI document (no pfSense {"data": ...} envelope,
    unlike every other endpoint), openapi=3.0.0, 267 paths, 186 schemas.
    Internal-only -- never a direct client.<method>() call inside any
    tools/read/*.py file; consumed exclusively by
    pfsense_mcp.pfrest_docs.appliance_schema."""
    assert Endpoints.SYSTEM_SCHEMA_OPENAPI.verified is True


def test_system_schema_openapi_path_suffix_has_no_api_prefix():
    assert not Endpoints.SYSTEM_SCHEMA_OPENAPI.path_suffix.startswith("/api")


def test_system_schema_openapi_path_suffix_is_correct():
    assert Endpoints.SYSTEM_SCHEMA_OPENAPI.path_suffix == "/schema/openapi"
