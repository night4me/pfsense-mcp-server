"""ToolRegistry — the only place mcp.tool() is called. Registration
is gated by which capabilities are active for this server instance."""

from __future__ import annotations

from ..capabilities import Capability
from ..pfsense_client import PfSenseClient
from .audit import audit_logged
from .read import (
    arp_table,
    bind_settings,
    carp_status,
    dhcp_leases,
    dhcp_servers,
    dhcp_static_mappings,
    dns_resolver_host_overrides,
    dns_resolver_settings,
    email_notification_settings,
    firewall_advanced_settings,
    firewall_aliases,
    firewall_apply_status,
    firewall_nat_outbound_mode,
    firewall_nat_port_forwards,
    firewall_rules,
    firewall_states,
    firewall_states_size,
    firewall_traffic_shaper_limiters,
    gateway_status,
    gateways,
    interface_bridges,
    interface_configs,
    interfaces,
    service_status,
    system_certificates,
    system_hasync,
    system_packages,
    system_restapi_settings,
    system_status,
    system_tunables,
    system_version,
    user_groups,
    users,
)


class ToolRegistry:
    def __init__(self, mcp, client: PfSenseClient, identity: str, capabilities: frozenset[Capability]) -> None:
        self._mcp = mcp
        self._client = client
        self._identity = identity
        self._capabilities = capabilities

    def register_all(self) -> None:
        if Capability.SYSTEM_READ in self._capabilities:
            self._register_system_read()
        if Capability.INTERFACE_READ in self._capabilities:
            self._register_interface_read()
        if Capability.GATEWAY_READ in self._capabilities:
            self._register_gateway_read()
        if Capability.FIREWALL_READ in self._capabilities:
            self._register_firewall_read()
        if Capability.ALIAS_READ in self._capabilities:
            self._register_alias_read()
        if Capability.SERVICE_READ in self._capabilities:
            self._register_service_read()
        if Capability.SYSTEM_INFO_READ in self._capabilities:
            self._register_system_info_read()
        if Capability.INTERFACE_CONFIG_READ in self._capabilities:
            self._register_interface_config_read()
        if Capability.FIREWALL_NAT_READ in self._capabilities:
            self._register_firewall_nat_read()
        if Capability.USER_READ in self._capabilities:
            self._register_user_read()
        if Capability.SYSTEM_CERTIFICATE_READ in self._capabilities:
            self._register_system_certificate_read()
        if Capability.USER_GROUP_READ in self._capabilities:
            self._register_user_group_read()
        if Capability.DHCP_LEASE_READ in self._capabilities:
            self._register_dhcp_lease_read()
        if Capability.DHCP_STATIC_MAPPING_READ in self._capabilities:
            self._register_dhcp_static_mapping_read()
        if Capability.DHCP_SERVER_READ in self._capabilities:
            self._register_dhcp_server_read()
        if Capability.INTERFACE_VIRTUAL_READ in self._capabilities:
            self._register_interface_virtual_read()
        if Capability.STATUS_CARP_READ in self._capabilities:
            self._register_status_carp_read()
        if Capability.SYSTEM_RESTAPI_SETTINGS_READ in self._capabilities:
            self._register_system_restapi_settings_read()
        if Capability.SYSTEM_HA_SYNC_READ in self._capabilities:
            self._register_system_ha_sync_read()
        if Capability.SERVICES_DNS_RESOLVER_READ in self._capabilities:
            self._register_services_dns_resolver_read()
        if Capability.DIAGNOSTICS_ARP_READ in self._capabilities:
            self._register_diagnostics_arp_read()
        if Capability.FIREWALL_TRAFFIC_SHAPER_READ in self._capabilities:
            self._register_firewall_traffic_shaper_read()
        if Capability.FIREWALL_ADVANCED_SETTINGS_READ in self._capabilities:
            self._register_firewall_advanced_settings_read()
        if Capability.SYSTEM_PACKAGE_READ in self._capabilities:
            self._register_system_package_read()
        if Capability.SYSTEM_TUNABLE_READ in self._capabilities:
            self._register_system_tunable_read()
        if Capability.SYSTEM_NOTIFICATIONS_READ in self._capabilities:
            self._register_system_notifications_read()
        if Capability.SERVICES_BIND_READ in self._capabilities:
            self._register_services_bind_read()

    def _register_system_read(self) -> None:
        fn = system_status.build(self._client)
        wrapped = audit_logged("pfsense_get_system_status", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_interface_read(self) -> None:
        fn = interfaces.build(self._client)
        wrapped = audit_logged("pfsense_get_interfaces", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_gateway_read(self) -> None:
        gateways_fn = gateways.build(self._client)
        wrapped_gateways = audit_logged("pfsense_get_gateways", self._identity)(gateways_fn)
        self._mcp.tool()(wrapped_gateways)

        status_fn = gateway_status.build(self._client)
        wrapped_status = audit_logged("pfsense_get_gateway_status", self._identity)(status_fn)
        self._mcp.tool()(wrapped_status)

    def _register_firewall_read(self) -> None:
        rules_fn = firewall_rules.build(self._client)
        wrapped_rules = audit_logged("pfsense_get_firewall_rules", self._identity)(rules_fn)
        self._mcp.tool()(wrapped_rules)

        states_fn = firewall_states.build(self._client)
        wrapped_states = audit_logged("pfsense_get_firewall_states", self._identity)(states_fn)
        self._mcp.tool()(wrapped_states)

        states_size_fn = firewall_states_size.build(self._client)
        wrapped_states_size = audit_logged("pfsense_get_firewall_states_size", self._identity)(states_size_fn)
        self._mcp.tool()(wrapped_states_size)

        apply_status_fn = firewall_apply_status.build(self._client)
        wrapped_apply_status = audit_logged("pfsense_get_firewall_apply_status", self._identity)(apply_status_fn)
        self._mcp.tool()(wrapped_apply_status)

    def _register_alias_read(self) -> None:
        fn = firewall_aliases.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_aliases", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_service_read(self) -> None:
        fn = service_status.build(self._client)
        wrapped = audit_logged("pfsense_get_service_status", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_system_info_read(self) -> None:
        fn = system_version.build(self._client)
        wrapped = audit_logged("pfsense_get_system_version", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_interface_config_read(self) -> None:
        fn = interface_configs.build(self._client)
        wrapped = audit_logged("pfsense_get_interface_configs", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_firewall_nat_read(self) -> None:
        fn = firewall_nat_port_forwards.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_nat_port_forwards", self._identity)(fn)
        self._mcp.tool()(wrapped)

        firewall_nat_outbound_mode_fn = firewall_nat_outbound_mode.build(self._client)
        firewall_nat_outbound_mode_wrapped = audit_logged("pfsense_get_firewall_nat_outbound_mode", self._identity)(
            firewall_nat_outbound_mode_fn
        )
        self._mcp.tool()(firewall_nat_outbound_mode_wrapped)

    def _register_user_read(self) -> None:
        fn = users.build(self._client)
        wrapped = audit_logged("pfsense_get_users", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_system_certificate_read(self) -> None:
        fn = system_certificates.build(self._client)
        wrapped = audit_logged("pfsense_get_system_certificates", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_user_group_read(self) -> None:
        fn = user_groups.build(self._client)
        wrapped = audit_logged("pfsense_get_user_groups", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_dhcp_lease_read(self) -> None:
        fn = dhcp_leases.build(self._client)
        wrapped = audit_logged("pfsense_get_dhcp_leases", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_dhcp_static_mapping_read(self) -> None:
        fn = dhcp_static_mappings.build(self._client)
        wrapped = audit_logged("pfsense_get_dhcp_static_mappings", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_dhcp_server_read(self) -> None:
        fn = dhcp_servers.build(self._client)
        wrapped = audit_logged("pfsense_get_dhcp_servers", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_interface_virtual_read(self) -> None:
        fn = interface_bridges.build(self._client)
        wrapped = audit_logged("pfsense_get_interface_bridges", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_status_carp_read(self) -> None:
        fn = carp_status.build(self._client)
        wrapped = audit_logged("pfsense_get_carp_status", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_system_restapi_settings_read(self) -> None:
        fn = system_restapi_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_system_restapi_settings", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_system_ha_sync_read(self) -> None:
        fn = system_hasync.build(self._client)
        wrapped = audit_logged("pfsense_get_system_hasync", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_services_dns_resolver_read(self) -> None:
        fn = dns_resolver_host_overrides.build(self._client)
        wrapped = audit_logged("pfsense_get_dns_resolver_host_overrides", self._identity)(fn)
        self._mcp.tool()(wrapped)

        dns_resolver_settings_fn = dns_resolver_settings.build(self._client)
        dns_resolver_settings_wrapped = audit_logged("pfsense_get_dns_resolver_settings", self._identity)(
            dns_resolver_settings_fn
        )
        self._mcp.tool()(dns_resolver_settings_wrapped)

    def _register_diagnostics_arp_read(self) -> None:
        fn = arp_table.build(self._client)
        wrapped = audit_logged("pfsense_get_arp_table", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_firewall_traffic_shaper_read(self) -> None:
        fn = firewall_traffic_shaper_limiters.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_traffic_shaper_limiters", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_firewall_advanced_settings_read(self) -> None:
        fn = firewall_advanced_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_advanced_settings", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_system_package_read(self) -> None:
        fn = system_packages.build(self._client)
        wrapped = audit_logged("pfsense_get_system_packages", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_system_tunable_read(self) -> None:
        fn = system_tunables.build(self._client)
        wrapped = audit_logged("pfsense_get_system_tunables", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_system_notifications_read(self) -> None:
        fn = email_notification_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_email_notification_settings", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_services_bind_read(self) -> None:
        fn = bind_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_bind_settings", self._identity)(fn)
        self._mcp.tool()(wrapped)
