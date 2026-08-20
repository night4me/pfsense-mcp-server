"""ToolRegistry — the only place mcp.tool() is called. Registration
is gated by which capabilities are active for this server instance."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
from dataclasses import dataclass
from typing import Callable

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .. import tier1_write_bridge
from ..capabilities import Capability
from ..errors import ConfigurationError
from ..models.server_introspection import ServerIntrospection
from ..pfsense_client import PfSenseClient
from ..write_endpoints import WriteEndpointInfo, WriteEndpoints
from .audit import audit_logged
from .read import (
    acme_settings,
    arp_table,
    auth_keys,
    bind_settings,
    carp_status,
    cron_jobs,
    dhcp_leases,
    dhcp_servers,
    dhcp_static_mappings,
    diagnostics_tables,
    dns_resolver_host_overrides,
    dns_resolver_settings,
    email_notification_settings,
    firewall_advanced_settings,
    firewall_aliases,
    firewall_apply_status,
    firewall_nat_one_to_one_mappings,
    firewall_nat_outbound_mappings,
    firewall_nat_outbound_mode,
    firewall_nat_port_forwards,
    firewall_rules,
    firewall_schedules,
    firewall_states,
    firewall_states_size,
    firewall_traffic_shaper_limiters,
    firewall_virtual_ips,
    freeradius_eap,
    gateway_status,
    gateways,
    interface_bridges,
    interface_configs,
    interface_groups,
    interface_vlans,
    interfaces,
    mcp_info,
    ntp_settings,
    ntp_time_servers,
    routing_static_routes,
    service_status,
    ssh_settings,
    system_certificate_authorities,
    system_certificates,
    system_hasync,
    system_packages,
    system_restapi_settings,
    system_restapi_version,
    system_status,
    system_tunables,
    system_version,
    user_groups,
    users,
)
from .write import set_firewall_alias_description


@dataclass(frozen=True)
class ReadToolAnnotationPolicy:
    read_only_hint: bool = True
    open_world_hint: bool = True

    def to_mcp(self) -> ToolAnnotations:
        return ToolAnnotations(readOnlyHint=self.read_only_hint, openWorldHint=self.open_world_hint)


READ_TOOL_ANNOTATION_POLICY = ReadToolAnnotationPolicy()

# pfsense_mcp_info is the only READ tool that never contacts pfSense —
# every field it returns is already-resolved local process state.
LOCAL_ONLY_ANNOTATION_POLICY = ReadToolAnnotationPolicy(open_world_hint=False)

KNOWN_READ_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "pfsense_get_acme_settings",
        "pfsense_get_arp_table",
        "pfsense_get_auth_keys",
        "pfsense_get_bind_settings",
        "pfsense_get_carp_status",
        "pfsense_get_cron_jobs",
        "pfsense_get_dhcp_leases",
        "pfsense_get_dhcp_servers",
        "pfsense_get_dhcp_static_mappings",
        "pfsense_get_diagnostics_tables",
        "pfsense_get_dns_resolver_host_overrides",
        "pfsense_get_dns_resolver_settings",
        "pfsense_get_email_notification_settings",
        "pfsense_get_firewall_advanced_settings",
        "pfsense_get_firewall_aliases",
        "pfsense_get_firewall_apply_status",
        "pfsense_get_firewall_nat_one_to_one_mappings",
        "pfsense_get_firewall_nat_outbound_mappings",
        "pfsense_get_firewall_nat_outbound_mode",
        "pfsense_get_firewall_nat_port_forwards",
        "pfsense_get_firewall_rules",
        "pfsense_get_firewall_schedules",
        "pfsense_get_firewall_states",
        "pfsense_get_firewall_states_size",
        "pfsense_get_firewall_traffic_shaper_limiters",
        "pfsense_get_firewall_virtual_ips",
        "pfsense_get_freeradius_eap",
        "pfsense_get_gateway_status",
        "pfsense_get_gateways",
        "pfsense_get_interface_bridges",
        "pfsense_get_interface_configs",
        "pfsense_get_interface_groups",
        "pfsense_get_interface_vlans",
        "pfsense_get_interfaces",
        "pfsense_get_ntp_settings",
        "pfsense_get_ntp_time_servers",
        "pfsense_get_routing_static_routes",
        "pfsense_get_service_status",
        "pfsense_get_ssh_settings",
        "pfsense_get_system_certificate_authorities",
        "pfsense_get_system_certificates",
        "pfsense_get_system_hasync",
        "pfsense_get_system_packages",
        "pfsense_get_system_restapi_settings",
        "pfsense_get_system_restapi_version",
        "pfsense_get_system_status",
        "pfsense_get_system_tunables",
        "pfsense_get_system_version",
        "pfsense_get_user_groups",
        "pfsense_get_users",
        "pfsense_mcp_info",
    }
)

#: W3 Slice 4's single accepted first-WRITE MCP tool. `destructiveHint`
#: is False and `idempotentHint` is True to match this operation's own
#: accepted properties (ADR-026: description-only, reversible via the
#: existing snapshot/restore mechanism; repeat calls with the same
#: alias_name/description are recognized as the same request via the
#: underlying runtime's own idempotency-key dedup, not a fresh mutation
#: each time).
WRITE_TOOL_ANNOTATION_POLICY = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

KNOWN_WRITE_TOOL_NAMES: frozenset[str] = frozenset({"set_firewall_alias_description_v1"})


class ToolRegistry:
    def __init__(
        self,
        mcp: FastMCP,
        client: PfSenseClient,
        identity: str,
        capabilities: frozenset[Capability],
        *,
        allowed_tools: frozenset[str] | None = None,
        profile_name: str = "unknown",
    ) -> None:
        unknown_tools = (
            allowed_tools - (KNOWN_READ_TOOL_NAMES | KNOWN_WRITE_TOOL_NAMES)
            if allowed_tools is not None
            else frozenset()
        )
        if unknown_tools:
            names = ", ".join(sorted(unknown_tools))
            raise ConfigurationError(f"PFSENSE_ALLOWED_TOOLS contains unknown tool name(s): {names}")
        self._mcp = mcp
        self._client = client
        self._identity = identity
        self._capabilities = capabilities
        self._allowed_tools = allowed_tools
        self._profile_name = profile_name
        # Populated by _register_read_tool()/a future write-registration
        # equivalent only when a tool is actually registered (i.e. not
        # filtered out by allowed_tools) — the source pfsense_mcp_info
        # reads for its own registered-tool-count fields, so those counts
        # can never drift from what was actually registered on self._mcp.
        self._registered_read_names: list[str] = []
        self._registered_write_names: list[str] = []

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
        if Capability.SERVICES_NTP_READ in self._capabilities:
            self._register_services_ntp_read()
        if Capability.SERVICES_SSH_READ in self._capabilities:
            self._register_services_ssh_read()
        if Capability.SERVICES_CRON_READ in self._capabilities:
            self._register_services_cron_read()
        if Capability.SERVICES_ACME_READ in self._capabilities:
            self._register_services_acme_read()
        if Capability.SERVICES_FREERADIUS_READ in self._capabilities:
            self._register_services_freeradius_read()
        if Capability.DIAGNOSTICS_TABLES_READ in self._capabilities:
            self._register_diagnostics_tables_read()
        if Capability.AUTH_KEYS_READ in self._capabilities:
            self._register_auth_keys_read()
        if Capability.SERVER_INFO_READ in self._capabilities:
            self._register_server_info_read()
        if Capability.INTERFACE_VLAN_READ in self._capabilities:
            self._register_interface_vlan_read()
        if Capability.ROUTING_STATIC_ROUTE_READ in self._capabilities:
            self._register_routing_static_route_read()
        if Capability.INTERFACE_GROUP_READ in self._capabilities:
            self._register_interface_group_read()
        if Capability.FIREWALL_SCHEDULE_READ in self._capabilities:
            self._register_firewall_schedule_read()
        if Capability.SYSTEM_RESTAPI_VERSION_READ in self._capabilities:
            self._register_system_restapi_version_read()
        if Capability.FIREWALL_VIRTUAL_IP_READ in self._capabilities:
            self._register_firewall_virtual_ip_read()
        if Capability.SYSTEM_CERTIFICATE_AUTHORITY_READ in self._capabilities:
            self._register_system_certificate_authority_read()

        self.register_all_write()

    def register_all_write(self) -> None:
        """Write-capability registration dispatch point. W3 Slice 4 adds
        the single accepted first-WRITE branch below; no other
        `Capability.X_WRITE` is ever present in `self._capabilities` for
        any selectable profile (independently enforced by
        `scripts/write_capability_check.py`), so no other branch is ever
        reachable. Any additional write capability would add its own
        `if Capability.X_WRITE in self._capabilities: self._register_x_write()`
        branch here, mirroring `register_all()`'s existing per-capability
        dispatch pattern above -- under its own separately authorized
        tier; the durable owner roadmap ceiling forbids adding one
        without a new, separate, explicit owner decision."""

        if Capability.ALIAS_WRITE in self._capabilities:
            self._register_alias_write()

    def _register_alias_write(self) -> None:
        """The ADR-028 three-condition activation gate, all three
        independently required: (A) `Capability.ALIAS_WRITE` in the
        active profile's capability set -- already proven true by the
        sole caller, `register_all_write()`'s `if` guard above; (B) the
        exact alias-description endpoint is present in `WriteEndpoints`;
        (C) the complete, fail-closed production runtime successfully
        constructs. Any single condition failing means the tool is
        simply absent -- never degraded, never partially available."""

        endpoint = getattr(WriteEndpoints, "FIREWALL_ALIAS_DESCRIPTION", None)
        if not isinstance(endpoint, WriteEndpointInfo):
            return
        if not tier1_write_bridge.can_construct_write_runtime():
            return

        fn = set_firewall_alias_description.build()
        wrapped = audit_logged("set_firewall_alias_description_v1", self._identity)(fn)
        self._register_write_tool(wrapped)

    def _register_write_tool(self, wrapped: Callable[..., object]) -> None:
        """Mirrors `_register_read_tool()` exactly: `PFSENSE_ALLOWED_TOOLS`
        may only narrow an already-gate-satisfied registration, never
        grant one -- this method is reached only after
        `_register_alias_write()`'s own three-condition gate has already
        held; `allowed_tools` can suppress the tool from here, but cannot
        cause it to appear when the gate above did not hold, since this
        method is never called at all in that case."""

        if self._allowed_tools is not None and wrapped.__name__ not in self._allowed_tools:
            return
        self._mcp.tool(annotations=WRITE_TOOL_ANNOTATION_POLICY)(wrapped)
        self._registered_write_names.append(wrapped.__name__)

    def _register_read_tool(
        self,
        wrapped: Callable[..., object],
        *,
        annotation_policy: ReadToolAnnotationPolicy = READ_TOOL_ANNOTATION_POLICY,
    ) -> None:
        if self._allowed_tools is not None and wrapped.__name__ not in self._allowed_tools:
            return
        self._mcp.tool(annotations=annotation_policy.to_mcp())(wrapped)
        self._registered_read_names.append(wrapped.__name__)

    def _register_system_read(self) -> None:
        fn = system_status.build(self._client)
        wrapped = audit_logged("pfsense_get_system_status", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_interface_read(self) -> None:
        fn = interfaces.build(self._client)
        wrapped = audit_logged("pfsense_get_interfaces", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_gateway_read(self) -> None:
        gateways_fn = gateways.build(self._client)
        wrapped_gateways = audit_logged("pfsense_get_gateways", self._identity)(gateways_fn)
        self._register_read_tool(wrapped_gateways)

        status_fn = gateway_status.build(self._client)
        wrapped_status = audit_logged("pfsense_get_gateway_status", self._identity)(status_fn)
        self._register_read_tool(wrapped_status)

    def _register_firewall_read(self) -> None:
        rules_fn = firewall_rules.build(self._client)
        wrapped_rules = audit_logged("pfsense_get_firewall_rules", self._identity)(rules_fn)
        self._register_read_tool(wrapped_rules)

        states_fn = firewall_states.build(self._client)
        wrapped_states = audit_logged("pfsense_get_firewall_states", self._identity)(states_fn)
        self._register_read_tool(wrapped_states)

        states_size_fn = firewall_states_size.build(self._client)
        wrapped_states_size = audit_logged("pfsense_get_firewall_states_size", self._identity)(states_size_fn)
        self._register_read_tool(wrapped_states_size)

        apply_status_fn = firewall_apply_status.build(self._client)
        wrapped_apply_status = audit_logged("pfsense_get_firewall_apply_status", self._identity)(apply_status_fn)
        self._register_read_tool(wrapped_apply_status)

    def _register_alias_read(self) -> None:
        fn = firewall_aliases.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_aliases", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_service_read(self) -> None:
        fn = service_status.build(self._client)
        wrapped = audit_logged("pfsense_get_service_status", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_info_read(self) -> None:
        fn = system_version.build(self._client)
        wrapped = audit_logged("pfsense_get_system_version", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_interface_config_read(self) -> None:
        fn = interface_configs.build(self._client)
        wrapped = audit_logged("pfsense_get_interface_configs", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_firewall_nat_read(self) -> None:
        fn = firewall_nat_port_forwards.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_nat_port_forwards", self._identity)(fn)
        self._register_read_tool(wrapped)

        firewall_nat_outbound_mode_fn = firewall_nat_outbound_mode.build(self._client)
        firewall_nat_outbound_mode_wrapped = audit_logged("pfsense_get_firewall_nat_outbound_mode", self._identity)(
            firewall_nat_outbound_mode_fn
        )
        self._register_read_tool(firewall_nat_outbound_mode_wrapped)

        outbound_mappings_fn = firewall_nat_outbound_mappings.build(self._client)
        outbound_mappings_wrapped = audit_logged("pfsense_get_firewall_nat_outbound_mappings", self._identity)(
            outbound_mappings_fn
        )
        self._register_read_tool(outbound_mappings_wrapped)

        one_to_one_fn = firewall_nat_one_to_one_mappings.build(self._client)
        one_to_one_wrapped = audit_logged("pfsense_get_firewall_nat_one_to_one_mappings", self._identity)(one_to_one_fn)
        self._register_read_tool(one_to_one_wrapped)

    def _register_user_read(self) -> None:
        fn = users.build(self._client)
        wrapped = audit_logged("pfsense_get_users", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_certificate_read(self) -> None:
        fn = system_certificates.build(self._client)
        wrapped = audit_logged("pfsense_get_system_certificates", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_user_group_read(self) -> None:
        fn = user_groups.build(self._client)
        wrapped = audit_logged("pfsense_get_user_groups", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_dhcp_lease_read(self) -> None:
        fn = dhcp_leases.build(self._client)
        wrapped = audit_logged("pfsense_get_dhcp_leases", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_dhcp_static_mapping_read(self) -> None:
        fn = dhcp_static_mappings.build(self._client)
        wrapped = audit_logged("pfsense_get_dhcp_static_mappings", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_dhcp_server_read(self) -> None:
        fn = dhcp_servers.build(self._client)
        wrapped = audit_logged("pfsense_get_dhcp_servers", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_interface_virtual_read(self) -> None:
        fn = interface_bridges.build(self._client)
        wrapped = audit_logged("pfsense_get_interface_bridges", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_status_carp_read(self) -> None:
        fn = carp_status.build(self._client)
        wrapped = audit_logged("pfsense_get_carp_status", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_restapi_settings_read(self) -> None:
        fn = system_restapi_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_system_restapi_settings", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_ha_sync_read(self) -> None:
        fn = system_hasync.build(self._client)
        wrapped = audit_logged("pfsense_get_system_hasync", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_services_dns_resolver_read(self) -> None:
        fn = dns_resolver_host_overrides.build(self._client)
        wrapped = audit_logged("pfsense_get_dns_resolver_host_overrides", self._identity)(fn)
        self._register_read_tool(wrapped)

        dns_resolver_settings_fn = dns_resolver_settings.build(self._client)
        dns_resolver_settings_wrapped = audit_logged("pfsense_get_dns_resolver_settings", self._identity)(
            dns_resolver_settings_fn
        )
        self._register_read_tool(dns_resolver_settings_wrapped)

    def _register_diagnostics_arp_read(self) -> None:
        fn = arp_table.build(self._client)
        wrapped = audit_logged("pfsense_get_arp_table", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_firewall_traffic_shaper_read(self) -> None:
        fn = firewall_traffic_shaper_limiters.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_traffic_shaper_limiters", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_firewall_advanced_settings_read(self) -> None:
        fn = firewall_advanced_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_advanced_settings", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_package_read(self) -> None:
        fn = system_packages.build(self._client)
        wrapped = audit_logged("pfsense_get_system_packages", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_tunable_read(self) -> None:
        fn = system_tunables.build(self._client)
        wrapped = audit_logged("pfsense_get_system_tunables", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_notifications_read(self) -> None:
        fn = email_notification_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_email_notification_settings", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_services_bind_read(self) -> None:
        fn = bind_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_bind_settings", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_services_ntp_read(self) -> None:
        fn = ntp_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_ntp_settings", self._identity)(fn)
        self._register_read_tool(wrapped)

        ntp_time_servers_fn = ntp_time_servers.build(self._client)
        ntp_time_servers_wrapped = audit_logged("pfsense_get_ntp_time_servers", self._identity)(ntp_time_servers_fn)
        self._register_read_tool(ntp_time_servers_wrapped)

    def _register_services_ssh_read(self) -> None:
        fn = ssh_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_ssh_settings", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_services_cron_read(self) -> None:
        fn = cron_jobs.build(self._client)
        wrapped = audit_logged("pfsense_get_cron_jobs", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_services_acme_read(self) -> None:
        fn = acme_settings.build(self._client)
        wrapped = audit_logged("pfsense_get_acme_settings", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_services_freeradius_read(self) -> None:
        fn = freeradius_eap.build(self._client)
        wrapped = audit_logged("pfsense_get_freeradius_eap", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_diagnostics_tables_read(self) -> None:
        fn = diagnostics_tables.build(self._client)
        wrapped = audit_logged("pfsense_get_diagnostics_tables", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_auth_keys_read(self) -> None:
        fn = auth_keys.build(self._client)
        wrapped = audit_logged("pfsense_get_auth_keys", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_server_info_read(self) -> None:
        fn = mcp_info.build(self._build_introspection_snapshot)
        wrapped = audit_logged("pfsense_mcp_info", self._identity)(fn)
        self._register_read_tool(wrapped, annotation_policy=LOCAL_ONLY_ANNOTATION_POLICY)

    def _register_interface_vlan_read(self) -> None:
        fn = interface_vlans.build(self._client)
        wrapped = audit_logged("pfsense_get_interface_vlans", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_routing_static_route_read(self) -> None:
        fn = routing_static_routes.build(self._client)
        wrapped = audit_logged("pfsense_get_routing_static_routes", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_interface_group_read(self) -> None:
        fn = interface_groups.build(self._client)
        wrapped = audit_logged("pfsense_get_interface_groups", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_firewall_schedule_read(self) -> None:
        fn = firewall_schedules.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_schedules", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_restapi_version_read(self) -> None:
        fn = system_restapi_version.build(self._client)
        wrapped = audit_logged("pfsense_get_system_restapi_version", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_firewall_virtual_ip_read(self) -> None:
        fn = firewall_virtual_ips.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_virtual_ips", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _register_system_certificate_authority_read(self) -> None:
        fn = system_certificate_authorities.build(self._client)
        wrapped = audit_logged("pfsense_get_system_certificate_authorities", self._identity)(fn)
        self._register_read_tool(wrapped)

    def _build_introspection_snapshot(self) -> ServerIntrospection:
        """Assemble pfsense_mcp_info's response from live process state,
        evaluated at call time (not registration time) so it always
        reflects everything register_all() actually did, including this
        tool's own registration."""
        active_write_capabilities = tuple(
            sorted(capability.name for capability in self._capabilities if capability.name.endswith("_WRITE"))
        )
        return ServerIntrospection(
            server_version=importlib.metadata.version("pfsense-mcp-server"),
            active_profile=self._profile_name,
            registered_tool_count=len(self._registered_read_names) + len(self._registered_write_names),
            registered_read_tool_count=len(self._registered_read_names),
            registered_write_tool_count=len(self._registered_write_names),
            active_capability_set=tuple(sorted(capability.name for capability in self._capabilities)),
            active_write_capabilities=active_write_capabilities,
            active_write_endpoint_count=len(WriteEndpoints.active_entries()),
            tier1_package_present=importlib.util.find_spec("pfsense_mcp.tier1") is not None,
            tier1_imported_this_process="pfsense_mcp.tier1" in sys.modules,
            guidance_package_present=importlib.util.find_spec("pfsense_mcp.guidance") is not None,
            guidance_imported_this_process="pfsense_mcp.guidance" in sys.modules,
            mcp_transport="stdio",
        )
