"""Tool -> pfREST endpoint path mapping (pfREST_LIVE_GUIDANCE_ARC Phase
9/10).

Generated once from this project's own authoritative source
(`scripts/public_contract.py`'s AST-derived tool/endpoint mapping,
2026-08-28) and checked in as a literal table here -- verified not to
drift by `tests/pfrest_docs/test_tool_endpoint_map.py`, which
re-derives the same mapping from source at test time and asserts an
exact match against this dict. The production runtime path is a plain
dict lookup, never AST parsing -- this file exists so that lookup never
has to read/parse this project's own source tree at MCP call time.

114 of the 115 public READ tools appear here; the missing one is
`pfsense_mcp_info` (`LOCAL_ONLY_TOOL_NAMES` in `scripts/public_contract.py`),
which has no pfSense API call at all and therefore no endpoint to map.

Values are this project's own internal `EndpointInfo.path_suffix`
(e.g. `"/firewall/aliases"`) and HTTP method -- `pfrest_path_for()`
below converts to the `/api/v2...`-prefixed form pfREST's own OpenAPI
document actually keys its `paths` by (verified live 2026-08-28:
`pfsense_get_firewall_aliases`'s own endpoint is the *plural* "many"
path `/api/v2/firewall/aliases`, a genuinely different OpenAPI path
from the *singular* `/api/v2/firewall/alias` -- this project's own
`path_suffix` already disambiguates the two correctly, since it is
itself the authoritative source these values were derived from).
"""

from __future__ import annotations

TOOL_ENDPOINT_PATHS: dict[str, tuple[str, str]] = {
    "pfsense_get_acme_settings": ("/services/acme/settings", "GET"),
    "pfsense_get_arp_table": ("/diagnostics/arp_table", "GET"),
    "pfsense_get_auth_keys": ("/auth/keys", "GET"),
    "pfsense_get_bind_access_lists": ("/services/bind/access_lists", "GET"),
    "pfsense_get_bind_settings": ("/services/bind/settings", "GET"),
    "pfsense_get_bind_sync_settings": ("/services/bind/sync/settings", "GET"),
    "pfsense_get_bind_views": ("/services/bind/views", "GET"),
    "pfsense_get_bind_zone_record": ("/services/bind/zone/record", "GET"),
    "pfsense_get_bind_zones": ("/services/bind/zones", "GET"),
    "pfsense_get_carp_status": ("/status/carp", "GET"),
    "pfsense_get_cron_jobs": ("/services/cron/jobs", "GET"),
    "pfsense_get_dhcp_leases": ("/status/dhcp_server/leases", "GET"),
    "pfsense_get_dhcp_relay": ("/services/dhcp_relay", "GET"),
    "pfsense_get_dhcp_server_address_pools": ("/services/dhcp_server/address_pools", "GET"),
    "pfsense_get_dhcp_server_apply_status": ("/services/dhcp_server/apply", "GET"),
    "pfsense_get_dhcp_server_custom_options": ("/services/dhcp_server/custom_options", "GET"),
    "pfsense_get_dhcp_servers": ("/services/dhcp_servers", "GET"),
    "pfsense_get_dhcp_static_mappings": ("/services/dhcp_server/static_mappings", "GET"),
    "pfsense_get_diagnostics_config_history_revisions": ("/diagnostics/config_history/revisions", "GET"),
    "pfsense_get_diagnostics_tables": ("/diagnostics/tables", "GET"),
    "pfsense_get_dns_forwarder_apply_status": ("/services/dns_forwarder/apply", "GET"),
    "pfsense_get_dns_forwarder_host_overrides": ("/services/dns_forwarder/host_overrides", "GET"),
    "pfsense_get_dns_resolver_access_lists": ("/services/dns_resolver/access_lists", "GET"),
    "pfsense_get_dns_resolver_apply_status": ("/services/dns_resolver/apply", "GET"),
    "pfsense_get_dns_resolver_domain_overrides": ("/services/dns_resolver/domain_overrides", "GET"),
    "pfsense_get_dns_resolver_host_overrides": ("/services/dns_resolver/host_overrides", "GET"),
    "pfsense_get_dns_resolver_settings": ("/services/dns_resolver/settings", "GET"),
    "pfsense_get_email_notification_settings": ("/system/notifications/email_settings", "GET"),
    "pfsense_get_firewall_advanced_settings": ("/firewall/advanced_settings", "GET"),
    "pfsense_get_firewall_aliases": ("/firewall/aliases", "GET"),
    "pfsense_get_firewall_apply_status": ("/firewall/apply", "GET"),
    "pfsense_get_firewall_nat_one_to_one_mappings": ("/firewall/nat/one_to_one/mappings", "GET"),
    "pfsense_get_firewall_nat_outbound_mappings": ("/firewall/nat/outbound/mappings", "GET"),
    "pfsense_get_firewall_nat_outbound_mode": ("/firewall/nat/outbound/mode", "GET"),
    "pfsense_get_firewall_nat_port_forwards": ("/firewall/nat/port_forwards", "GET"),
    "pfsense_get_firewall_rules": ("/firewall/rules", "GET"),
    "pfsense_get_firewall_schedules": ("/firewall/schedules", "GET"),
    "pfsense_get_firewall_states": ("/firewall/states", "GET"),
    "pfsense_get_firewall_states_size": ("/firewall/states/size", "GET"),
    "pfsense_get_firewall_traffic_shaper_limiters": ("/firewall/traffic_shaper/limiters", "GET"),
    "pfsense_get_firewall_traffic_shapers": ("/firewall/traffic_shapers", "GET"),
    "pfsense_get_firewall_virtual_ip_apply_status": ("/firewall/virtual_ip/apply", "GET"),
    "pfsense_get_firewall_virtual_ips": ("/firewall/virtual_ips", "GET"),
    "pfsense_get_freeradius_eap": ("/services/freeradius/eap", "GET"),
    "pfsense_get_gateway_status": ("/status/gateways", "GET"),
    "pfsense_get_gateways": ("/routing/gateways", "GET"),
    "pfsense_get_haproxy_apply_status": ("/services/haproxy/apply", "GET"),
    "pfsense_get_haproxy_backend_acls": ("/services/haproxy/backend/acls", "GET"),
    "pfsense_get_haproxy_backend_errorfiles": ("/services/haproxy/backend/errorfiles", "GET"),
    "pfsense_get_haproxy_backend_servers": ("/services/haproxy/backend/servers", "GET"),
    "pfsense_get_haproxy_backends": ("/services/haproxy/backends", "GET"),
    "pfsense_get_haproxy_dns_resolvers": ("/services/haproxy/settings/dns_resolvers", "GET"),
    "pfsense_get_haproxy_email_mailers": ("/services/haproxy/settings/email_mailers", "GET"),
    "pfsense_get_haproxy_files": ("/services/haproxy/files", "GET"),
    "pfsense_get_haproxy_frontend_acls": ("/services/haproxy/frontend/acls", "GET"),
    "pfsense_get_haproxy_frontend_addresses": ("/services/haproxy/frontend/addresses", "GET"),
    "pfsense_get_haproxy_frontend_certificates": ("/services/haproxy/frontend/certificates", "GET"),
    "pfsense_get_haproxy_frontend_error_files": ("/services/haproxy/frontend/error_files", "GET"),
    "pfsense_get_haproxy_frontends": ("/services/haproxy/frontends", "GET"),
    "pfsense_get_haproxy_settings": ("/services/haproxy/settings", "GET"),
    "pfsense_get_interface_apply_status": ("/interface/apply", "GET"),
    "pfsense_get_interface_available_interfaces": ("/interface/available_interfaces", "GET"),
    "pfsense_get_interface_bridges": ("/interface/bridges", "GET"),
    "pfsense_get_interface_configs": ("/interfaces", "GET"),
    "pfsense_get_interface_gres": ("/interface/gres", "GET"),
    "pfsense_get_interface_groups": ("/interface/groups", "GET"),
    "pfsense_get_interface_laggs": ("/interface/laggs", "GET"),
    "pfsense_get_interface_vlans": ("/interface/vlans", "GET"),
    "pfsense_get_interfaces": ("/status/interfaces", "GET"),
    "pfsense_get_ipsec_apply_status": ("/vpn/ipsec/apply", "GET"),
    "pfsense_get_ntp_settings": ("/services/ntp/settings", "GET"),
    "pfsense_get_ntp_time_servers": ("/services/ntp/time_servers", "GET"),
    "pfsense_get_routing_apply_status": ("/routing/apply", "GET"),
    "pfsense_get_routing_gateway_default": ("/routing/gateway/default", "GET"),
    "pfsense_get_routing_gateway_groups": ("/routing/gateway/groups", "GET"),
    "pfsense_get_routing_static_routes": ("/routing/static_routes", "GET"),
    "pfsense_get_service_status": ("/status/services", "GET"),
    "pfsense_get_services_service_watchdogs": ("/services/service_watchdogs", "GET"),
    "pfsense_get_ssh_settings": ("/services/ssh", "GET"),
    "pfsense_get_status_ipsec_child_sas": ("/status/ipsec/child_sas", "GET"),
    "pfsense_get_status_ipsec_sas": ("/status/ipsec/sas", "GET"),
    "pfsense_get_status_logs_settings": ("/status/logs/settings", "GET"),
    "pfsense_get_status_openvpn_clients": ("/status/openvpn/clients", "GET"),
    "pfsense_get_status_openvpn_server_connections": ("/status/openvpn/server/connections", "GET"),
    "pfsense_get_status_openvpn_server_routes": ("/status/openvpn/server/routes", "GET"),
    "pfsense_get_status_openvpn_servers": ("/status/openvpn/servers", "GET"),
    "pfsense_get_status_wireguard_peers": ("/status/wireguard/peers", "GET"),
    "pfsense_get_status_wireguard_tunnels": ("/status/wireguard/tunnels", "GET"),
    "pfsense_get_system_certificate_authorities": ("/system/certificate_authorities", "GET"),
    "pfsense_get_system_certificates": ("/system/certificates", "GET"),
    "pfsense_get_system_console": ("/system/console", "GET"),
    "pfsense_get_system_crls": ("/system/crls", "GET"),
    "pfsense_get_system_dns": ("/system/dns", "GET"),
    "pfsense_get_system_hasync": ("/system/hasync", "GET"),
    "pfsense_get_system_hostname": ("/system/hostname", "GET"),
    "pfsense_get_system_package_available": ("/system/package/available", "GET"),
    "pfsense_get_system_packages": ("/system/packages", "GET"),
    "pfsense_get_system_restapi_access_list": ("/system/restapi/access_list", "GET"),
    "pfsense_get_system_restapi_settings": ("/system/restapi/settings", "GET"),
    "pfsense_get_system_restapi_version": ("/system/restapi/version", "GET"),
    "pfsense_get_system_status": ("/status/system", "GET"),
    "pfsense_get_system_timezone": ("/system/timezone", "GET"),
    "pfsense_get_system_tunables": ("/system/tunables", "GET"),
    "pfsense_get_system_version": ("/system/version", "GET"),
    "pfsense_get_system_webgui_settings": ("/system/webgui/settings", "GET"),
    "pfsense_get_user_auth_servers": ("/user/auth_servers", "GET"),
    "pfsense_get_user_groups": ("/user/groups", "GET"),
    "pfsense_get_users": ("/users", "GET"),
    "pfsense_get_vpn_ipsec_phase1_encryptions": ("/vpn/ipsec/phase1/encryptions", "GET"),
    "pfsense_get_vpn_ipsec_phase1s": ("/vpn/ipsec/phase1s", "GET"),
    "pfsense_get_vpn_ipsec_phase2_encryptions": ("/vpn/ipsec/phase2/encryptions", "GET"),
    "pfsense_get_vpn_ipsec_phase2s": ("/vpn/ipsec/phase2s", "GET"),
    "pfsense_get_vpn_openvpn_clients": ("/vpn/openvpn/clients", "GET"),
    "pfsense_get_vpn_openvpn_csos": ("/vpn/openvpn/csos", "GET"),
    "pfsense_get_vpn_openvpn_servers": ("/vpn/openvpn/servers", "GET"),
    "pfsense_get_vpn_wireguard_peers": ("/vpn/wireguard/peers", "GET"),
    "pfsense_get_vpn_wireguard_tunnel_addresses": ("/vpn/wireguard/tunnel/addresses", "GET"),
    "pfsense_get_vpn_wireguard_settings": ("/vpn/wireguard/settings", "GET"),
    "pfsense_get_vpn_wireguard_tunnels": ("/vpn/wireguard/tunnels", "GET"),
    "pfsense_get_wireguard_apply_status": ("/vpn/wireguard/apply", "GET"),
}


def pfrest_path_for(tool_name: str) -> tuple[str, str] | None:
    """Returns (api-v2-prefixed path, HTTP method) for a known tool
    name, or None for an unknown tool name or one with no mapped
    endpoint (currently only `pfsense_mcp_info`). Never raises."""

    entry = TOOL_ENDPOINT_PATHS.get(tool_name)
    if entry is None:
        return None
    path_suffix, method = entry
    return f"/api/v2{path_suffix}", method
