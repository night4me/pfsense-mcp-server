"""Static category grouping (Phase 4A: STATIC GROUPING prototype).

Maps every one of the 97 existing, already-reviewed public MCP tool names
(as captured by `measure_schema_cost.py` from the real `tools/list`
response) to exactly one of 7 categories. This is pure metadata -- a
`dict[str, str]` and its inverse -- never a dispatcher: every category
resolves only to a fixed list of the *existing* explicit tool names, and
nothing here can select, construct, or invoke an endpoint that isn't
already one of the 97 reviewed tools.

Categories deliberately mirror the mission's own example taxonomy:
system, networking, firewall, dns_dhcp, vpn, identity_certificates,
guidance.

Note: this "guidance" category (3 tools: the 2 provenance-classified
guidance tools plus `pfsense_mcp_info`, grouped here for being
introspective/meta rather than live pfSense state) is this benchmark's
own analytical UX grouping -- it is NOT the same as the project's
authoritative public-contract classification (95 READ / 2 guidance /
97 total), which counts `pfsense_mcp_info` among the 95 READ tools. Do
not conflate the two when citing tool counts.
"""

from __future__ import annotations

CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "system": "Appliance identity, status, and platform configuration -- "
    "hostname, version, timezone, console, packages, tunables, NTP, "
    "logging, SSH/web GUI access, REST API settings, scheduled jobs, "
    "diagnostics, and high-availability sync state.",
    "networking": "Interfaces, gateways, static routes, ARP, and interface "
    "composition (VLANs, bridges, LAGGs, groups, GRE tunnels).",
    "firewall": "Firewall rules, aliases, NAT (1:1/outbound/port-forward), "
    "schedules, traffic shaping, virtual IPs, and live firewall state.",
    "dns_dhcp": "DNS resolver/forwarder configuration and DHCP server/relay "
    "configuration and leases, including the BIND package if installed.",
    "vpn": "IPsec, OpenVPN, and WireGuard configuration and live status, "
    "plus RADIUS/EAP settings used by some VPN authentication.",
    "identity_certificates": "Local users and groups, API authentication "
    "keys, and the certificate/CA/CRL/ACME PKI inventory.",
    "guidance": "Meta-tools that describe this server's own capabilities "
    "or the pfSense REST API itself, rather than reading appliance state.",
}

#: name -> category, for every one of the 97 tools as of the checkpoint
#: this benchmark was built against (045051f). If the real tool count
#: ever drifts, `tests_or_scripts` should re-derive this from a fresh
#: `measure_schema_cost.py` run rather than hand-editing silently stale.
TOOL_CATEGORY: dict[str, str] = {
    # --- system ---
    "pfsense_get_system_status": "system",
    "pfsense_get_system_version": "system",
    "pfsense_get_system_hostname": "system",
    "pfsense_get_system_console": "system",
    "pfsense_get_system_timezone": "system",
    "pfsense_get_system_dns": "system",
    "pfsense_get_system_hasync": "system",
    "pfsense_get_system_tunables": "system",
    "pfsense_get_system_webgui_settings": "system",
    "pfsense_get_system_packages": "system",
    "pfsense_get_system_package_available": "system",
    "pfsense_get_system_restapi_access_list": "system",
    "pfsense_get_system_restapi_settings": "system",
    "pfsense_get_system_restapi_version": "system",
    "pfsense_get_ssh_settings": "system",
    "pfsense_get_ntp_settings": "system",
    "pfsense_get_ntp_time_servers": "system",
    "pfsense_get_cron_jobs": "system",
    "pfsense_get_email_notification_settings": "system",
    "pfsense_get_status_logs_settings": "system",
    "pfsense_get_service_status": "system",
    "pfsense_get_diagnostics_config_history_revisions": "system",
    "pfsense_get_diagnostics_tables": "system",
    "pfsense_get_arp_table": "system",
    # --- networking ---
    "pfsense_get_interfaces": "networking",
    "pfsense_get_interface_configs": "networking",
    "pfsense_get_interface_apply_status": "networking",
    "pfsense_get_interface_available_interfaces": "networking",
    "pfsense_get_interface_bridges": "networking",
    "pfsense_get_interface_groups": "networking",
    "pfsense_get_interface_gres": "networking",
    "pfsense_get_interface_laggs": "networking",
    "pfsense_get_interface_vlans": "networking",
    "pfsense_get_gateways": "networking",
    "pfsense_get_gateway_status": "networking",
    "pfsense_get_routing_apply_status": "networking",
    "pfsense_get_routing_gateway_default": "networking",
    "pfsense_get_routing_gateway_groups": "networking",
    "pfsense_get_routing_static_routes": "networking",
    "pfsense_get_carp_status": "networking",
    # --- firewall ---
    "pfsense_get_firewall_rules": "firewall",
    "pfsense_get_firewall_aliases": "firewall",
    "pfsense_get_firewall_advanced_settings": "firewall",
    "pfsense_get_firewall_apply_status": "firewall",
    "pfsense_get_firewall_schedules": "firewall",
    "pfsense_get_firewall_states": "firewall",
    "pfsense_get_firewall_states_size": "firewall",
    "pfsense_get_firewall_traffic_shapers": "firewall",
    "pfsense_get_firewall_traffic_shaper_limiters": "firewall",
    "pfsense_get_firewall_virtual_ips": "firewall",
    "pfsense_get_firewall_virtual_ip_apply_status": "firewall",
    "pfsense_get_firewall_nat_one_to_one_mappings": "firewall",
    "pfsense_get_firewall_nat_outbound_mappings": "firewall",
    "pfsense_get_firewall_nat_outbound_mode": "firewall",
    "pfsense_get_firewall_nat_port_forwards": "firewall",
    # --- dns_dhcp ---
    "pfsense_get_dns_resolver_settings": "dns_dhcp",
    "pfsense_get_dns_resolver_host_overrides": "dns_dhcp",
    "pfsense_get_dns_resolver_domain_overrides": "dns_dhcp",
    "pfsense_get_dns_resolver_access_lists": "dns_dhcp",
    "pfsense_get_dns_resolver_apply_status": "dns_dhcp",
    "pfsense_get_dns_forwarder_host_overrides": "dns_dhcp",
    "pfsense_get_dns_forwarder_apply_status": "dns_dhcp",
    "pfsense_get_bind_settings": "dns_dhcp",
    "pfsense_get_dhcp_servers": "dns_dhcp",
    "pfsense_get_dhcp_server_address_pools": "dns_dhcp",
    "pfsense_get_dhcp_server_custom_options": "dns_dhcp",
    "pfsense_get_dhcp_server_apply_status": "dns_dhcp",
    "pfsense_get_dhcp_static_mappings": "dns_dhcp",
    "pfsense_get_dhcp_leases": "dns_dhcp",
    "pfsense_get_dhcp_relay": "dns_dhcp",
    # --- vpn ---
    "pfsense_get_vpn_ipsec_phase1_encryptions": "vpn",
    "pfsense_get_vpn_ipsec_phase2_encryptions": "vpn",
    "pfsense_get_vpn_ipsec_phase2s": "vpn",
    "pfsense_get_ipsec_apply_status": "vpn",
    "pfsense_get_status_ipsec_sas": "vpn",
    "pfsense_get_status_ipsec_child_sas": "vpn",
    "pfsense_get_vpn_openvpn_servers": "vpn",
    "pfsense_get_vpn_openvpn_csos": "vpn",
    "pfsense_get_status_openvpn_servers": "vpn",
    "pfsense_get_status_openvpn_clients": "vpn",
    "pfsense_get_status_openvpn_server_connections": "vpn",
    "pfsense_get_status_openvpn_server_routes": "vpn",
    "pfsense_get_vpn_wireguard_tunnel_addresses": "vpn",
    "pfsense_get_wireguard_apply_status": "vpn",
    "pfsense_get_status_wireguard_tunnels": "vpn",
    "pfsense_get_status_wireguard_peers": "vpn",
    "pfsense_get_freeradius_eap": "vpn",
    # --- identity_certificates ---
    "pfsense_get_users": "identity_certificates",
    "pfsense_get_user_groups": "identity_certificates",
    "pfsense_get_auth_keys": "identity_certificates",
    "pfsense_get_system_certificates": "identity_certificates",
    "pfsense_get_system_certificate_authorities": "identity_certificates",
    "pfsense_get_system_crls": "identity_certificates",
    "pfsense_get_acme_settings": "identity_certificates",
    # --- guidance ---
    "pfsense_get_api_guidance": "guidance",
    "pfsense_get_official_guidance": "guidance",
    "pfsense_mcp_info": "guidance",
}


def category_for(tool_name: str) -> str | None:
    return TOOL_CATEGORY.get(tool_name)


def tools_in_category(category: str) -> list[str]:
    return sorted(name for name, cat in TOOL_CATEGORY.items() if cat == category)


if __name__ == "__main__":
    # Self-check: every category has at least one tool, every tool has
    # exactly one category, counts sum to the total.
    counts = {cat: len(tools_in_category(cat)) for cat in CATEGORY_DESCRIPTIONS}
    total = sum(counts.values())
    print(f"total categorized: {total}")
    for cat, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {cat:<24} {count:>3}")
