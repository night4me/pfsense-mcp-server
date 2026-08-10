# READ Capability Backlog

> **Historical discovery snapshot.** This document records the initial v0.1.0
> comparison with one pfSense REST API schema. It is not the current capability
> status and does not authorize implementation. See [ROADMAP.md](ROADMAP.md)
> and `src/pfsense_mcp/capabilities.py` for current planning and build state.
> Endpoint availability also varies by appliance and installed package.

Implementation roadmap for remaining GET-only ("READ") capabilities, derived
by comparing the live pfSense REST API v2 OpenAPI schema
(`/api/v2/schema/openapi`, 267 total paths / 243 distinct GET endpoints)
against the capabilities currently implemented in this repository.

This is a roadmap, not a design document. No capability listed here as
"Planned" or "Deferred" has been implemented, scaffolded, or otherwise
changed as part of producing this document.

## Post-snapshot discovery (2026-08-10) — `SYSTEM_INFO_READ` implemented narrower than originally planned

Found during a real-world READ-only diagnostic session (a certificate-
manager investigation, see `reports-ai/` for the full session record),
not while producing or revising this snapshot. Recorded here as an
addendum, not a rewrite of the table above — the original snapshot row
is left exactly as it was written.

The table below groups `/system/webgui/settings` under
`SYSTEM_INFO_READ` alongside `/system/version`, `/system/hostname`,
`/system/timezone`, `/system/dns`, and `/system/console`. **As actually
built, `SYSTEM_INFO_READ` registers exactly one tool**,
`pfsense_get_system_version`
(`src/pfsense_mcp/tools/registry.py::_register_system_info_read`, which
calls only `src/pfsense_mcp/tools/read/system_version.py`) — covering
`/system/version` alone. None of the other five endpoints originally
grouped under this capability, including `/system/webgui/settings`,
were ever implemented. This was confirmed by reading the registry and
tool source directly, not inferred from behavior alone.

**Why this specific endpoint matters**: `/system/webgui/settings` is
where pfSense's `ssl-certref` — which certificate the webConfigurator
GUI is actually presenting — lives. During the diagnostic session that
found this gap, an agent using only this MCP server's READ tools could
enumerate certificates and their validity, but could not determine
which one was actually bound to the GUI without a human checking the
pfSense UI directly. See `reports-ai/` for the full session record;
`docs/ROADMAP.md`'s "Possible ideas" (v0.3.0 section) now has a
one-line pointer to this addendum. The same session also motivated a
broader future direction — see `docs/ROADMAP.md`'s "WebGUI Evidence
Layer" idea (a tightly constrained, provenance-tracked, READ-only
WebGUI fallback for exactly this class of API-coverage gap) — this
specific `/system/webgui/settings` gap is its motivating real-world
example, not a duplicate of it.

No implementation, scaffolding, or capability/tool change was made as
part of recording this discovery.

## Coverage summary

| Metric | Count |
|---|---|
| Total GET endpoints (live schema) | 243 |
| Endpoints covered by completed capabilities | 8 |
| Endpoints covered by planned capabilities | 235 |
| Endpoints covered by deferred capabilities | 0 |
| Completed capabilities | 4 |
| Planned capabilities | 47 |
| Deferred capabilities | 0 |

All 243 endpoints are accounted for exactly once across 51 capability rows
(4 Done + 47 Planned). See the Appendix for the full path-level mapping used
to derive this table.

## Capabilities

| Capability | GET endpoint(s) | Complexity | Sensitivity | Dependencies | Priority | Status |
|---|---|---|---|---|---|---|
| SYSTEM_READ | `/status/system` | Low | Low | — | — | Done |
| INTERFACE_READ | `/status/interfaces` | Low | Low | — | — | Done |
| GATEWAY_READ | `/routing/gateways`, `/status/gateways` | Low | Low | — | — | Done |
| FIREWALL_READ | `/firewall/rules`, `/firewall/states`, `/firewall/states/size`, `/firewall/apply` | Medium | Medium | — | — | Done |
| FIREWALL_ALIAS_READ | `/firewall/alias`, `/firewall/aliases` | Low | Low | Enum placeholder `Capability.ALIAS_READ` already exists | High | Planned |
| FIREWALL_SINGLETON_READ | `/firewall/rule`, `/firewall/state` | Low | Medium | FIREWALL_READ (by-id lookup counterparts) | Low | Planned |
| FIREWALL_SCHEDULE_READ | `/firewall/schedule(s)`, `/firewall/schedule/time_range(s)` | Low | Low | — | Medium | Planned |
| FIREWALL_NAT_READ | `/firewall/nat/one_to_one/mapping(s)`, `/firewall/nat/outbound/mapping(s)`, `/firewall/nat/outbound/mode`, `/firewall/nat/port_forward(s)` | Medium | High | — | High | Planned |
| FIREWALL_VIRTUAL_IP_READ | `/firewall/virtual_ip(s)`, `/firewall/virtual_ip/apply` | Low | Medium | — | Medium | Planned |
| FIREWALL_TRAFFIC_SHAPER_READ | `/firewall/traffic_shaper(s)`, `/firewall/traffic_shaper/limiter(s)`, `/firewall/traffic_shaper/limiter/bandwidth(s)`, `/firewall/traffic_shaper/limiter/queue(s)`, `/firewall/traffic_shaper/queue(s)` | Medium | Low | — | Low | Planned |
| FIREWALL_ADVANCED_SETTINGS_READ | `/firewall/advanced_settings` | Low | Medium | — | Low | Planned |
| INTERFACE_CONFIG_READ | `/interface`, `/interfaces`, `/interface/available_interfaces`, `/interface/apply` | Medium | Medium | — | High | Planned |
| INTERFACE_VIRTUAL_READ | `/interface/vlan(s)`, `/interface/bridge(s)`, `/interface/lagg(s)`, `/interface/group(s)`, `/interface/gre(s)` | Medium | Medium | INTERFACE_CONFIG_READ (shares interface identifiers) | Medium | Planned |
| ROUTING_GATEWAY_GROUP_READ | `/routing/gateway`, `/routing/gateway/default`, `/routing/gateway/group(s)`, `/routing/gateway/group/priorit(y\|ies)`, `/routing/apply` | Medium | Medium | GATEWAY_READ | Medium | Planned |
| ROUTING_STATIC_ROUTE_READ | `/routing/static_route(s)` | Low | Medium | GATEWAY_READ | Medium | Planned |
| STATUS_SERVICES_READ | `/status/services` | Low | Low | Enum placeholder `Capability.SERVICE_READ` already exists | High | Planned |
| STATUS_CARP_READ | `/status/carp` | Low | Medium | GATEWAY_READ (HA context) | Medium | Planned |
| STATUS_DHCP_LEASES_READ | `/status/dhcp_server/leases` | Low | High | — | High | Planned |
| STATUS_LOGS_READ | `/status/logs/auth`, `/status/logs/dhcp`, `/status/logs/firewall`, `/status/logs/openvpn`, `/status/logs/packages/restapi`, `/status/logs/settings`, `/status/logs/system` | Medium | High | — | Medium | Planned |
| STATUS_IPSEC_READ | `/status/ipsec/sas`, `/status/ipsec/child_sa(s)` | Low | High | VPN_IPSEC_CONFIG_READ | Medium | Planned |
| STATUS_OPENVPN_READ | `/status/openvpn/clients`, `/status/openvpn/server(s)`, `/status/openvpn/server/connection(s)`, `/status/openvpn/server/route(s)` | Medium | High | VPN_OPENVPN_SERVER_READ, VPN_OPENVPN_CLIENT_READ | Medium | Planned |
| STATUS_WIREGUARD_READ | `/status/wireguard/peers`, `/status/wireguard/tunnels` | Low | High | VPN_WIREGUARD_READ | Medium | Planned |
| SYSTEM_INFO_READ | `/system/version`, `/system/hostname`, `/system/timezone`, `/system/dns`, `/system/console`, `/system/webgui/settings` | Low | Low | — | High | Planned |
| SYSTEM_CERTIFICATE_READ | `/system/certificate(s)`, `/system/certificate_authorit(y\|ies)`, `/system/crl(s)`, `/system/crl/revoked_certificate` | Medium | High | — | High | Planned |
| SYSTEM_PACKAGE_READ | `/system/package(s)`, `/system/package/available` | Low | Low | — | Low | Planned |
| SYSTEM_TUNABLE_READ | `/system/tunable(s)` | Low | Low | — | Low | Planned |
| SYSTEM_RESTAPI_SETTINGS_READ | `/system/restapi/settings`, `/system/restapi/version`, `/system/restapi/access_list(entry)` | Low | Medium | — | Medium | Planned |
| SYSTEM_HA_SYNC_READ | `/system/hasync` | Low | High | — | Medium | Planned |
| SYSTEM_NOTIFICATIONS_READ | `/system/notifications/email_settings` | Low | High | — | Low | Planned |
| SERVICES_DHCP_READ | `/services/dhcp_server(s)`, `/services/dhcp_server/address_pool(s)`, `/services/dhcp_server/apply`, `/services/dhcp_server/custom_option(s)`, `/services/dhcp_server/static_mapping(s)`, `/services/dhcp_relay` | Medium | High | INTERFACE_CONFIG_READ | High | Planned |
| SERVICES_DNS_RESOLVER_READ | `/services/dns_resolver/access_list(s\|/network(s))`, `/services/dns_resolver/apply`, `/services/dns_resolver/domain_override(s)`, `/services/dns_resolver/host_override(s\|/alias(es))`, `/services/dns_resolver/settings` | Medium | Medium | — | Medium | Planned |
| SERVICES_DNS_FORWARDER_READ | `/services/dns_forwarder/apply`, `/services/dns_forwarder/host_override(s\|/alias(es))` | Low | Medium | — | Low | Planned |
| SERVICES_BIND_READ | `/services/bind/access_list(entries)`, `/services/bind/settings`, `/services/bind/sync/remote_host(s)`, `/services/bind/sync/settings`, `/services/bind/view(s)`, `/services/bind/zone(s)`, `/services/bind/zone/record` | High | Medium | Requires `pfSense-pkg-bind` package | Low | Planned |
| SERVICES_NTP_READ | `/services/ntp/settings`, `/services/ntp/time_server(s)` | Low | Low | — | Low | Planned |
| SERVICES_SSH_READ | `/services/ssh` | Low | Medium | — | Low | Planned |
| SERVICES_CRON_READ | `/services/cron/job(s)` | Low | Low | — | Low | Planned |
| SERVICES_WATCHDOG_READ | `/services/service_watchdog(s)` | Low | Low | — | Low | Planned |
| SERVICES_ACME_READ | `/services/acme/account_key(s\|/registrations)`, `/services/acme/certificate(s)`, `/services/acme/certificate/action`, `/services/acme/certificate/domain`, `/services/acme/certificate/issuances`, `/services/acme/certificate/renewals`, `/services/acme/settings` | High | High | Requires `pfSense-pkg-acme` package | Low | Planned |
| SERVICES_FREERADIUS_READ | `/services/freeradius/client(s)`, `/services/freeradius/eap`, `/services/freeradius/interface(s)`, `/services/freeradius/ldap`, `/services/freeradius/mac(s)`, `/services/freeradius/user(s)` | High | High | Requires `pfSense-pkg-FreeRADIUS` package | Low | Planned |
| SERVICES_HAPROXY_READ | `/services/haproxy/*` (30 endpoints: backends, frontends, actions, acls, certs, errorfiles, logs, etc.) | High | High | Requires `pfSense-pkg-haproxy` package | Low | Planned |
| USER_READ | `/user`, `/users`, `/user/group(s)` | Medium | High | — | High | Planned |
| USER_AUTH_SERVER_READ | `/user/auth_server(s)` | Low | High | USER_READ | Medium | Planned |
| VPN_IPSEC_CONFIG_READ | `/vpn/ipsec/phase1(s)`, `/vpn/ipsec/phase1/encryption(s)`, `/vpn/ipsec/phase2(s)`, `/vpn/ipsec/phase2/encryption(s)`, `/vpn/ipsec/apply` | Medium | High | — | Medium | Planned |
| VPN_OPENVPN_SERVER_READ | `/vpn/openvpn/server(s)` | Medium | High | — | Medium | Planned |
| VPN_OPENVPN_CLIENT_READ | `/vpn/openvpn/client(s)`, `/vpn/openvpn/cso(s)` | Medium | High | — | Medium | Planned |
| VPN_OPENVPN_CLIENT_EXPORT_READ | `/vpn/openvpn/client_export/config(s)` | Medium | High | VPN_OPENVPN_SERVER_READ | Low | Planned |
| VPN_WIREGUARD_READ | `/vpn/wireguard/tunnel(s)`, `/vpn/wireguard/tunnel/address(es)`, `/vpn/wireguard/peer(s)`, `/vpn/wireguard/peer/allowed_ip(s)`, `/vpn/wireguard/settings`, `/vpn/wireguard/apply` | Medium | High | — | Medium | Planned |
| DIAGNOSTICS_ARP_READ | `/diagnostics/arp_table`, `/diagnostics/arp_table/entry` | Low | Medium | — | Medium | Planned |
| DIAGNOSTICS_CONFIG_HISTORY_READ | `/diagnostics/config_history/revision(s)` | Low | High | — | Medium | Planned |
| DIAGNOSTICS_TABLES_READ | `/diagnostics/table(s)` | Low | Medium | — | Low | Planned |
| AUTH_KEYS_READ | `/auth/keys` | Low | High | — | Low | Planned |

Notes:
- Paths are shown relative to `/api/v2` and use `(s)`/`(x|y)` shorthand to
  fold singular/plural or sibling variants of the same resource into one
  cell; the Appendix expands every path individually.
- `Capability.ALIAS_READ` and `Capability.SERVICE_READ` already exist as
  unused enum placeholders in `capabilities.py` (not yet in
  `SUPPORTED_CAPABILITIES_THIS_BUILD`); `FIREWALL_ALIAS_READ` and
  `STATUS_SERVICES_READ` are the natural activations of those placeholders
  and are prioritized accordingly.
- `SERVICES_HAPROXY_READ` is large (30 endpoints) and entirely
  package-dependent (`pfSense-pkg-haproxy` is not installed by default);
  recommend deferring a build/no-build decision until package availability
  and the multi-endpoint manifest question are resolved. Treated as a
  Planned/Low-priority item, flagged as the one candidate for future
  Deferred status rather than moved there outright, since no endpoints are
  confirmed unreachable.

## Recommended implementation order

1. **FIREWALL_ALIAS_READ** and **STATUS_SERVICES_READ** — placeholders
   already exist in the `Capability` enum; lowest-friction next steps.
2. **SYSTEM_INFO_READ** — small, low-sensitivity, high day-to-day value
   (hostname, version, timezone, DNS).
3. **INTERFACE_CONFIG_READ** — natural companion to the already-Done
   `INTERFACE_READ` (status) capability; unblocks `INTERFACE_VIRTUAL_READ`.
4. **FIREWALL_NAT_READ** — high operator value, most-requested visibility
   gap next to firewall rules.
5. **USER_READ** and **SYSTEM_CERTIFICATE_READ** — high sensitivity but
   high audit value; implement once redaction/identifying-field handling
   for account and certificate data has been reviewed.
6. **STATUS_DHCP_LEASES_READ**, **VPN_WIREGUARD_READ**,
   **VPN_IPSEC_CONFIG_READ**, **VPN_OPENVPN_SERVER_READ/CLIENT_READ** —
   VPN and lease visibility, moderate complexity, high sensitivity.
7. Remaining `SERVICES_*` and `DIAGNOSTICS_*` capabilities in priority
   order shown in the table; package-dependent capabilities
   (BIND, ACME, FreeRADIUS, HAProxy) last, gated on confirming the
   corresponding pfSense package is actually installed in the target
   environment.

## Appendix: full endpoint-to-capability mapping (243 endpoints)

Full paths are prefixed with `/api/v2` (omitted above for brevity).

| Capability | Endpoint paths |
|---|---|
| SYSTEM_READ | `/status/system` |
| INTERFACE_READ | `/status/interfaces` |
| GATEWAY_READ | `/routing/gateways`, `/status/gateways` |
| FIREWALL_READ | `/firewall/rules`, `/firewall/states`, `/firewall/states/size`, `/firewall/apply` |
| FIREWALL_ALIAS_READ | `/firewall/alias`, `/firewall/aliases` |
| FIREWALL_SINGLETON_READ | `/firewall/rule`, `/firewall/state` |
| FIREWALL_SCHEDULE_READ | `/firewall/schedule`, `/firewall/schedule/time_range`, `/firewall/schedule/time_ranges`, `/firewall/schedules` |
| FIREWALL_NAT_READ | `/firewall/nat/one_to_one/mapping`, `/firewall/nat/one_to_one/mappings`, `/firewall/nat/outbound/mapping`, `/firewall/nat/outbound/mappings`, `/firewall/nat/outbound/mode`, `/firewall/nat/port_forward`, `/firewall/nat/port_forwards` |
| FIREWALL_VIRTUAL_IP_READ | `/firewall/virtual_ip`, `/firewall/virtual_ip/apply`, `/firewall/virtual_ips` |
| FIREWALL_TRAFFIC_SHAPER_READ | `/firewall/traffic_shaper`, `/firewall/traffic_shaper/limiter`, `/firewall/traffic_shaper/limiter/bandwidth`, `/firewall/traffic_shaper/limiter/bandwidths`, `/firewall/traffic_shaper/limiter/queue`, `/firewall/traffic_shaper/limiter/queues`, `/firewall/traffic_shaper/limiters`, `/firewall/traffic_shaper/queue`, `/firewall/traffic_shaper/queues`, `/firewall/traffic_shapers` |
| FIREWALL_ADVANCED_SETTINGS_READ | `/firewall/advanced_settings` |
| INTERFACE_CONFIG_READ | `/interface`, `/interfaces`, `/interface/available_interfaces`, `/interface/apply` |
| INTERFACE_VIRTUAL_READ | `/interface/vlan`, `/interface/vlans`, `/interface/bridge`, `/interface/bridges`, `/interface/lagg`, `/interface/laggs`, `/interface/group`, `/interface/groups`, `/interface/gre`, `/interface/gres` |
| ROUTING_GATEWAY_GROUP_READ | `/routing/gateway`, `/routing/gateway/default`, `/routing/gateway/group`, `/routing/gateway/groups`, `/routing/gateway/group/priority`, `/routing/gateway/group/priorities`, `/routing/apply` |
| ROUTING_STATIC_ROUTE_READ | `/routing/static_route`, `/routing/static_routes` |
| STATUS_SERVICES_READ | `/status/services` |
| STATUS_CARP_READ | `/status/carp` |
| STATUS_DHCP_LEASES_READ | `/status/dhcp_server/leases` |
| STATUS_LOGS_READ | `/status/logs/auth`, `/status/logs/dhcp`, `/status/logs/firewall`, `/status/logs/openvpn`, `/status/logs/packages/restapi`, `/status/logs/settings`, `/status/logs/system` |
| STATUS_IPSEC_READ | `/status/ipsec/sas`, `/status/ipsec/child_sa`, `/status/ipsec/child_sas` |
| STATUS_OPENVPN_READ | `/status/openvpn/clients`, `/status/openvpn/server/connection`, `/status/openvpn/server/connections`, `/status/openvpn/server/route`, `/status/openvpn/server/routes`, `/status/openvpn/servers` |
| STATUS_WIREGUARD_READ | `/status/wireguard/peers`, `/status/wireguard/tunnels` |
| SYSTEM_INFO_READ | `/system/version`, `/system/hostname`, `/system/timezone`, `/system/dns`, `/system/console`, `/system/webgui/settings` |
| SYSTEM_CERTIFICATE_READ | `/system/certificate`, `/system/certificates`, `/system/certificate_authority`, `/system/certificate_authorities`, `/system/crl`, `/system/crls`, `/system/crl/revoked_certificate` |
| SYSTEM_PACKAGE_READ | `/system/package`, `/system/package/available`, `/system/packages` |
| SYSTEM_TUNABLE_READ | `/system/tunable`, `/system/tunables` |
| SYSTEM_RESTAPI_SETTINGS_READ | `/system/restapi/settings`, `/system/restapi/version`, `/system/restapi/access_list`, `/system/restapi/access_list/entry` |
| SYSTEM_HA_SYNC_READ | `/system/hasync` |
| SYSTEM_NOTIFICATIONS_READ | `/system/notifications/email_settings` |
| SERVICES_DHCP_READ | `/services/dhcp_server`, `/services/dhcp_servers`, `/services/dhcp_server/address_pool`, `/services/dhcp_server/address_pools`, `/services/dhcp_server/apply`, `/services/dhcp_server/custom_option`, `/services/dhcp_server/custom_options`, `/services/dhcp_server/static_mapping`, `/services/dhcp_server/static_mappings`, `/services/dhcp_relay` |
| SERVICES_DNS_RESOLVER_READ | `/services/dns_resolver/access_list`, `/services/dns_resolver/access_lists`, `/services/dns_resolver/access_list/network`, `/services/dns_resolver/access_list/networks`, `/services/dns_resolver/apply`, `/services/dns_resolver/domain_override`, `/services/dns_resolver/domain_overrides`, `/services/dns_resolver/host_override`, `/services/dns_resolver/host_overrides`, `/services/dns_resolver/host_override/alias`, `/services/dns_resolver/host_override/aliases`, `/services/dns_resolver/settings` |
| SERVICES_DNS_FORWARDER_READ | `/services/dns_forwarder/apply`, `/services/dns_forwarder/host_override`, `/services/dns_forwarder/host_overrides`, `/services/dns_forwarder/host_override/alias`, `/services/dns_forwarder/host_override/aliases` |
| SERVICES_BIND_READ | `/services/bind/access_list`, `/services/bind/access_lists`, `/services/bind/access_list/entry`, `/services/bind/access_list/entries`, `/services/bind/settings`, `/services/bind/sync/remote_host`, `/services/bind/sync/remote_hosts`, `/services/bind/sync/settings`, `/services/bind/view`, `/services/bind/views`, `/services/bind/zone`, `/services/bind/zones`, `/services/bind/zone/record` |
| SERVICES_NTP_READ | `/services/ntp/settings`, `/services/ntp/time_server`, `/services/ntp/time_servers` |
| SERVICES_SSH_READ | `/services/ssh` |
| SERVICES_CRON_READ | `/services/cron/job`, `/services/cron/jobs` |
| SERVICES_WATCHDOG_READ | `/services/service_watchdog`, `/services/service_watchdogs` |
| SERVICES_ACME_READ | `/services/acme/account_key`, `/services/acme/account_keys`, `/services/acme/account_key/registrations`, `/services/acme/certificate`, `/services/acme/certificates`, `/services/acme/certificate/action`, `/services/acme/certificate/domain`, `/services/acme/certificate/issuances`, `/services/acme/certificate/renewals`, `/services/acme/settings` |
| SERVICES_FREERADIUS_READ | `/services/freeradius/client`, `/services/freeradius/clients`, `/services/freeradius/eap`, `/services/freeradius/interface`, `/services/freeradius/interfaces`, `/services/freeradius/ldap`, `/services/freeradius/mac`, `/services/freeradius/macs`, `/services/freeradius/user`, `/services/freeradius/users` |
| SERVICES_HAPROXY_READ | all 30 paths under `/services/haproxy/*` (backends, frontends, actions, acls, certs, errorfiles, files, logs, mailer_settings, monitor_endpoints, reason_msgs, settings, and their singular/plural/nested variants) |
| USER_READ | `/user`, `/users`, `/user/group`, `/user/groups` |
| USER_AUTH_SERVER_READ | `/user/auth_server`, `/user/auth_servers` |
| VPN_IPSEC_CONFIG_READ | `/vpn/ipsec/phase1`, `/vpn/ipsec/phase1s`, `/vpn/ipsec/phase1/encryption`, `/vpn/ipsec/phase1/encryptions`, `/vpn/ipsec/phase2`, `/vpn/ipsec/phase2s`, `/vpn/ipsec/phase2/encryption`, `/vpn/ipsec/phase2/encryptions`, `/vpn/ipsec/apply` |
| VPN_OPENVPN_SERVER_READ | `/vpn/openvpn/server`, `/vpn/openvpn/servers` |
| VPN_OPENVPN_CLIENT_READ | `/vpn/openvpn/client`, `/vpn/openvpn/clients`, `/vpn/openvpn/cso`, `/vpn/openvpn/csos` |
| VPN_OPENVPN_CLIENT_EXPORT_READ | `/vpn/openvpn/client_export/config`, `/vpn/openvpn/client_export/configs` |
| VPN_WIREGUARD_READ | `/vpn/wireguard/tunnel`, `/vpn/wireguard/tunnels`, `/vpn/wireguard/tunnel/address`, `/vpn/wireguard/tunnel/addresses`, `/vpn/wireguard/peer`, `/vpn/wireguard/peers`, `/vpn/wireguard/peer/allowed_ip`, `/vpn/wireguard/peer/allowed_ips`, `/vpn/wireguard/settings`, `/vpn/wireguard/apply` |
| DIAGNOSTICS_ARP_READ | `/diagnostics/arp_table`, `/diagnostics/arp_table/entry` |
| DIAGNOSTICS_CONFIG_HISTORY_READ | `/diagnostics/config_history/revision`, `/diagnostics/config_history/revisions` |
| DIAGNOSTICS_TABLES_READ | `/diagnostics/table`, `/diagnostics/tables` |
| AUTH_KEYS_READ | `/auth/keys` |

Total: 51 capability rows, 243 endpoint paths, each counted exactly once.
