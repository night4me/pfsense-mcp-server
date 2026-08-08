# Writable endpoint risk matrix

Status: study only; no endpoint is allow-listed or authorized.

## Source and method

This inventory was generated from every endpoint class declaring POST, PUT,
PATCH, or DELETE in the public pfrest endpoint source at commit
`805c7f0cfd4b50ae34dc4295635b7b1d823b1f75` (reviewed 2026-08-08).
The package is an independent community API, not a Netgate-supported interface.
Source declarations are discovery evidence, not sufficient OpenAPI or appliance
verification. Every future candidate must be compared with the exact disposable
lab appliance's generated OpenAPI document and behavior before an allow-list
entry is proposed.

The inventory contains 240 writable endpoint classes. Ratings are
conservative domain-level triage: `Critical` is excluded from early tiers,
`High` requires endpoint-specific evidence, and starred rows are narrow-field
studies only—the broad upstream endpoint is not recommended as-is.

## Complete inventory

| Endpoint | Methods | Risk | Rollback | Verification | Blast radius | Candidate tier | Decision |
|---|---|---|---|---|---|---|---|
| `/api/v2/auth/jwt` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/auth/key` | POST/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/auth/keys` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/diagnostics/arp_table` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/diagnostics/arp_table/entry` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/diagnostics/command_prompt` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/diagnostics/config_history/revision` | DELETE | High | Hard | Weak | Operational | Defer | Diagnostic action or destructive runtime state |
| `/api/v2/diagnostics/config_history/revisions` | DELETE | High | Hard | Weak | Operational | Defer | Diagnostic action or destructive runtime state |
| `/api/v2/diagnostics/halt_system` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/diagnostics/ping` | POST | Medium | Not applicable | Observable action | Low/network probe | Action-only | Not a configuration mutation; separate abuse review |
| `/api/v2/diagnostics/reboot` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/diagnostics/table` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/firewall/advanced_settings` | PATCH | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/alias` | POST/PATCH/DELETE | High* | Deterministic for description-only | Strong via existing READ | Policy-dependent | T1 candidate | Typed description-only PATCH; address/type forbidden |
| `/api/v2/firewall/aliases` | PUT/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/apply` | POST | Critical | No direct rollback | Indirect | Service/network-wide | Exclude early tiers | Apply/reload is a compound side effect |
| `/api/v2/firewall/nat/one_to_one/mapping` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/nat/one_to_one/mappings` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/nat/outbound/mapping` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/nat/outbound/mappings` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/nat/outbound/mode` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/nat/port_forward` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/nat/port_forwards` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/rule` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/rules` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/schedule` | POST/PATCH/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/schedule/time_range` | POST/PATCH/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/schedule/time_ranges` | DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/schedules` | PUT/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/state` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/firewall/states` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/firewall/states/size` | PATCH | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/firewall/traffic_shaper` | POST/PATCH/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/limiter/bandwidth` | POST/PATCH/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/limiter/bandwidths` | DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/limiter` | POST/PATCH/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/limiter/queue` | POST/PATCH/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/limiter/queues` | DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/limiters` | PUT | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/queue` | POST/PATCH/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shaper/queues` | DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/traffic_shapers` | PUT/DELETE | High | Complex | Moderate | Traffic policy | Defer | Firewall semantics and dependent reload |
| `/api/v2/firewall/virtual_ip/apply` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/virtual_ip` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/firewall/virtual_ips` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/graphql` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/apply` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/bridge` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/gre` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/gres` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/group` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/groups` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/lagg` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/laggs` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/vlan` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface/vlans` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interface` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/interfaces` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/apply` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/gateway/default` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/gateway` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/gateway/group` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/gateway/group/priorities` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/gateway/group/priority` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/gateway/groups` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/gateways` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/static_route` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/routing/static_routes` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/services/acme/account_key` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/account_key/register` | POST | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/account_keys` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/certificate/action` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/certificate/domain` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/certificate` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/certificate/issue` | POST | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/certificate/renew` | POST | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/certificates` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/acme/settings` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/access_list` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/access_list/entries` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/access_list/entry` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/access_lists` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/settings` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/sync/remote_host` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/sync/remote_hosts` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/sync/settings` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/view` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/views` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/zone` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/zone/record` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/bind/zones` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/cron/job` | POST/PATCH/DELETE | High | Varies | Moderate | Service-wide | Defer | Service restart/dependency risk |
| `/api/v2/services/cron/jobs` | PUT/DELETE | High | Varies | Moderate | Service-wide | Defer | Service restart/dependency risk |
| `/api/v2/services/dhcp_relay` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server/address_pool` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server/address_pools` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server/apply` | POST | Critical | No direct rollback | Indirect | Service/network-wide | Exclude early tiers | Apply/reload is a compound side effect |
| `/api/v2/services/dhcp_server/backend` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server/custom_option` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server/custom_options` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server/static_mapping` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_server/static_mappings` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dhcp_servers` | PUT | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_forwarder/apply` | POST | Critical | No direct rollback | Indirect | Service/network-wide | Exclude early tiers | Apply/reload is a compound side effect |
| `/api/v2/services/dns_forwarder/host_override/alias` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_forwarder/host_override/aliases` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_forwarder/host_override` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_forwarder/host_overrides` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/access_list` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/access_list/network` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/access_list/networks` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/access_lists` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/apply` | POST | Critical | No direct rollback | Indirect | Service/network-wide | Exclude early tiers | Apply/reload is a compound side effect |
| `/api/v2/services/dns_resolver/domain_override` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/domain_overrides` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/host_override/alias` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/host_override/aliases` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/host_override` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/host_overrides` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/dns_resolver/settings` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/client` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/clients` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/eap` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/interface` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/interfaces` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/ldap` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/mac` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/macs` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/user` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/freeradius/users` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/apply` | POST | Critical | No direct rollback | Indirect | Service/network-wide | Exclude early tiers | Apply/reload is a compound side effect |
| `/api/v2/services/haproxy/backend/acl` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend/acls` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend/action` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend/actions` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend/error_file` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend/errorfiles` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend/server` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backend/servers` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/backends` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/file` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/files` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/acl` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/acls` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/action` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/actions` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/address` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/addresses` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/certificate` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/certificates` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/error_file` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontend/error_files` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/frontends` | PUT/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/settings/dns_resolver` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/settings/dns_resolvers` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/settings/email_mailer` | POST/PATCH/DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/settings/email_mailers` | DELETE | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/haproxy/settings` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/ntp/settings` | PATCH | High | Varies | Moderate | Service-wide | Defer | Service restart/dependency risk |
| `/api/v2/services/ntp/time_server` | POST/PATCH/DELETE | High | Varies | Moderate | Service-wide | Defer | Service restart/dependency risk |
| `/api/v2/services/ntp/time_servers` | PUT/DELETE | High | Varies | Moderate | Service-wide | Defer | Service restart/dependency risk |
| `/api/v2/services/ssh` | PATCH | High | Complex | Moderate | Core service/auth | Defer | Service interruption or security dependency |
| `/api/v2/services/service_watchdog` | POST/PATCH/DELETE | High | Varies | Moderate | Service-wide | Defer | Service restart/dependency risk |
| `/api/v2/services/service_watchdogs` | PUT/DELETE | High | Varies | Moderate | Service-wide | Defer | Service restart/dependency risk |
| `/api/v2/services/wake_on_lan/send` | POST | Medium | Impossible | Delivery unprovable | Low external side effect | Reject first Tier 1 | Irreversible packet emission |
| `/api/v2/status/carp` | PATCH | High | Varies | Moderate | Operational | Defer | Runtime control/status mutation |
| `/api/v2/status/dhcp_server/leases` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/status/logs/settings` | PATCH | High | Varies | Moderate | Operational | Defer | Runtime control/status mutation |
| `/api/v2/status/openvpn/server/connection` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/status/openvpn/server/connections` | DELETE | High | Non-deterministic | Transient state only | Operational | Defer | Runtime-state deletion is not safely restorable |
| `/api/v2/status/service` | POST | High | Varies | Moderate | Operational | Defer | Runtime control/status mutation |
| `/api/v2/system/crl` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/crl/revoked_certificate` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/crls` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate_authorities` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate_authority` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate_authority/generate` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate_authority/renew` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate/generate` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate/pkcs12/export` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate/renew` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate/signing_request` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificate/signing_request/sign` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/certificates` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/console` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/dns` | PATCH | High | Varies | Moderate | System-wide | Defer | Global system configuration |
| `/api/v2/system/enum` | POST | High | Varies | Moderate | System-wide | Defer | Global system configuration |
| `/api/v2/system/hasync` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/hostname` | PATCH | High | Varies | Moderate | System-wide | Defer | Global system configuration |
| `/api/v2/system/notifications/email_settings` | PATCH | High | Varies | Moderate | System-wide | Defer | Global system configuration |
| `/api/v2/system/package` | POST/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/packages` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/restapi/access_list` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/restapi/access_list/entry` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/restapi/settings` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/restapi/settings/sync` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/restapi/version` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/timezone` | PATCH | High | Varies | Moderate | System-wide | Defer | Global system configuration |
| `/api/v2/system/tunable` | POST/PATCH/DELETE | High* | Deterministic for description-only | Strong via existing READ | System-wide if scope escapes | T1 conditional | Description-only after lab proof; value/name forbidden |
| `/api/v2/system/tunables` | PUT/DELETE | High | Varies | Moderate | System-wide | Defer | Global system configuration |
| `/api/v2/system/update` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/system/webgui/settings` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/user/auth_server` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/user/auth_servers` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/user` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/user/group` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/user/groups` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/users` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/apply` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase1/encryption` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase1/encryptions` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase1` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase1s` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase2/encryption` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase2/encryptions` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase2` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/ipsec/phase2s` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/cso` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/csos` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/client` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/client_export/config` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/client_export/configs` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/client_export` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/clients` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/server` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/openvpn/servers` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/apply` | POST | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/peer/allowed_ip` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/peer/allowed_ips` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/peer` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/peers` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/settings` | PATCH | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/tunnel/address` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/tunnel/addresses` | DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/tunnel` | POST/PATCH/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |
| `/api/v2/vpn/wireguard/tunnels` | PUT/DELETE | Critical | Hard/global | Hard | Lockout/appliance-wide | Exclude early tiers | High-risk domain or generic/bulk mutation |

## Lowest-risk configuration candidates

### 1. Firewall alias description-only PATCH — preferred study

- Natural identity: immutable alias `name`; numeric `id` is a transient locator.
- Existing verified READ dependency can locate exactly one alias and capture the
  full pre-state/fingerprint.
- The capability-specific request model would permit only `descr`; alias type,
  addresses, details, name, placement, apply controls, and bulk operations stay
  forbidden.
- Rollback restores only the prior description after identity/fingerprint and
  unrelated-field conflict checks.
- Residual risk: the upstream endpoint is broadly capable and alias objects can
  affect policy. Disposable-lab proof must show partial PATCH does not rewrite,
  reorder, apply, or normalize unrelated fields.

### 2. System tunable description-only PATCH — conditional fallback

- Natural identity: immutable tunable name; numeric index is transient.
- Existing verified READ dependency supports snapshot and read-back.
- Only `descr` could be accepted; tunable name/value, create/delete, bulk and
  apply behavior remain forbidden.
- Residual risk is higher because the endpoint governs system-level settings.
  It is rejected unless the lab proves description-only PATCH cannot touch the
  value or trigger runtime changes.

No third candidate currently meets the combination of verified READ dependency,
stable identity, deterministic rollback, no credential effect, and narrow blast
radius. Diagnostic actions are not suitable substitutes because irreversible or
transient actions do not exercise the Recovery Contract safely.

## Explicitly excluded early domains

Firewall rules/NAT/virtual IPs, interfaces, gateways/routing, users/authentication,
certificates/keys, VPN, generic GraphQL, package/update, reboot/halt/command
execution, HA sync, DNS/DHCP/BIND/FreeRADIUS/HAProxy, and bulk endpoints are not
first-capability candidates. API availability does not reduce their lockout,
service, credential, ordering, dependency, or rollback risks.
