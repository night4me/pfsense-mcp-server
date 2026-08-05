# Project Checkpoint

Generated: 2026-08-05T22:05:11.594762+00:00

## Project status

- Current branch: `main`
- Latest commit hash: `a9a6d0d773282960cd3fd91c2c8c1b7068234d7b`
- Latest commit message: Add read-only DHCP static mapping capability
- Git status: dirty
- pytest totals: 665 passed, 18 skipped
- make quick: passed
- make validate: passed

## Backlog progress

- Completed capabilities: 4
- Remaining capabilities: 47
- Blocked capabilities: 0

Remaining capabilities (priority order):

- FIREWALL_ALIAS_READ (High)
- FIREWALL_NAT_READ (High)
- INTERFACE_CONFIG_READ (High)
- STATUS_SERVICES_READ (High)
- STATUS_DHCP_LEASES_READ (High)
- SYSTEM_INFO_READ (High)
- SYSTEM_CERTIFICATE_READ (High)
- SERVICES_DHCP_READ (High)
- USER_READ (High)
- FIREWALL_SCHEDULE_READ (Medium)
- FIREWALL_VIRTUAL_IP_READ (Medium)
- INTERFACE_VIRTUAL_READ (Medium)
- ROUTING_GATEWAY_GROUP_READ (Medium)
- ROUTING_STATIC_ROUTE_READ (Medium)
- STATUS_CARP_READ (Medium)
- STATUS_LOGS_READ (Medium)
- STATUS_IPSEC_READ (Medium)
- STATUS_OPENVPN_READ (Medium)
- STATUS_WIREGUARD_READ (Medium)
- SYSTEM_RESTAPI_SETTINGS_READ (Medium)
- SYSTEM_HA_SYNC_READ (Medium)
- SERVICES_DNS_RESOLVER_READ (Medium)
- USER_AUTH_SERVER_READ (Medium)
- VPN_IPSEC_CONFIG_READ (Medium)
- VPN_OPENVPN_SERVER_READ (Medium)
- VPN_OPENVPN_CLIENT_READ (Medium)
- VPN_WIREGUARD_READ (Medium)
- DIAGNOSTICS_ARP_READ (Medium)
- DIAGNOSTICS_CONFIG_HISTORY_READ (Medium)
- FIREWALL_SINGLETON_READ (Low)
- FIREWALL_TRAFFIC_SHAPER_READ (Low)
- FIREWALL_ADVANCED_SETTINGS_READ (Low)
- SYSTEM_PACKAGE_READ (Low)
- SYSTEM_TUNABLE_READ (Low)
- SYSTEM_NOTIFICATIONS_READ (Low)
- SERVICES_DNS_FORWARDER_READ (Low)
- SERVICES_BIND_READ (Low)
- SERVICES_NTP_READ (Low)
- SERVICES_SSH_READ (Low)
- SERVICES_CRON_READ (Low)
- SERVICES_WATCHDOG_READ (Low)
- SERVICES_ACME_READ (Low)
- SERVICES_FREERADIUS_READ (Low)
- SERVICES_HAPROXY_READ (Low)
- VPN_OPENVPN_CLIENT_EXPORT_READ (Low)
- DIAGNOSTICS_TABLES_READ (Low)
- AUTH_KEYS_READ (Low)

## Current work

Modified files:
- Makefile
Untracked files:
- .checkpoint/
- CHECKPOINT.md
- scripts/checkpoint.py
- tests/test_checkpoint.py

## Resume prompt

```
Continue from the current repository state.

Read CHECKPOINT.md.

Resume with the highest-priority remaining READ capability from READ_BACKLOG.md.

Do not rebuild tooling unless a concrete capability-blocking defect is encountered.

Continue following the throughput-first policy.
```

## Engineering handoff

- Latest completed capability (by commit): Add read-only DHCP static mapping capability
- Latest MCP tool count: 19
- Known blocked endpoints/capabilities: none
- Next recommended capability: FIREWALL_ALIAS_READ
- Outstanding issues requiring attention:
  - docs/READ_BACKLOG.md Status column appears stale: 14 capabilities are actually supported in capabilities.py, but only 4 rows are marked Done in the backlog doc. Capability names may also differ between the doc and the real Capability enum (e.g. historical naming changes) — treat 'next_capability' as a suggestion to verify, not a guarantee.
- Current verification status: pytest=ok, make quick=passed, make validate=passed
