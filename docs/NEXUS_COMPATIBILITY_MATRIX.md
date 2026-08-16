# Netgate Nexus / official API — READ-tool compatibility matrix

**Status: research artifact, Phase A only. No code in this repository depends on
this document. Nothing here is wired into the running server.**

This matrix compares every one of the current 42 default-profile MCP READ
tools against the *official* Netgate API schema (`Netgate/pfsense-api`,
`pfapi_openapi.yml`, OpenAPI 3.0.3, `info.version: "1.0"`, description:
"Nexus Multi-instance Management APIs"), fetched directly from
`https://raw.githubusercontent.com/Netgate/pfsense-api/main/pfapi_openapi.yml`
and parsed programmatically (486 paths, 755 operations). This is **not** the
same product as the community `pfSense-pkg-RESTAPI` package this project's
existing backend already uses — it is Netgate's own, Plus-only,
Controller-mediated multi-instance API.

## Methodology and honesty notes

- Every current-side fact (tool names, `Endpoints.path_suffix` values,
  domain model required fields) was re-derived directly from `src/` on
  commit `0ce37ab0c7d4d99421146e4d45085fe8ed6cb467`, not recalled from prior conversation or reports-ai.
- Every Nexus-side fact was extracted by loading the actual schema YAML with
  `pyyaml` and inspecting `paths`/`components.schemas` programmatically —
  not inferred from path names alone.
- **No entry is classified DIRECT.** For every tool where a plausible Nexus
  endpoint exists, deep-enough inspection found at least one genuine
  semantic gap (a required field on the current Pydantic model with no
  confirmed source field in the Nexus schema, an identifier-shape mismatch,
  or a structural difference such as per-interface vs. flat collections).
  Where that inspection was not completed to the same depth, the entry is
  marked ADAPTABLE with confidence noted, not DIRECT.
- UNKNOWN means genuinely insufficient evidence was gathered this pass, not
  "probably unsupported." UNSUPPORTED means a positive search was made and
  no candidate was found.

## Summary

| Classification | Count |
|---|---|
| DIRECT | 0 |
| ADAPTABLE | 32 |
| PARTIAL | 3 |
| UNSUPPORTED | 5 |
| UNKNOWN | 1 |
| LOCAL | 1 |
| **Total** | **42** |

(`system_status` is counted under PARTIAL, not ADAPTABLE — see its row; the
narrative below the table explains the reclassification.)

## Full matrix

| MCP tool | Current endpoint (`Endpoints.*`) | Current method | Candidate Nexus path(s) | Nexus method(s) | Classification | Confidence | Key semantic differences |
|---|---|---|---|---|---|---|---|
| `pfsense_get_system_status` | `SYSTEM_STATUS` (`/status/system`) | GET | `/system/status` | GET | **PARTIAL** | High | Nexus `SystemStatus` schema has no field corresponding to the current model's required `disk_usage: int`, and no `temp_c`/`temp_f` equivalent at all. `ram`/`fram`/`swap`/`fswap` are untyped-unit integers (no documented unit), `cpu` is a string (likely a model name, not a usage percentage) — the current model's `cpu_usage: float` has no confirmed source. `up` is a string of undocumented format. Full reproduction is not possible from this schema as published. |
| `pfsense_get_interface_configs` | `INTERFACES` (`/interfaces`) | GET | `/interfaces` | GET | ADAPTABLE | Medium | `InterfaceSimple` has `ipaddr`/`ipaddrv6`/`mac`/`descr`/`enable` — reasonable config-field overlap. Not schema-diffed field-by-field against the current `InterfaceConfig` model. |
| `pfsense_get_interfaces` | `STATUS_INTERFACES` (`/status/interfaces`) | GET | none confirmed | — | **UNKNOWN** | — | This tool returns live link/status data (`InterfaceStatus`). The `/interfaces` schema found is configuration-shaped (no link/media/up-down field observed); `/system/status/ifstats` was found but not inspected. Insufficient evidence to classify. |
| `pfsense_get_gateways` | `ROUTING_GATEWAYS` (`/routing/gateways`) | GET | `/system/gateways` | GET | ADAPTABLE | Medium | `Gateways.gateways` structure not diffed field-by-field against `GatewayConfig`'s ~20 required fields. |
| `pfsense_get_gateway_status` | `STATUS_GATEWAYS` (`/status/gateways`) | GET | `/system/gateways/status` | GET | ADAPTABLE | Medium-High | `GatewayStatus` schema has `delay`/`stddev`/`loss`/`status` overlapping well with the current model, but has **no `id: int`** or `substatus` field — current model requires both. Gateways in Nexus appear to be identified by `name`/`gateway` (string), not an integer index. |
| `pfsense_get_firewall_rules` | `FIREWALL_RULES` (`/firewall/rules`) | GET | `/firewall/rules/interface`, `/firewall/rules/interface/{interface}` | GET | **PARTIAL** | High | Structural mismatch: current tool returns one flat rule list; Nexus requires enumerating interfaces first, then one call per interface, then aggregating — a real multi-call transformation, not just field renaming. |
| `pfsense_get_firewall_states` | `FIREWALL_STATES` (`/firewall/states`) | GET | `/diag/states` | GET (also DELETE — do not use) | ADAPTABLE | Low-Medium | Endpoint exists; response schema not inspected this pass. |
| `pfsense_get_firewall_states_size` | `FIREWALL_STATES_SIZE` (`/firewall/states/size`) | GET | none found | — | UNSUPPORTED | High (positive search) | No state-table size/count endpoint found anywhere in the 486-path schema. |
| `pfsense_get_firewall_apply_status` | `FIREWALL_APPLY_STATUS` (`/firewall/apply`) | GET | `/system/config/dirty` | GET | ADAPTABLE | Medium | Real scope difference: Nexus's dirty-state check is system-wide across all "subsystems," not scoped to the firewall subsystem the way the current endpoint is. |
| `pfsense_get_firewall_aliases` | `FIREWALL_ALIASES` (`/firewall/aliases`) | GET | `/aliases` | GET | ADAPTABLE | Medium | Endpoint exists (`maxvalues` query param caps values per alias); full field diff against `FirewallAlias` not completed. |
| `pfsense_get_service_status` | `STATUS_SERVICES` (`/status/services`) | GET | `/services/status` | GET | ADAPTABLE | Low-Medium | Endpoint exists; response schema not inspected this pass. |
| `pfsense_get_system_version` | `SYSTEM_VERSION` (`/system/version`) | GET | embedded in `/system/status` (`SystemStatus.rev`, `.osver`) | GET | ADAPTABLE | Medium | No standalone version endpoint; version-like fields exist but are untyped strings nested in the broader status object, requiring extraction. |
| `pfsense_get_firewall_nat_port_forwards` | `FIREWALL_NAT_PORT_FORWARDS` | GET | `/firewall/nat/port-forward` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_firewall_nat_outbound_mode` | `FIREWALL_NAT_OUTBOUND_MODE` | GET | `/firewall/nat/outbound` | GET (note: `/firewall/nat/outbound/mode` is **POST-only** in Nexus — a write/apply action, not a mode-read) | ADAPTABLE | Low | The current tool reads a mode value; whether Nexus's GET on `/firewall/nat/outbound` includes a `mode` field was not confirmed. |
| `pfsense_get_users` | `USERS` (`/users`) | GET | `/system/users` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_system_certificates` | `SYSTEM_CERTIFICATES` | GET | `/system/certificates` | GET | ADAPTABLE | Medium | Nexus has a notably richer certificate surface (export-cert/export-key/export-p12/renew as separate operations); base collection endpoint exists. |
| `pfsense_get_user_groups` | `USER_GROUPS` (`/user/groups`) | GET | `/system/users/group` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_dhcp_leases` | `STATUS_DHCP_LEASES` | GET | `/services/dhcp/leases` | GET | ADAPTABLE | Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_dhcp_static_mappings` | `DHCP_SERVER_STATIC_MAPPINGS` | GET | `/services/dhcp-server/{version}/static-mappings/{iface}` | GET | **PARTIAL** | High | Structural mismatch: requires iterating `{version}` (v4/v6) × `{iface}` and aggregating, vs. the current single flat list. |
| `pfsense_get_dhcp_servers` | `DHCP_SERVERS` | GET | `/services/dhcp-server`, `/services/dhcp-server/{version}/interface` | GET | ADAPTABLE | Low-Medium | Endpoint exists; shape not diffed. |
| `pfsense_get_interface_bridges` | `INTERFACE_BRIDGES` | GET | `/interfaces/bridge` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_carp_status` | `STATUS_CARP` | GET | `/services/carp/status` | GET | ADAPTABLE | Medium | Endpoint exists with a clear name match; not schema-diffed. |
| `pfsense_get_system_restapi_settings` | `SYSTEM_RESTAPI_SETTINGS` | GET | none | — | UNSUPPORTED | High | This tool exposes settings for the community `pfSense-pkg-RESTAPI` package specifically. That package/concept does not exist under Nexus's own, separate auth/API model. |
| `pfsense_get_system_hasync` | `SYSTEM_HASYNC` | GET | none found | — | UNSUPPORTED | High (positive search) | Searched for `pfsync`/`hasync`/`sync peer`/`failover` — no match. CARP *status* exists (`/services/carp/status`, `/services/carp/enabled`) but the HA-sync *configuration* (sync interface, sync peer IP) this tool exposes was not found. This is also the exact endpoint whose privilege (`api-v2-system-hasync-get`) is one of the 4 privileges the existing Tier1 scoped credential holds — see the security note below. |
| `pfsense_get_dns_resolver_host_overrides` | `DNS_RESOLVER_HOST_OVERRIDES` | GET | `/services/dnsresolver` (likely a sub-field) | GET | ADAPTABLE | Low | No standalone host-overrides endpoint found; likely nested inside the general resolver-settings object — not confirmed. |
| `pfsense_get_dns_resolver_settings` | `DNS_RESOLVER_SETTINGS` | GET | `/services/dnsresolver` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_arp_table` | `DIAGNOSTICS_ARP_TABLE` | GET | `/diag/arp` | GET (also DELETE — do not use) | ADAPTABLE | Medium | Clear name/purpose match; not schema-diffed. |
| `pfsense_get_firewall_traffic_shaper_limiters` | `FIREWALL_TRAFFIC_SHAPER_LIMITERS` | GET | `/firewall/traffic-shaper/limiter` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_firewall_advanced_settings` | `FIREWALL_ADVANCED_SETTINGS` | GET | `/system/advanced/firewall` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_system_packages` | `SYSTEM_PACKAGES` | GET | `/system/package/installed` | GET | ADAPTABLE | Medium-High | `Package` schema (`name`, `version`, `installed_version`, `available_version`, `update_available`, `dependencies`) overlaps well conceptually with the current `SystemPackage` model; not diffed field-by-field. |
| `pfsense_get_system_tunables` | `SYSTEM_TUNABLES` | GET | `/system/advanced/sysctl` | GET | ADAPTABLE | Medium | Good name/purpose match (pfSense "tunables" are sysctl values); not schema-diffed. |
| `pfsense_get_email_notification_settings` | `SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS` | GET | `/system/advanced/notifications` | GET | ADAPTABLE | Medium | `AdvNotifications.notifications` contains `smtp*` fields but is a combined object also covering Pushover/Slack/Telegram/cert-expiry notification — requires extracting the SMTP-only subset. |
| `pfsense_get_bind_settings` | `BIND_SETTINGS` | GET | none confirmed | — | **UNKNOWN** | — | The current model's fields (`bind_dnssec_validation`, `bind_forwarder`, `bind_forwarder_ips`, `bind_custom_options`) suggest literal BIND-DNS-server configuration. Nexus has `/services/dnsmasq` and `/services/coredns` (pfSense's actual built-in resolver/forwarder options) but no confirmed BIND-specific endpoint, and the dnsmasq/coredns schemas were not inspected to check for overlap. Not classified UNSUPPORTED because the search was not exhaustive enough to be a confident negative. |
| `pfsense_get_ntp_settings` | `NTP_SETTINGS` | GET | `/services/ntp` | GET | ADAPTABLE | Medium | `ServicesNtpConfig.settings` has a clear overlapping field set (`enable`, `servers`, `ntpmaxpeers`, etc.). |
| `pfsense_get_ntp_time_servers` | `NTP_TIME_SERVERS` | GET | embedded in `/services/ntp` (`settings.servers`) | GET | ADAPTABLE | Medium | No standalone endpoint; time servers are a field within the general NTP settings object, requiring extraction. |
| `pfsense_get_ssh_settings` | `SERVICES_SSH` | GET | embedded in `/system/advanced/admin` (`SystemAdvAdmin`: `enablesshd`, `sshport`, `sshdkeyonly`, `sshdagentforwarding`) | GET | ADAPTABLE | Medium | No standalone SSH endpoint; SSH config is a subset of the broader "admin access" settings object. |
| `pfsense_get_cron_jobs` | `CRON_JOBS` | GET | none found | — | UNSUPPORTED | High (positive search) | No cron/scheduled-task endpoint found anywhere in the schema. |
| `pfsense_get_acme_settings` | `ACME_SETTINGS` | GET | `/services/acme` | GET | ADAPTABLE | Medium | Endpoint exists (also has richer per-account-key/per-cert sub-resources); base object not schema-diffed. |
| `pfsense_get_freeradius_eap` | `FREERADIUS_EAP` | GET | `/ports/freeradius/eap` | GET | ADAPTABLE | Low-Medium | Endpoint exists under the `/ports/` namespace (suggesting a package/plugin-dependent feature in Nexus too); not schema-diffed. |
| `pfsense_get_diagnostics_tables` | `DIAGNOSTICS_TABLES` | GET | `/diag/tables`, `/diag/tables/{table_name}` | GET | ADAPTABLE | Medium | Clear name/purpose match; not schema-diffed. |
| `pfsense_get_auth_keys` | `AUTH_KEYS` | GET | none | — | UNSUPPORTED | High | Fundamentally different auth model: Nexus authenticates via `POST /login` → JWT access + refresh token (username/password + optional 2FA), not per-user long-lived API keys. There is no concept in this schema equivalent to "list a user's API keys." |
| `pfsense_mcp_info` | n/a (local process introspection) | n/a | n/a | n/a | **LOCAL** | — | No upstream call of any kind; unaffected by backend choice. |

## Notable cross-cutting findings (apply to many rows above)

1. **Identifier-shape mismatch.** The current domain models and the Tier1
   execution-target layer (`tier1/transport_target.py::ResolvedTransportTarget.numeric_locator: int`)
   assume pfSense-REST-API-style integer indices. Every Nexus identifier
   inspected this pass is either a string name (`GatewayStatus` has no
   `id`, only `name`/`gateway`), a `device_id` string (MIM device registry),
   or a `refid` string (certificates) — no confirmed integer-index
   identifier scheme anywhere in the Nexus schema. This is a real
   architectural incompatibility for the WRITE side, not just a READ
   nuance — see Phase 4/ADR.
2. **No pagination.** Three representative large-collection endpoints
   (`/services/dhcp/leases`, `/system/users`, `/firewall/rules/interface/{interface}`)
   have zero pagination parameters. Collections appear to be returned in
   full.
3. **Two-value HTTP status model.** All 755 operations in the schema use
   only `200` and `400` as documented response codes — no distinct
   401/403/404/500. Error classification (auth failure vs. not-found vs.
   validation) would have to come from the JSON body's `Error.errcode`/
   `errlevel` fields, not the HTTP status code the current `RestApiClient`
   relies on (`errors.py` maps 401/403 → `PfSenseAuthError` by status code
   today).
4. **JWT/session auth, not a static API key.** `POST /login` with
   base64-encoded username/password (+ optional `secondfactor`) returns a
   JWT access token plus a refresh-token cookie, refreshable via
   `POST /login/refresh`. This does not map onto the current
   `PFSENSE_API_KEY_FILE` / static-credential model at all — a Nexus
   backend would need its own credential lifecycle (login + periodic
   refresh), not a drop-in swap of the API key file.
