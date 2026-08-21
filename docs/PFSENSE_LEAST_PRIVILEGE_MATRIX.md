# pfSense least-privilege matrix — READ and WRITE

**Status: does not authorize provisioning, user creation, or privilege
assignment against any pfSense appliance.** Companion data to
[`ADR-033`](adr/ADR-033-pfsense-least-privilege-bootstrap-architecture.md),
which covers the bootstrap architecture this matrix feeds. See that ADR
for the full design; this document is the raw evidence table plus its
derivation methodology.

**2026-08-20 — outbound-NAT/1:1-NAT mappings live-verified and registered**:
`PfSenseClient.get_firewall_nat_outbound_mappings()`/
`get_firewall_nat_one_to_one_mappings()`, their models, and their
`Endpoints` entries (`FIREWALL_NAT_OUTBOUND_MAPPINGS`/`FIREWALL_NAT_ONE_
TO_ONE_MAPPINGS`) were added offline (2026-08-20 earlier this same day,
derived from the pinned v2.10 OpenAPI schema) and deliberately held back
from `tools/registry.py`/`KNOWN_READ_TOOL_NAMES` until live-verified,
per `tests/test_public_contract.py::test_public_contract_is_complete_
and_security_preserving`'s requirement that every *registered* tool's
endpoint be `verified=True`. Owner then authorized a narrowly-scoped
live production READ verification of exactly these two endpoints: both
GETs succeeded against the production appliance (pfSense Plus
26.07-RELEASE) with zero configured mappings in either category at
verification time. Field-level type/nullability compatibility was
confirmed via an exact, byte-for-byte match between the live OpenAPI
schema's `OutboundNATMapping`/`OneToOneNATMapping` components (and both
endpoints' full "Allowed privileges" description text) and the pinned
v2.10 reference this project's models were already derived from — not
by parsing a live instance, since none exist on the target appliance.
Both `Endpoints` entries are now `verified=True`; both tools are now
registered. **41 READ / 42 combined become 43 READ / 44 combined**
throughout this document as of this pass.

**2026-08-20 — interface VLANs / static routes LAB-verified and
registered** (READ Expansion phase, offline discovery-audit P0
candidates): `PfSenseClient.get_interface_vlans()`/
`get_routing_static_routes()`, their models, and their `Endpoints`
entries (`INTERFACE_VLANS`/`ROUTING_STATIC_ROUTES`) were added offline
earlier the same day, derived from the pinned v2.10 OpenAPI schema, and
held back from `tools/registry.py` until live-verified. Owner then
authorized READ-only verification against the **LAB** appliance
(`https://pfsense-test.lab.invalid`, pfSense CE 2.8.1-RELEASE — a
distinct identity from production, confirmed before any request).
The LAB's REST API package reported version v2.10 — an exact,
byte-for-byte schema match (267/267 paths) against the pinned
reference these models were derived from. Both typed GETs succeeded
(HTTP 200, correct `{"data": [...]}` envelope) with zero configured
VLANs/static routes on the LAB appliance at verification time —
`ENDPOINT_VERIFIED`, not `FIELD_MODEL_LIVE_VERIFIED` (no populated
object to exercise field parsing); field-type compatibility is backed
by the schema-component match above, the same method already
established for the NAT mappings. Both `Endpoints` entries are now
`verified=True`; both tools are now registered. **43 READ / 44
combined become 45 READ / 46 combined** throughout this document as of
this pass.

**2026-08-20 — interface groups / firewall schedules / REST API version
LAB-verified and registered** (READ Expansion phase, Batch 2 —
zero-redaction P0 candidates): `PfSenseClient.get_interface_groups()`/
`get_firewall_schedules()`/`get_system_restapi_version()`, their
models, and their `Endpoints` entries (`INTERFACE_GROUPS`/
`FIREWALL_SCHEDULES`/`SYSTEM_RESTAPI_VERSION`) were implemented and
LAB-verified in the same pass as the interface-VLAN/static-route
addition above, against the same LAB appliance. `interface/groups` and
`firewall/schedules` returned zero configured objects
(`ENDPOINT_VERIFIED` only). `system/restapi/version` returned a fully
populated singleton object — `FIELD_MODEL_LIVE_VERIFIED` — which also
confirmed `install_version` is genuinely absent from the live response
(not merely null), so that field is modeled as optional rather than
required. All three `Endpoints` entries are now `verified=True`; all
three tools are now registered. **45 READ / 46 combined become 48
READ / 49 combined** throughout this document as of this pass.

**2026-08-20 — firewall virtual IPs / certificate authorities
LAB-verified and registered** (READ Expansion phase, Batch 3 —
redaction-bearing P0 candidates): `PfSenseClient.get_firewall_virtual_ips()`/
`get_system_certificate_authorities()`, their models, and their
`Endpoints` entries (`FIREWALL_VIRTUAL_IPS`/
`SYSTEM_CERTIFICATE_AUTHORITIES`) were implemented and LAB-verified
against the same LAB appliance. Both candidates carry a confirmed
secret field in the pinned schema (`VirtualIP.password`, the CARP
shared advertisement secret; `CertificateAuthority.prv`, the CA
private key) — both are **never modeled at all**, mirroring the
already-shipped `SystemCertificate` model's own established treatment
of the identical `prv` distinction, not merely redacted behind a flag.
`firewall/virtual_ips` returned zero configured objects
(`ENDPOINT_VERIFIED` only). `system/certificate_authorities` returned
one real, populated object — the LAB's own internal CA —
`FIELD_MODEL_LIVE_VERIFIED`; the parsed model had no `prv` attribute
at all, proven by construction rather than by inspecting and discarding
a captured value. Both `Endpoints` entries are now `verified=True`;
both tools are now registered. **48 READ / 49 combined become 50
READ / 51 combined** throughout this document as of this pass.

**2026-08-21 — IPsec SA/child-SA status LAB-verified and registered**
(P1 Batch A, partial — operational/status value): the LAB appliance was
upgraded to pfSense CE 2.9.0-RELEASE (FreeBSD 16.0-CURRENT,
`pfSense-pkg-RESTAPI` v2.10 reinstalled, same 267-path schema) ahead of
this batch; a required pre-batch regression check of all 51 existing
public tools found and fixed 2 nullability compatibility issues
(`DhcpServer`, `DnsResolverSettings` — see `CHANGELOG.md`), unrelated to
this batch's own candidates. `PfSenseClient.get_status_ipsec_sas()`/
`get_status_ipsec_child_sas()`, their models, and their `Endpoints`
entries (`STATUS_IPSEC_SAS`/`STATUS_IPSEC_CHILD_SAS`) were implemented
and LAB-verified against the upgraded LAB appliance — both returned
zero configured SAs (`ENDPOINT_VERIFIED` only). `IPsecSaStatus.child_sas`
is schema-confirmed to embed full `IPsecChildSaStatus` objects and is
constructed through that model's own `from_api()` for every nested
item, not passed through as a raw dict. `local_host`/`remote_host`/
`local_id`/`remote_id` (on `IPsecSaStatus`) and `local_ts`/`remote_ts`
(on `IPsecChildSaStatus`, including within nested `child_sas` items)
are redacted by default. Both `Endpoints` entries are now
`verified=True`; both tools are now registered. **50 READ / 51
combined become 52 READ / 53 combined** throughout this document as of
this pass.

The same batch also implemented `status/wireguard/tunnels`/
`status/wireguard/peers` (`WireGuardTunnelStatus`/`WireGuardPeerStatus`
models, offline-tested) but LAB verification is **blocked**: this LAB
does not have `pfSense-pkg-WireGuard` installed (HTTP 404,
`response_id=MODEL_MISSING_REQUIRED_PACKAGE`, observed directly).
Installing the package would be a LAB environment mutation, outside
this project's non-destructive READ-only LAB authorization — left
`verified=False` and unregistered pending a separate owner decision, not
worked around. `WireGuardPeerStatus.preshared_key` is confirmed present
in the schema (in the *status* object, not merely config) and is
**never modeled at all**, matching the `VirtualIP.password`/
`CertificateAuthority.prv` precedent — this exclusion is independent of,
and unaffected by, the verification blocker.
`WireGuardTunnelStatus.peers` is schema-confirmed to embed full
`WireGuardPeerStatus` objects; it is constructed through that model's
own `from_api()` for every nested item specifically so the
`preshared_key` exclusion holds for the nested case too (a raw-dict
passthrough there would have leaked it).

**Implementation Phase B (2026-08-17)**: every value below is now
reproduced by real, tested, pure production code —
`src/pfsense_mcp/security_privileges.py`'s
`read_profile_requirements()`/`write_protected_profile_requirements()`
plus `resolve_privilege()`'s schema+source cross-check — rather than
being a hand-maintained table that could silently drift from the actual
codebase. This document's own values remain the regression evidence
those functions are tested against
(`tests/test_security_privileges.py`), not a second, independent source
of truth.

**Implementation Phase C (2026-08-17)**: this document's values are now
also the exact target privilege set `src/pfsense_mcp/
security_bootstrap_engine.py`'s `provision_service_account()` grants —
never a second, hard-coded copy; the engine calls the same
`read_profile_requirements()`/`write_protected_profile_requirements()`
functions this matrix's own regression tests exercise. Still
offline-tested only; see `ADR-033`'s "Implementation Phase C" section
for the full provisioning-sequence writeup and its GO/NO-GO for a
future live-validation phase.

## Method (evidence tier 1 of 3 — see ADR-033 §"Evidence")

Every privilege string below is the output of the installed pfSense REST
API package's own `Core/Endpoint.inc::get_method_priv_name()`:

```php
private function get_method_priv_name(string $method): string {
    $priv_name_prefix = str_replace('/', '-', $this->url) . '-';
    $priv_name_prefix = str_replace('_', '-', $priv_name_prefix);
    if (str_starts_with($priv_name_prefix, '-')) {
        $priv_name_prefix = substr($priv_name_prefix, offset: 1);
    }
    return $priv_name_prefix . strtolower($method);
}
```

(`pfrest/pfSense-pkg-RESTAPI`, `Core/Endpoint.inc`, confirmed **byte-identical**
across every tag from `v2.7.7` through `v2.10.0` — the current latest
tag as of this research pass, 2026-08-17. The algorithm has not changed
across this project's entire lifetime.)

Concretely: take the endpoint's URL (e.g. `/api/v2/status/system`),
replace every `/` and `_` with `-`, strip the resulting leading `-`,
append the lowercase HTTP method. `/api/v2/status/dhcp_server/leases`
(GET) → `api-v2-status-dhcp-server-leases-get`.

**Authorization is an ANY-match, not an ALL-match.** `Core/Auth.inc`'s
`authorize()` checks `array_intersect($this->required_privileges,
$this->client_privileges)` — holding *either* `page-all` *or* the
endpoint's own narrow privilege is sufficient. This is what makes a true
least-privilege identity (holding only the narrow privileges, never
`page-all`) architecturally valid, not merely a documentation
convention this project has chosen to follow.

**`requires_page_all_privilege` exists and matters.** A small number of
endpoints package-wide (1 of 268 checked this pass:
`/api/v2/system/restapi/settings/sync`, a POST-only sync action) hard-code
`page-all` as the *only* accepted privilege — no narrow alternative
exists for them. **None of the 52 endpoints this project's 53 READ
tools use require `page-all`**, confirmed by direct inspection of every
matching `Endpoints/*.inc` file at the pinned tag (including the two
outbound-NAT/1:1-NAT mapping endpoints, the interface-VLAN/static-route/
group, firewall-schedule/virtual-IP, REST-API-version, and
certificate-authority endpoints, and, as of 2026-08-21, the IPsec
SA/child-SA status endpoints, each of which offers a narrow alternative
alongside `page-all`). This must be re-checked for any *future* tool
added against a new endpoint — it is not a general guarantee.

## Evidence tier 2: live OpenAPI schema corroboration

Independently, the REST API package's own `Schemas/OpenAPISchema.inc`
embeds each operation's exact allowed-privileges list directly in the
generated schema's `description` field:
`"**Allowed privileges**: [ page-all, api-v2-status-system-get ]"`.
**Every single privilege string below was cross-checked against this
exact text in a real OpenAPI schema previously captured live from the
disposable LAB appliance** (`pfsense_openapi_schema.json`, captured
during the ADR-026 least-privilege provisioning work) — not merely
computed from the algorithm above. All 42 matched exactly; zero
mismatches, zero endpoints missing from the live schema. The two
outbound-NAT/1:1-NAT mapping endpoints added 2026-08-20 were
independently cross-checked the same way, but against a live schema
freshly fetched from the **production** appliance during an
owner-authorized live READ verification, not the original LAB capture
— also an exact match, zero mismatches (43 of 43 now, including these
two).

This corroboration matters for a second reason beyond double-checking
arithmetic: the live schema is generated by the **actually installed**
package on the **actual target appliance**, so agreement between the
algorithm (run against pinned GitHub source) and the live schema
(generated by the real running instance) is itself evidence that the
installed version's privilege-naming behavior matches the pinned
source this document reasons about. The interface-VLAN/static-route
pair, the interface-group/firewall-schedule/REST-API-version trio, the
firewall-virtual-IP/certificate-authority pair, and (2026-08-21) the
IPsec SA/child-SA status pair, were cross-checked against a live schema
freshly fetched from the **LAB** appliance (`pfsense-test.lab.invalid`)
during owner-authorized LAB READ verification passes — also an exact
match, zero mismatches (52 of 52 now, including all nine). The IPsec
pair's LAB cross-check was against the upgraded pfSense CE 2.9.0
appliance specifically; its REST API package schema remained an exact
267-path match despite the platform upgrade.

## READ privilege matrix (53 tools)

| MCP tool | `PfSenseClient` method | pfSense endpoint | Required privilege | Live-confirmed |
|---|---|---|---|---|
| `pfsense_acme_settings` | `get_acme_settings` | `GET /api/v2/services/acme/settings` | `api-v2-services-acme-settings-get` | ✅ |
| `pfsense_arp_table` | `get_arp_table` | `GET /api/v2/diagnostics/arp_table` | `api-v2-diagnostics-arp-table-get` | ✅ |
| `pfsense_auth_keys` | `get_auth_keys` | `GET /api/v2/auth/keys` | `api-v2-auth-keys-get` | ✅ |
| `pfsense_bind_settings` | `get_bind_settings` | `GET /api/v2/services/bind/settings` | `api-v2-services-bind-settings-get` | ✅ |
| `pfsense_carp_status` | `get_carp_status` | `GET /api/v2/status/carp` | `api-v2-status-carp-get` | ✅ |
| `pfsense_cron_jobs` | `get_cron_jobs` | `GET /api/v2/services/cron/jobs` | `api-v2-services-cron-jobs-get` | ✅ |
| `pfsense_dhcp_leases` | `get_dhcp_leases` | `GET /api/v2/status/dhcp_server/leases` | `api-v2-status-dhcp-server-leases-get` | ✅ |
| `pfsense_dhcp_servers` | `get_dhcp_servers` | `GET /api/v2/services/dhcp_servers` | `api-v2-services-dhcp-servers-get` | ✅ |
| `pfsense_dhcp_static_mappings` | `get_dhcp_static_mappings` | `GET /api/v2/services/dhcp_server/static_mappings` | `api-v2-services-dhcp-server-static-mappings-get` | ✅ |
| `pfsense_diagnostics_tables` | `get_diagnostics_tables` | `GET /api/v2/diagnostics/tables` | `api-v2-diagnostics-tables-get` | ✅ |
| `pfsense_dns_resolver_host_overrides` | `get_dns_resolver_host_overrides` | `GET /api/v2/services/dns_resolver/host_overrides` | `api-v2-services-dns-resolver-host-overrides-get` | ✅ |
| `pfsense_dns_resolver_settings` | `get_dns_resolver_settings` | `GET /api/v2/services/dns_resolver/settings` | `api-v2-services-dns-resolver-settings-get` | ✅ |
| `pfsense_email_notification_settings` | `get_email_notification_settings` | `GET /api/v2/system/notifications/email_settings` | `api-v2-system-notifications-email-settings-get` | ✅ |
| `pfsense_firewall_advanced_settings` | `get_firewall_advanced_settings` | `GET /api/v2/firewall/advanced_settings` | `api-v2-firewall-advanced-settings-get` | ✅ |
| `pfsense_firewall_aliases` | `get_firewall_aliases` | `GET /api/v2/firewall/aliases` | `api-v2-firewall-aliases-get` | ✅ |
| `pfsense_firewall_apply_status` | `get_firewall_apply_status` | `GET /api/v2/firewall/apply` | `api-v2-firewall-apply-get` | ✅ |
| `pfsense_firewall_nat_one_to_one_mappings` | `get_firewall_nat_one_to_one_mappings` | `GET /api/v2/firewall/nat/one_to_one/mappings` | `api-v2-firewall-nat-one-to-one-mappings-get` | ✅ |
| `pfsense_firewall_nat_outbound_mappings` | `get_firewall_nat_outbound_mappings` | `GET /api/v2/firewall/nat/outbound/mappings` | `api-v2-firewall-nat-outbound-mappings-get` | ✅ |
| `pfsense_firewall_nat_outbound_mode` | `get_firewall_nat_outbound_mode` | `GET /api/v2/firewall/nat/outbound/mode` | `api-v2-firewall-nat-outbound-mode-get` | ✅ |
| `pfsense_firewall_nat_port_forwards` | `get_firewall_nat_port_forwards` | `GET /api/v2/firewall/nat/port_forwards` | `api-v2-firewall-nat-port-forwards-get` | ✅ |
| `pfsense_firewall_rules` | `get_firewall_rules` | `GET /api/v2/firewall/rules` | `api-v2-firewall-rules-get` | ✅ |
| `pfsense_firewall_schedules` | `get_firewall_schedules` | `GET /api/v2/firewall/schedules` | `api-v2-firewall-schedules-get` | ✅ |
| `pfsense_firewall_states` | `get_firewall_states` | `GET /api/v2/firewall/states` | `api-v2-firewall-states-get` | ✅ |
| `pfsense_firewall_states_size` | `get_firewall_states_size` | `GET /api/v2/firewall/states/size` | `api-v2-firewall-states-size-get` | ✅ |
| `pfsense_firewall_traffic_shaper_limiters` | `get_firewall_traffic_shaper_limiters` | `GET /api/v2/firewall/traffic_shaper/limiters` | `api-v2-firewall-traffic-shaper-limiters-get` | ✅ |
| `pfsense_firewall_virtual_ips` | `get_firewall_virtual_ips` | `GET /api/v2/firewall/virtual_ips` | `api-v2-firewall-virtual-ips-get` | ✅ |
| `pfsense_freeradius_eap` | `get_freeradius_eap` | `GET /api/v2/services/freeradius/eap` | `api-v2-services-freeradius-eap-get` | ✅ |
| `pfsense_gateway_status` | `get_gateway_status` | `GET /api/v2/status/gateways` | `api-v2-status-gateways-get` | ✅ |
| `pfsense_gateways` | `get_gateways` | `GET /api/v2/routing/gateways` | `api-v2-routing-gateways-get` | ✅ |
| `pfsense_interface_bridges` | `get_interface_bridges` | `GET /api/v2/interface/bridges` | `api-v2-interface-bridges-get` | ✅ |
| `pfsense_interface_configs` | `get_interface_configs` | `GET /api/v2/interfaces` | `api-v2-interfaces-get` | ✅ |
| `pfsense_interface_groups` | `get_interface_groups` | `GET /api/v2/interface/groups` | `api-v2-interface-groups-get` | ✅ |
| `pfsense_interface_vlans` | `get_interface_vlans` | `GET /api/v2/interface/vlans` | `api-v2-interface-vlans-get` | ✅ |
| `pfsense_interfaces` | `get_interfaces` | `GET /api/v2/status/interfaces` | `api-v2-status-interfaces-get` | ✅ |
| `pfsense_mcp_info` | *(none — local only)* | *(no pfSense call)* | *(none required)* | n/a |
| `pfsense_ntp_settings` | `get_ntp_settings` | `GET /api/v2/services/ntp/settings` | `api-v2-services-ntp-settings-get` | ✅ |
| `pfsense_ntp_time_servers` | `get_ntp_time_servers` | `GET /api/v2/services/ntp/time_servers` | `api-v2-services-ntp-time-servers-get` | ✅ |
| `pfsense_routing_static_routes` | `get_routing_static_routes` | `GET /api/v2/routing/static_routes` | `api-v2-routing-static-routes-get` | ✅ |
| `pfsense_service_status` | `get_service_status` | `GET /api/v2/status/services` | `api-v2-status-services-get` | ✅ |
| `pfsense_ssh_settings` | `get_ssh_settings` | `GET /api/v2/services/ssh` | `api-v2-services-ssh-get` | ✅ |
| `pfsense_status_ipsec_child_sas` | `get_status_ipsec_child_sas` | `GET /api/v2/status/ipsec/child_sas` | `api-v2-status-ipsec-child-sas-get` | ✅ |
| `pfsense_status_ipsec_sas` | `get_status_ipsec_sas` | `GET /api/v2/status/ipsec/sas` | `api-v2-status-ipsec-sas-get` | ✅ |
| `pfsense_system_certificate_authorities` | `get_system_certificate_authorities` | `GET /api/v2/system/certificate_authorities` | `api-v2-system-certificate-authorities-get` | ✅ |
| `pfsense_system_certificates` | `get_system_certificates` | `GET /api/v2/system/certificates` | `api-v2-system-certificates-get` | ✅ |
| `pfsense_system_hasync` | `get_system_hasync` | `GET /api/v2/system/hasync` | `api-v2-system-hasync-get` | ✅ |
| `pfsense_system_packages` | `get_system_packages` | `GET /api/v2/system/packages` | `api-v2-system-packages-get` | ✅ |
| `pfsense_system_restapi_settings` | `get_system_restapi_settings` | `GET /api/v2/system/restapi/settings` | `api-v2-system-restapi-settings-get` | ✅ |
| `pfsense_system_restapi_version` | `get_system_restapi_version` | `GET /api/v2/system/restapi/version` | `api-v2-system-restapi-version-get` | ✅ |
| `pfsense_system_status` | `get_system_status` | `GET /api/v2/status/system` | `api-v2-status-system-get` | ✅ |
| `pfsense_system_tunables` | `get_system_tunables` | `GET /api/v2/system/tunables` | `api-v2-system-tunables-get` | ✅ |
| `pfsense_system_version` | `get_system_version` | `GET /api/v2/system/version` | `api-v2-system-version-get` | ✅ |
| `pfsense_user_groups` | `get_user_groups` | `GET /api/v2/user/groups` | `api-v2-user-groups-get` | ✅ |
| `pfsense_users` | `get_users` | `GET /api/v2/users` | `api-v2-users-get` | ✅ |

**52 distinct privileges, one per tool, zero sharing between tools** —
confirmed programmatically (`len(set(privileges)) == 52`). A least-privilege
READ-only identity holding exactly these 52 (never `page-all`) can serve
every one of this project's 53 registered READ tools.

## Additional client-only capability (not a registered MCP tool)

`PfSenseClient.get_config_history_revisions()` exists and is fully
implemented (added closing ADR-026 row 18) but **no file under
`tools/read/` calls it** — it is unreachable through the MCP surface
today, used only for internal evidence-gathering. **Not required for
"current default READ-only operation" (item A)** — included here for
completeness, since a future decision to expose it as a 54th tool would
need this privilege:

| Client method | pfSense endpoint | Required privilege | Live-confirmed |
|---|---|---|---|
| `get_config_history_revisions` | `GET /api/v2/diagnostics/config_history/revisions` | `api-v2-diagnostics-config-history-revisions-get` | ✅ |

**Also currently in this state (2026-08-21, not a stale carryover):**
`PfSenseClient.get_status_wireguard_tunnels()`/`get_status_wireguard_peers()`
are fully implemented and offline-tested but **not registered** —
`Endpoints.STATUS_WIREGUARD_TUNNELS`/`STATUS_WIREGUARD_PEERS` remain
`verified=False` because this LAB appliance does not have
`pfSense-pkg-WireGuard` installed (confirmed via a direct HTTP 404,
`response_id=MODEL_MISSING_REQUIRED_PACKAGE`), and installing it would
be a LAB mutation outside this project's non-destructive READ-only LAB
authorization. Privileges below are schema-derived only, not yet
live-confirmed:

| Client method | pfSense endpoint | Required privilege | Live-confirmed |
|---|---|---|---|
| `get_status_wireguard_tunnels` | `GET /api/v2/status/wireguard/tunnels` | `api-v2-status-wireguard-tunnels-get` | ❌ (package not installed on LAB) |
| `get_status_wireguard_peers` | `GET /api/v2/status/wireguard/peers` | `api-v2-status-wireguard-peers-get` | ❌ (package not installed on LAB) |

## WRITE privilege matrix (`set_firewall_alias_description_v1`)

**Re-derived independently this pass** (not merely copied forward) from
the same pinned source and the same live schema, as the task's "do not
assume previously documented privilege IDs remain correct" instruction
required — and found **unchanged** from the values already live-provisioned
and live-verified in
[`ADR-026`](adr/ADR-026-first-write-capability-adapter.md):

| Purpose | pfSense endpoint | Required privilege | Live-confirmed |
|---|---|---|---|
| Read current alias state before mutation | `GET /api/v2/firewall/aliases` | `api-v2-firewall-aliases-get` | ✅ |
| The mutation itself | `PATCH /api/v2/firewall/alias` | `api-v2-firewall-alias-patch` | ✅ |
| System status (production runtime dependency) | `GET /api/v2/status/system` | `api-v2-status-system-get` | ✅ |
| HA-sync check (conditional — see ADR-026) | `GET /api/v2/system/hasync` | `api-v2-system-hasync-get` | ✅ |

These 4, plus the already-documented, already-revoked, one-time
bootstrap privilege `api-v2-auth-key-post` (needed only for a new
identity to self-generate its first API key — see ADR-033 §"Bootstrap
security model" and the historical
`reports-ai/reviews/SLICE6_LEAST_PRIVILEGE_PROVISIONING_2026-08-16.md`
transcript), are the complete set this project has ever needed to
provision for WRITE, live-tested twice against the disposable LAB
appliance.

## Combined minimum set, READ + existing WRITE

The 4 WRITE privileges are a strict subset of the 52 READ privileges
except for `api-v2-firewall-alias-patch` (the mutation itself, obviously
WRITE-only) — `firewall-aliases-get`, `status-system-get`, and
`system-hasync-get` are already required for the READ tools
`pfsense_firewall_aliases`, `pfsense_system_status`, and
`pfsense_system_hasync` respectively. A `write_protected`-profile
identity therefore needs exactly **53 distinct privileges**: the 52 READ
privileges plus the one additional `api-v2-firewall-alias-patch`.
