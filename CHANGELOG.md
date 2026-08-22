# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Schema field-drift regression protection (v0.6.0 Phase B, Batch A).**
  `scripts/lib/schema_drift.py` provides a general mechanism,
  independently designed (not derived from the comparison project
  investigated in the v0.6.0 competitive audit), that asserts every
  field a pinned upstream OpenAPI schema component declares is either a
  field this project's Pydantic response model already declares, or is
  present in an explicit, reviewed `intentional_exclusions` allowlist
  (e.g. `WireGuardPeerStatus.preshared_key`, deliberately never
  modeled). This closes a real, previously-unguarded gap: a future
  pfREST release adding a field to an already-modeled response object
  would otherwise go completely unnoticed, since a Pydantic model
  silently ignores unknown upstream keys by construction.
  `tests/test_schema_field_drift.py` registers four already-shipped
  models (`ConfigHistoryRevision`, `SystemTimezone`,
  `WireGuardTunnelStatus`, `WireGuardPeerStatus`) against a small,
  explicitly curated fixture (`tests/fixtures/pinned_response_schemas.json`)
  and proves the mechanism itself fires correctly against synthetic
  ordinary-field, secret-like-field, nested-model, exclusion-allowlist,
  stale-exclusion, and schema-evolution (nullable) cases. No MCP tool,
  capability, or public contract change. Public contract remains 84
  READ / 0 default WRITE.

- **`pfsense_get_diagnostics_config_history_revisions` (v0.6.0 Phase B,
  Batch B).** Lists configuration-history (backup) revisions: change
  timestamp, pfSense's own system-generated audit description, the
  pfSense version at the time, and the backup file size. Metadata only
  — the v0.6.0 Phase A qualification independently confirmed, against
  the upstream `ConfigHistoryRevision.inc` Model source (not just the
  OpenAPI schema), that this endpoint's response never includes the
  backup's actual configuration content, only filesystem-level metadata.
  The underlying client method, typed model, and `Endpoints` entry
  already existed (added 2026-08-16 for internal ADR-026 evidence
  gathering, `verified=True` from that session's real LAB call); this
  release adds only the public MCP tool registration. A fresh
  confirmatory LAB call was attempted this session but could not be
  completed (the read-only LAB service account's privilege scope did
  not yet include this endpoint, and granting it required admin LAB
  access not available in this session) — promotion rests on the
  pre-existing 2026-08-16 evidence, disclosed explicitly rather than
  overstated; see `docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md`. Public
  contract: 84 → 85 READ tools (0 default WRITE, unchanged).

- **`LogSettings` model + client method, implemented and offline-tested
  (v0.6.0 Phase B, Batch C — not yet registered).** New
  `src/pfsense_mcp/models/log_settings.py` (34 fields, all
  boolean/string/integer, no `writeOnly`/secret-shaped field anywhere —
  re-verified directly against the pinned schema immediately before
  implementation, independent of the v0.6.0 Phase A finding) and
  `PfSenseClient.get_status_logs_settings()`. LAB verification could not
  be completed this session: the read-only LAB service account's
  privilege scope covers only already-registered tools, and granting
  `api-v2-status-logs-settings-get` required admin LAB access that did
  not authenticate successfully. `Endpoints.STATUS_LOGS_SETTINGS` remains
  `verified=False`; no `tools/read/` file, `Capability` enum member, or
  registry wiring was added, matching this project's established
  WireGuard-package-blocker precedent. Public contract unchanged at 85
  READ / 0 default WRITE. Registered in the Batch A schema-drift
  registry.

- **Apply-status sweep, implemented and offline-tested (v0.6.0 Phase B,
  Batch D — not yet registered).** Eight new models/client methods for
  `firewall/virtual_ip/apply`, `interface/apply`, `routing/apply`,
  `services/dhcp_server/apply`, `services/dns_forwarder/apply`,
  `services/dns_resolver/apply`, `vpn/ipsec/apply`, `vpn/wireguard/apply`
  — each independently re-verified against the pinned schema (all
  trivial `{"applied": bool}` shapes; `interface/apply` additionally
  has a flat `pending_interfaces: list[str]`; no secret material in
  any). Mirrors the already-shipped `FirewallApplyStatus` pattern.
  `applied`/`pending_interfaces` are modeled `| None` (schema-declared
  `nullable: true`), deliberately not assumed non-null the way the
  pre-existing `FirewallApplyStatus` is, since no live call has
  confirmed any of these eight endpoints' actual behavior yet. None
  registered as public tools — same LAB-access blocker as Batch C.
  Public contract unchanged at 85 READ / 0 default WRITE.

- **WireGuard tunnel addresses, implemented and offline-tested (v0.6.0
  Phase B, Batch E — not yet registered).** New
  `WireGuardTunnelAddress` model/client method for
  `vpn/wireguard/tunnel/addresses` (`address`/`mask`/`descr`, none
  `writeOnly`, no secret material — `address`/`mask` redacted by
  default, matching `RoutingStaticRoute`'s established convention).
  Independently re-confirmed NOT redundant with the already-shipped
  `WireGuardTunnelStatus`, which has no address/CIDR field at all —
  unlike WireGuard peer allowed-IPs, deliberately **not** implemented
  since it is already nested as `WireGuardPeerStatus.allowed_ips`.
  pfSense-pkg-WireGuard is already installed on the LAB (prior,
  separately authorized action), so package availability is not this
  batch's blocker — the same read-only LAB service-account privilege
  scope issue as Batches C/D is. Not registered as a public tool. Public
  contract unchanged at 85 READ / 0 default WRITE.

## [0.5.1] - 2026-08-21

**Documentation-accuracy and security-communication patch. NO MCP
capability change. NO runtime security-semantic change. Public contract
remains exactly 84 READ / 0 default WRITE**, byte-identical to `v0.5.0`
— confirmed by an unchanged `tests/contracts/mcp_public_contract_v0.5.1.json`
snapshot relative to `v0.5.0`'s. Every finding below is documentation or
presentation only.

### Fixed

- **Post-publication documentation correction (2026-08-21): incorrect
  pfSense Plus REST API packaging claim.** README's compatibility
  section (and the matching table in `docs/ACCEPTANCE_v0.5.0.md`)
  claimed the REST API "ships as a built-in platform component" on
  pfSense Plus rather than a separately versioned package, inferred
  from its absence in the general installed-package listing
  (`pfsense_get_system_packages`) during the v0.5.0 release audit. This
  was a genuine error: a direct, targeted follow-up call to
  `pfsense_get_system_restapi_version` — the tool actually built for
  this exact question, not consulted at the time — confirms the REST
  API package's own self-reported version (`current_version`) is
  **v2.10 on both pfSense CE (re-confirmed live on the CE 2.9.0 LAB)
  and pfSense Plus 26.07 production**, identical to the CE baseline
  already documented. Further investigation found the package does
  **not** appear as a discrete entry in the general installed-package
  listing on **either** edition — re-confirmed directly on the CE 2.9.0
  LAB (which lists only the one other package genuinely installed
  there) — so this was never a CE-vs-Plus difference at all, only a
  characteristic of that one endpoint on every platform tested. README
  and `docs/ACCEPTANCE_v0.5.0.md` corrected to state only
  independently-verified facts, distinguishing pfSense platform
  version, edition, REST API package version, and schema/API
  compatibility as the separate facts they are. `v0.5.0` itself
  (already tagged, released, and published to PyPI before this error
  was found) still carries the original incorrect text in its
  immutable tag/Release/PyPI artifacts — per this project's own
  release policy, that historical record is not altered; this fix
  applies to `main` and every release from here forward. No public
  contract, security, or compatibility-verification-result change: the
  underlying evidence (schema match, tool-count regression results)
  was always correct — only the packaging-mechanism inference was
  wrong.
- **Package-dependency documentation was incomplete.** README only
  documented the two WireGuard status tools as package-conditional.
  Re-derived every one of the 84 registered endpoints' schema-declared
  `Required packages` metadata directly (not assumed): four more tools
  (`pfsense_get_acme_settings`, `pfsense_get_bind_settings`,
  `pfsense_get_cron_jobs`, `pfsense_get_freeradius_eap`) reference a
  package in the schema's own metadata (`pfSense-pkg-acme`,
  `pfSense-pkg-bind`, `pfSense-pkg-Cron`, `pfSense-pkg-freeradius3`
  respectively) but were directly confirmed, by invoking them against
  systems genuinely lacking those packages (the CE 2.9.0 LAB for all
  four; the Plus 26.07 production appliance for three of the four),
  to succeed regardless — these read as stored
  configuration/default-settings structures, not genuinely
  package-gated runtime state, unlike the WireGuard status pair (which
  do 404 with `MODEL_MISSING_REQUIRED_PACKAGE` when absent). README
  now documents this distinction precisely instead of implying only
  WireGuard has any package reference at all.
- **Evidence-tier terminology overlapped.** README's compatibility
  matrix previously used `LIVE VERIFIED` to mean "LAB or production,"
  which overlapped with the separate `LAB VERIFIED` tier and made the
  two indistinguishable for a reader. Replaced `LIVE VERIFIED` with
  `PRODUCTION VERIFIED` (production only) so all four tiers
  (`PRODUCTION VERIFIED` / `LAB VERIFIED` / `SUPPORTED / COMPATIBLE` /
  `EXPECTED COMPATIBLE / UNVERIFIED`) are mutually exclusive. No
  evidence changed — pfSense Plus 26.07's row is unaffected in
  substance, only relabeled from `LIVE VERIFIED` to the more precise
  `PRODUCTION VERIFIED`.
- **pfSense Plus 25.11's classification was too strong for its
  evidence.** Re-evaluated rather than preserved as previously written:
  the evidence behind the prior `SUPPORTED / COMPATIBLE` classification
  was entirely adjacent (FreeBSD-generation similarity via Netgate's
  own 25.11 release notes, plus pfREST v2.10 behavior observed on
  *other* releases) — nothing this project has directly exercised
  touches a 25.11 instance in any way. Downgraded to
  `EXPECTED COMPATIBLE / UNVERIFIED`, the tier this project's own newly
  mutually-exclusive definitions assign to exactly this evidence
  profile.
- **An unqualified "verified before promotion" claim was too
  universal.** README's "Key facts" bullet stated every tool is
  "verified against a real pfSense instance before public
  registration" without distinguishing depth. Reworded to state
  precisely what is true: every one of the 84 tools was exercised at
  least once and confirmed to match its typed model, but some have so
  far only been observed against a valid empty/default envelope on
  every system tested, not populated real data — the two are not the
  same claim and the README no longer conflates them.
- **`docs/TIER1_ARCHITECTURE.md` and `docs/ARCHITECTURE_DIAGRAMS.md`
  were stale, describing the pre-`ADR-026` v0.3.0-era state** ("no
  mutation executor exists yet," "adapter implementation remains
  blocked," "these diagrams describe the immutable v0.3.0 production
  baseline") despite the first WRITE capability having been built and
  independently live-verified since 2026-08-16. Added a dated
  historical note to `TIER1_ARCHITECTURE.md` (matching
  `SECURITY_MODEL.md`'s own established correction pattern) rather than
  rewriting its still-accurate generic reusable-framework content, and
  updated `ARCHITECTURE_DIAGRAMS.md`'s framing and its
  "Inert Tier 1 framework and future execution path" section — which
  claimed "no executor, endpoint, capability, or tool is active" — to
  describe the real, current architecture instead. This inaccuracy was
  independent of, and unrelated to, the pfREST packaging finding above;
  found during this release's own re-reading of the authoritative
  architecture sources before drafting new diagrams.

### Added

- **Three new Mermaid architecture diagrams**, derived directly from
  current source (`tools/registry.py`, `capabilities.py`, `profiles.py`,
  `tier1/execution_coordinator.py`, `tier1/executor.py`,
  `tier1/state_machine.py`) and accepted architecture
  (`ADR-026`, `SECURITY_MODEL.md`), not from this changelog entry's own
  prose:
  - **READ security path** — the exact path every one of the 84 tools
    takes, compact version in README near "Why this server," full
    version in `docs/ARCHITECTURE_DIAGRAMS.md`.
  - **Protected WRITE authorization path** — the gate-by-gate `ADR-026`
    flow (off-host signature → 6 fail-closed pre-execution gates →
    `RecoveryContract` → sealed `MutationExecutor` → read-back →
    verified/reconciliation), compact version in README's "Protected
    WRITE architecture" section, full version with all six gates named
    individually in `docs/ARCHITECTURE_DIAGRAMS.md`. Explicitly
    distinguishes `IMPLEMENTED` / `VERIFIED` / `DEFAULT-REACHABLE` as
    three different claims, since the one capability that exists is
    the first two but never the third.
  - **Defense in depth / trust boundaries** — a single high-level
    diagram in `docs/ARCHITECTURE_DIAGRAMS.md` showing which failure
    class each layer actually stops, limits, constrains, or detects
    (deliberately not a blanket "secure" label on any layer). Corrects
    a self-caught drafting error: the TPM witness was initially
    labeled "optional," which contradicts `SECURITY_MODEL.md`'s own
    statement that production WRITE activation requires it (a
    software-only anchor alternative is modeled but has no implemented
    backend) — fixed before this diagram was ever committed.
  - All four diagrams (three new plus the existing set) independently
    validated with `mermaid`'s own parser (`mermaid.parse()` via a
    headless DOM shim) before commit; full visual/browser rendering
    was not available in this environment (missing
    `chrome-headless-shell` system dependency), so parser-level syntax
    validation is this release's evidence tier for "renders correctly"
    rather than a rendered-image comparison.

## [0.5.0] - 2026-08-21

**Major READ capability expansion — no WRITE change, no security-model
change.** Public MCP contract grows from 42 to 84 READ tools (exactly a
100% increase over the last published baseline, `v0.4.2`), covering
roughly 80% of the useful READ capability universe identified by this
project's own capability discovery audit (267 OpenAPI paths / 243 GET
operations reviewed; every GET given exactly one disposition — up from
roughly 40% coverage at the `v0.4.2` baseline). Every tool below was
independently re-verified for secret-bearing fields before
implementation, then verified against a real pfSense instance (LAB or,
where explicitly owner-authorized, production) before public
registration — never assumed from schema alone. Closes with an
independent, adversarial release-readiness audit (security regression
sweep, CE/Plus compatibility verification including a live production
Plus 26.07 pass, packaging/fresh-install/upgrade-path verification, and
a full README restructure) — see "Security" and "Changed" below for its
findings.

### Added

- **2 new READ tools (production live-verified, pre-dating the P0
  backlog below), public MCP contract 42 → 44 (0 WRITE, unchanged):**
  - `pfsense_get_firewall_nat_outbound_mappings` — outbound NAT
    mappings (`source`/`destination`/`target` address/alias fields
    redacted by default, matching `FirewallNatPortForward`'s
    established convention; `source_hash_key` is a hash seed, not a
    credential, and stays visible).
  - `pfsense_get_firewall_nat_one_to_one_mappings` — 1:1 NAT mappings
    (`external`/`source`/`destination` redacted the same way).
  - Owner-authorized, narrowly-scoped live **production** READ
    verification (not LAB) of exactly these two endpoints: both typed
    GETs succeeded with zero configured mappings in either category;
    field-level type/nullability compatibility confirmed via an exact,
    byte-for-byte match between the live OpenAPI schema and the pinned
    v2.10 reference the models were derived from.
- **7 new READ tools, public MCP contract 44 → 51 (0 WRITE, unchanged):**
  - `pfsense_get_interface_vlans` — 802.1Q VLAN interfaces.
  - `pfsense_get_routing_static_routes` — static routes (network/gateway
    redacted by default).
  - `pfsense_get_interface_groups` — interface group membership, useful
    for interpreting firewall rules that target a group.
  - `pfsense_get_firewall_schedules` — time-based firewall schedules.
  - `pfsense_get_system_restapi_version` — installed REST API package
    version and update availability.
  - `pfsense_get_firewall_virtual_ips` — CARP/IP-alias/proxy-ARP virtual
    IPs (address fields redacted by default; the CARP shared secret is
    never modeled at all — see "Security" below).
  - `pfsense_get_system_certificate_authorities` — trusted CA inventory
    (the CA private key is never modeled at all — see "Security" below).
  - Two of the seven (`system_restapi_version`,
    `system_certificate_authorities`) were verified against real,
    populated LAB objects, not just an empty envelope — the latter
    against the LAB's own internal CA.
- **2 more READ tools (P1 Batch A, partial), public MCP contract 51 →
  53 (0 WRITE, unchanged):**
  - `pfsense_get_status_ipsec_sas` — live IPsec SA/tunnel status,
    including nested child SAs.
  - `pfsense_get_status_ipsec_child_sas` — live IPsec child SA status.
  - `IPsecSaStatus.child_sas` embeds full `IPsecChildSaStatus` objects
    (schema-confirmed `$ref`) and is constructed through that model's
    own parser for every nested item, not passed through as a raw dict.
  - `status/wireguard/tunnels`/`status/wireguard/peers` were also
    implemented and offline-tested this batch but remained unregistered
    at first: this LAB did not have `pfSense-pkg-WireGuard` installed,
    so live verification was blocked — see the next entry for how this
    was resolved.
- **2 more READ tools (P1 Batch A completion), public MCP contract 53 →
  55 (0 WRITE, unchanged):** owner explicitly authorized installing
  `pfSense-pkg-WireGuard` on the LAB for non-production READ
  verification only. Preflight: reconfirmed LAB identity distinct from
  production, identified the LAB as the sole pfSense-named VM in its
  Proxmox cluster, and took a fresh rollback snapshot before any
  change. Post-install: confirmed pfSense/pfREST healthy, re-ran a
  52-tool regression subset with zero regressions, then live-verified
  both endpoints (HTTP 200, correct envelope, zero configured tunnels/
  peers; raw responses inspected directly for unexpected fields).
  - `pfsense_get_status_wireguard_tunnels` — live WireGuard tunnel
    status, including nested peer status.
  - `pfsense_get_status_wireguard_peers` — live WireGuard peer status.
  - The package installation was a one-off authenticated LAB
    administrative call, made outside and independent of this
    project's own `WriteApiClient`/`WriteEndpoints` allow-list
    mechanism, which remains untouched and still empty except
    `FIREWALL_ALIAS_DESCRIPTION` — not a WRITE-capability expansion of
    the shipped server.
- **4 more READ tools (P1 Batch B), public MCP contract 55 → 59 (0
  WRITE, unchanged):**
  - `pfsense_get_status_openvpn_servers` — live OpenVPN server status,
    including nested connection/route status.
  - `pfsense_get_status_openvpn_clients` — live OpenVPN client status.
  - `pfsense_get_status_openvpn_server_connections` — flat, all-servers
    OpenVPN client connection status.
  - `pfsense_get_status_openvpn_server_routes` — flat, all-servers
    OpenVPN client route status.
  - Resolved the standing open question of whether the standalone
    connection/route endpoints duplicate `OpenVpnServerStatus`'s own
    nested `conns`/`routes` fields using the pinned schema's own
    `Parent model` declaration (both standalone endpoints declare
    `Parent model: OpenVPNServerStatus`) — the identical structural
    relationship already established as non-redundant between
    `IPsecSaStatus`/`IPsecChildSaStatus`, so all four were implemented
    as genuinely independent capabilities rather than assumed
    duplicates.
  - `OpenVpnServerStatus.conns`/`.routes` embed full
    `OpenVpnServerConnectionStatus`/`OpenVpnServerRouteStatus` objects
    (schema-confirmed `$ref`) and are constructed through those
    models' own parsers for every nested item, not passed through as
    raw dicts.
- **3 more READ tools (P1 Batch C), public MCP contract 59 → 62 (0
  WRITE, unchanged):**
  - `pfsense_get_dns_forwarder_host_overrides` — dnsmasq (DNS Forwarder)
    host overrides: addresses, aliases, and descriptions.
  - `pfsense_get_dns_resolver_domain_overrides` — Unbound (DNS Resolver)
    domain overrides: forwarding target address and DNS-over-TLS
    settings.
  - `pfsense_get_dns_resolver_access_lists` — Unbound (DNS Resolver)
    access lists: allow/deny action and the network ranges each list
    applies to.
  - All three re-checked against the pinned schema for secrets (none
    found) and modeled following the existing shipped
    `DnsResolverHostOverride` precedent: full field visibility, no
    `include_identifying_metadata` redaction, since address/network
    data is the core content of this capability class (the same
    rationale already documented for `DhcpServer`).
  - All three LAB-verified live: `HTTP 200`, zero configured objects
    (`ENDPOINT_VERIFIED`); no package required (base
    pfSense/dnsmasq/Unbound features).
- **3 more READ tools (P1 Batch D, interface extras), public MCP
  contract 62 → 65 (0 WRITE, unchanged):**
  - `pfsense_get_interface_available_interfaces` — all interfaces
    available for assignment (not just already-assigned ones):
    identifier, in-use status, hardware boot message.
  - `pfsense_get_interface_gres` — GRE tunnel interfaces.
  - `pfsense_get_interface_laggs` — LAGG (link aggregation) interfaces.
  - All three re-checked against the pinned schema for secrets (none
    found). `mac` (`AvailableInterface`) and 7 of `InterfaceGRE`'s 11
    fields (tunnel-endpoint addresses) are redacted by default,
    matching `InterfaceStatus.macaddr` and `RoutingStaticRoute`'s
    established conventions; `InterfaceLAGG`'s `members`/`laggif` stay
    visible, matching `InterfaceBridge`'s established no-redaction
    precedent. `InterfaceLAGG`'s proto-conditional fields
    (`lacptimeout`/`lagghash`/`failovermaster`) use `.get()` with the
    schema's own declared default, matching the `install_version`
    precedent for a field that can be legitimately absent rather than
    merely null.
  - `interface/available_interfaces` LAB-verified with
    `FIELD_MODEL_LIVE_VERIFIED`: 2 real populated objects (the LAB's
    actual `vtnet0`/`vtnet1` WAN/LAN interfaces), with redaction
    confirmed against real data. `interface/gres` and
    `interface/laggs` both LAB-verified `ENDPOINT_VERIFIED` (zero
    configured objects); no package required for any of the three
    (base pfSense features).
  - The models/client methods/`Endpoints` entries were implemented and
    offline-tested one commit before registration, deliberately
    unregistered in the interim, matching the established
    "implemented, offline-tested, blocked" precedent from P1 Batch A's
    WireGuard pair.
- **5 more READ tools (P1 Batch E, routing + DHCP extras), public MCP
  contract 65 → 70 (0 WRITE, unchanged):**
  - `pfsense_get_routing_gateway_groups` — gateway groups: name,
    failover trigger, description, prioritized member gateways.
  - `pfsense_get_routing_gateway_default` — current default IPv4/IPv6
    gateway assignment.
  - `pfsense_get_dhcp_relay` — DHCP Relay configuration.
  - `pfsense_get_dhcp_server_address_pools` — additional DHCP scopes
    across all configured DHCP servers.
  - `pfsense_get_dhcp_server_custom_options` — DHCP custom options
    across all configured DHCP servers.
  - `RoutingGatewayGroupPriority.gateway`/`.virtual_ip` and
    `DefaultGateway.defaultgw4`/`.defaultgw6` (gateway name references)
    and `DHCPRelay.server` (literal relay target addresses) are
    redacted by default, matching `RoutingStaticRoute.gateway` and
    `GatewayConfig.gateway`'s established conventions.
    `RoutingGatewayGroup.priorities` embeds full
    `RoutingGatewayGroupPriority` objects and is constructed through
    that model's own `from_api()` for every item.
    `DHCPServerAddressPool`/`DHCPServerCustomOption` are schema-declared
    children of `DHCPServer` (`Parent model: DHCPServer`) and follow
    that resource's own established no-redaction convention instead
    ("the whole point of a DHCP server (scope) configuration
    capability").
  - LAB verification found a genuine CE 2.9.0 nullability discrepancy:
    `DHCPRelay.interface` returned `null` on the LAB's unconfigured
    DHCP Relay despite the pinned schema declaring it `nullable: false`
    — fixed by widening the field before promoting, matching the
    `SystemRestApiVersion.install_version`/`DhcpServer` precedent.
  - All five reached `ENDPOINT_VERIFIED`; no package required for any
    of the five (base pfSense features).
  - The models/client methods/`Endpoints` entries were implemented and
    offline-tested one commit before registration, deliberately
    unregistered in the interim, matching the established
    "implemented, offline-tested, blocked" precedent from P1 Batch A's
    WireGuard pair.
- **5 more READ tools (P1 Batch F, system identity/config cluster),
  public MCP contract 70 → 75 (0 WRITE, unchanged):**
  - `pfsense_get_system_hostname` — system hostname and domain.
  - `pfsense_get_system_timezone` — system timezone.
  - `pfsense_get_system_dns` — system DNS settings: override policy,
    local-vs-remote resolution preference, remote DNS servers.
  - `pfsense_get_system_console` — whether a password is required to
    access the system console.
  - `pfsense_get_system_webgui_settings` — web GUI listener settings:
    protocol, port, assigned TLS certificate reference.
  - `SystemHostname.hostname`/`.domain` are redacted by default (a
    conservative-posture judgment call, not a schema-confirmed
    secret — they identify the specific managed appliance/network) and
    `SystemDNS.dnsserver` (literal DNS server addresses) is redacted by
    default, matching `RoutingStaticRoute.gateway`/`GatewayConfig.gateway`'s
    established conventions. `WebGUISettings` was independently
    re-verified secret-free during this batch's own re-check
    (`protocol`/`port`/`sslcertref` only — `sslcertref` is a certificate
    reference, not key material).
  - LAB-verified: `system/hostname`, `system/timezone`,
    `system/console`, and `system/webgui/settings` all reached
    `FIELD_MODEL_LIVE_VERIFIED` (real populated data, not just an empty
    envelope); `system/dns` reached `ENDPOINT_VERIFIED` (no remote DNS
    servers configured on this LAB). No package required for any of
    the five (base pfSense features).
  - The models/client methods/`Endpoints` entries were implemented and
    offline-tested one commit before registration, deliberately
    unregistered in the interim, matching the established
    "implemented, offline-tested, blocked" precedent from P1 Batch A's
    WireGuard pair.
- **3 more READ tools (P1 Batch G, REST API + PKI metadata), public
  MCP contract 75 → 78 (0 WRITE, unchanged):**
  - `pfsense_get_system_restapi_access_list` — the REST API's own IP
    allow/deny access list entries.
  - `pfsense_get_system_crls` — Certificate Revocation Lists (CRLs).
  - `pfsense_get_system_package_available` — packages available for
    installation.
  - `RESTAPIAccessListEntry.network` (the REST API's own literal IP
    allow/deny CIDR) is redacted by default, matching
    `GatewayConfig.gateway`'s established convention.
    `CertificateRevocationList.cert`/`.text` are each schema-documented
    as only available for a specific `method` value and are treated as
    genuinely possibly-absent, matching the `InterfaceLAGG` precedent.
  - Found during re-verification that
    `CertificateRevocationListRevokedCertificate` has five schema
    fields marked `writeOnly: true` — `crt`, `caref`, `descr`, `type`,
    and **`prv`, confirmed to be the revoked certificate's X509
    private key** — none of these are ever present in a real GET
    response, and none are modeled, matching the
    `CertificateAuthority.prv`/`SystemCertificate.prv` precedent
    exactly rather than trusting the schema's `writeOnly` promise
    alone.
  - LAB-verified: `system/restapi/access_list` and
    `system/package/available` both reached `FIELD_MODEL_LIVE_VERIFIED`
    (2 real default allow-all entries; 69 real available packages);
    `system/crls` reached `ENDPOINT_VERIFIED` (zero configured CRLs on
    this LAB). No package required for any of the three (base pfSense
    features).
  - The models/client methods/`Endpoints` entries were implemented and
    offline-tested one commit before registration, deliberately
    unregistered in the interim, matching the established
    "implemented, offline-tested, blocked" precedent from P1 Batch A's
    WireGuard pair.
- **1 more READ tool (P1 Batch H), public MCP contract 78 → 79 (0
  WRITE, unchanged):**
  - `pfsense_get_firewall_traffic_shapers` — traffic shapers:
    interface, scheduler algorithm, bandwidth, and child queues.
  - No field is redacted (pure QoS/bandwidth-shaping configuration
    data, no addresses). Of `TrafficShaperQueue`'s 27 fields, only 6
    are schema-required; the other 21 are each documented as only
    available for a specific `scheduler` type or sibling boolean flag
    and are treated as genuinely possibly-absent via `.get()`,
    matching the `InterfaceLAGG` precedent.
  - LAB-verified `ENDPOINT_VERIFIED` (zero configured traffic shapers
    on this LAB); no package required (base pfSense feature).
- **3 more READ candidates implemented and offline-tested (P1 Batch H,
  service/traffic policy cluster) but requiring an absent package —
  package-conditional, NOT a LAB-installation authorization**:
  `services/freeradius/interfaces` and `services/freeradius/macs`
  (require `pfSense-pkg-freeradius3`) and `services/service_watchdogs`
  (requires `pfSense-pkg-Service_Watchdog`). Direct LAB inspection via
  the already-shipped `pfsense_get_system_packages` tool confirmed
  neither package is installed on this LAB — only
  `pfSense-pkg-WireGuard` is. `FreeRADIUSInterface`/`FreeRADIUSMAC`/
  `ServiceWatchdog` models, their client methods, and their `Endpoints`
  entries (`verified=False`) all exist and are fully offline-tested,
  but are left unregistered pending an owner decision on installing
  either package — matching this project's standing
  package-conditional-candidate rule (only `pfSense-pkg-WireGuard`
  installation was ever explicitly authorized). `FreeRADIUSInterface.addr`
  (listening address) and `FreeRADIUSMAC.mac`/5 `framed_*` address
  fields are redacted by default once registered, matching
  `GatewayConfig.gateway`/`InterfaceStatus.macaddr`'s established
  conventions.
- **3 more READ tools (P1 Batch I, IPsec Phase 2 + encryption
  capability lists), public MCP contract 79 → 82 (0 WRITE,
  unchanged):**
  - `pfsense_get_vpn_ipsec_phase2s` — IPsec Phase 2 entries: mode,
    protocol, encryption/hash options, and rekey timing.
  - `pfsense_get_vpn_ipsec_phase1_encryptions` — IPsec Phase 1
    encryption algorithm/hash/DH-group capability options.
  - `pfsense_get_vpn_ipsec_phase2_encryptions` — IPsec Phase 2
    encryption algorithm capability options.
  - Re-confirmed the IPsec PSK lives only on `IPsecPhase1`, already
    REJECTed separately — no secret material is present on Phase 2
    itself. `IPsecPhase2.localid_address`/`.natlocalid_address`/
    `.remoteid_address`/`.pinghost` (endpoint and monitoring target
    addresses) are redacted by default, matching
    `RoutingStaticRoute.gateway`'s established convention.
    `encryption_algorithm_option` is schema-documented as only
    available when `protocol` is `'esp'` and is treated as genuinely
    possibly-absent via `.get()`, matching the `InterfaceLAGG`
    precedent; it is schema-confirmed to embed full
    `IPsecPhase2Encryption` objects and is constructed through that
    model's own `from_api()` for every item.
    `IPsecPhase1Encryption`/`IPsecPhase2Encryption` are pure
    algorithm/cipher capability reference data, no redaction needed.
  - LAB-verified `ENDPOINT_VERIFIED` for all three (zero configured
    Phase 2 entries; the encryption capability lists were also empty
    on this LAB, since no IPsec Phase 1 is configured to derive
    options from). No package required for any of the three (base
    pfSense feature).
- **2 more READ tools (P1 Batch J, OpenVPN server config +
  client-specific overrides), public MCP contract 82 → 84 (0 WRITE,
  unchanged):**
  - `pfsense_get_vpn_openvpn_servers` — OpenVPN server configurations:
    mode, protocol, TLS/cert references, ciphers, and topology
    (`OpenVpnServer`, 73 fields).
  - `pfsense_get_vpn_openvpn_csos` — OpenVPN client-specific overrides:
    per-client tunnel settings, allowed servers, and DNS/NTP/WINS
    pushes (`OpenVpnClientSpecificOverride`, 27 fields).
  - Neither schema component has any `writeOnly` field, unlike the
    Batch G CRL case. `caref`/`certref` are CA/certificate
    *references*, not certificate material, matching this project's
    established treatment of reference IDs as non-secret.
    `tlsauth_keydir` is re-confirmed (a fourth time across sessions)
    to be a direction-flag enum, not key material. The singular
    `vpn/openvpn/server` endpoint is redundant with the plural
    `vpn/openvpn/servers` (same underlying model) and is deliberately
    not implemented, matching the established NAT-mappings precedent.
  - Network/address fields (`local_network`/`local_networkv6`/
    `remote_network`/`remote_networkv6`/`tunnel_network`/
    `tunnel_networkv6`/`dns_server1-4`/`ntp_server1-2`/
    `wins_server1-2`/`serverbridge_dhcp_start`/`serverbridge_dhcp_end`
    on the server model; `common_name` plus the same address-field set
    on the client-specific-override model) are redacted by default,
    matching `RoutingStaticRoute.gateway`'s established convention.
  - 37 of `OpenVpnServer`'s 73 fields and 5 of
    `OpenVpnClientSpecificOverride`'s 27 fields are schema-documented
    as only available under a specific `mode`/`use_tls`/`gwredir`/
    `ping_action` condition and are treated as genuinely
    possibly-absent via `.get()`, matching the `InterfaceLAGG`/
    `TrafficShaperQueue` precedent.
  - LAB-verified `ENDPOINT_VERIFIED` for both (zero configured OpenVPN
    servers and zero client-specific overrides on this LAB). No
    package required for either (base pfSense feature).

### Security

- **Two confirmed secret-bearing schema fields are never modeled at
  all**, not merely redacted behind a flag: `VirtualIP.password` (the
  CARP shared advertisement secret between HA peers) and
  `CertificateAuthority.prv` (the CA private key) — mirroring the
  already-shipped `SystemCertificate` model's own established treatment
  of the identical `prv` distinction. Proven by construction
  (`hasattr(model, "password"/"prv")` is `False`), independently
  confirmed against real LAB data for the CA case.
- A draft test fixture containing a placeholder `password` key was
  caught and rejected by this project's own `fixture_safety.py`
  prohibited-credential-field scan before it reached `main` — fixed by
  injecting secret-field values into the raw response only in-memory,
  at test time, never in a committed fixture file.
- `SystemRestApiVersion.install_version` is modeled as optional: LAB
  verification found it genuinely absent from a real live response (not
  merely `null`), a compatibility finding the schema alone did not
  surface.
- **`WireGuardPeerStatus.preshared_key` is confirmed present in the
  live *status* object** (not merely the config object) and is **never
  modeled at all**, matching the `VirtualIP.password`/
  `CertificateAuthority.prv` precedent exactly. `WireGuardTunnelStatus.peers`
  is schema-confirmed to embed full `WireGuardPeerStatus` objects and is
  constructed through that model's own parser for every nested item —
  a raw-dict passthrough there would have silently leaked
  `preshared_key` verbatim into the tunnel-status tool's output.
  Independently re-confirmed via the owner's pfREST 2.10 settings-UI
  sensitive-field classification, which agrees with every exclusion
  this project has already made
  (`OpenVPNClient.proxy_passwd`/`.auth_pass`, `VirtualIP.password`,
  `CertificateAuthority.prv`, `WireGuardPeer.presharedkey`,
  `WireGuardPeerStatus.preshared_key`, `WireGuardTunnel.privatekey`) —
  this project's own model-level exclusions remain the enforcement
  mechanism regardless; pfREST's own redaction behavior, if any, is
  never relied upon.
- `OpenVpnServerConnectionStatus.common_name`/`.user_name` and the
  analogous `common_name` fields elsewhere in the OpenVPN status
  cluster are real per-connection human/device identity data, not
  merely network topology — redacted by default like other identifying
  fields, with the extra care this class of field warrants noted
  explicitly rather than treated as an ordinary address field.
- **Release-readiness audit (2026-08-21): hardened the global
  credential-disclosure regression test.**
  `tests/test_credential_non_disclosure.py`'s `PROHIBITED_FIELDS` set,
  which is scanned against every registered tool's full input/output
  MCP schema, previously only checked for `{ipsecpsk, password, key}`
  by exact field name — a future field literally named `auth_pass`,
  `proxy_passwd`, `privatekey`, `presharedkey`, `preshared_key`, or
  `prv` would not have been caught by this specific automated check
  even though this project has explicitly committed to excluding
  every one of those names. Expanded the set to all seven. Confirmed
  zero regressions and zero live hits with the expanded set across all
  84 registered tools.

### Changed

- **Release-readiness audit (2026-08-21): independently re-verified and
  documented pfSense CE/Plus compatibility.** pfSense CE 2.9.0 remains
  the **LAB VERIFIED** baseline (unchanged). Added **pfSense Plus
  26.07 — LIVE VERIFIED**: an owner-authorized, strictly READ-only
  production compatibility pass (identity verified first; no
  POST/PUT/PATCH/DELETE, no package/config/privilege changes performed)
  found the live OpenAPI schema structurally identical to the pinned
  v2.10 reference (267/267 paths, 186/186 components — the only
  differences across every field were 5 instance-specific runtime
  default values, never a type or nullability change), and successfully
  exercised 82 of the 84 public READ tools against real production data
  (30 of those as valid, meaningful empty envelopes); the remaining 2
  (`pfsense_get_status_wireguard_tunnels`/`_peers`) were correctly and
  automatically classified package-absent (WireGuard not installed on
  that appliance, and not installed by this audit) rather than treated
  as a failure. Zero genuine incompatibilities found; a targeted
  secret-safety re-check against the seven highest-risk live tool
  responses found zero prohibited field names. Added **pfSense Plus
  25.11 — SUPPORTED/COMPATIBLE (not live-verified)**, an explicit
  inference from converging platform/schema evidence (same FreeBSD
  16-CURRENT base OS as the verified CE 2.9.0/Plus 26.07 evidence; one
  platform-version step from a build already proven to have zero schema
  drift; the same pinned pfREST v2.10 package already confirmed
  compatible across three separate platform/edition combinations),
  explicitly not a test result.
- **Corrected the published-baseline framing used throughout this
  `[Unreleased]` narrative.** Git archaeology (checking
  `KNOWN_READ_TOOL_NAMES`'s length at the actual `v0.4.2` git tag,
  cross-checked against README's and v0.4.2's own `CHANGELOG` entry,
  both of which already correctly said 42) proved the true
  last-published baseline this entire READ-expansion audit measures
  against was **42 tools, not 44** as this section originally stated.
  The correct headline for this release is **42 → 84 public READ
  tools, exactly a 100% increase** (not 44 → 84 / ~91%). The two
  "extra" tools accounting for the discrepancy
  (`pfsense_get_firewall_nat_outbound_mappings`/
  `pfsense_get_firewall_nat_one_to_one_mappings`) were live-verified
  against production and registered before this audit's own tracked
  narrative began, but had never received their own `Added` bullet —
  fixed above.
- **Full README restructure** (key facts → what you can do → why this
  server → quick start → requirements/compatibility → MCP client setup
  → capability overview → security model → troubleshooting →
  documentation → release status → contributing/license), including a
  category-level capability overview table and a symptom/cause/action
  troubleshooting table. Structural/UX patterns only (badges,
  table-based summaries, per-client setup subsections) were drawn from
  surveying other pfSense MCP projects' README conventions for
  inspiration — no wording, architecture, or security claims copied
  from any external project.

### Fixed

- **LAB CE 2.8.1 → 2.9.0 platform-upgrade regression** (2026-08-21): a
  full regression smoke test of all 51 public READ tools against the
  freshly upgraded LAB appliance (pfSense CE 2.9.0-RELEASE, FreeBSD
  16.0-CURRENT, reinstalled `pfSense-pkg-RESTAPI` v2.10 — same REST API
  version, same 267-path schema, distinct install) found 2 of 51 tools
  now fail shape validation: `pfsense_get_dhcp_servers` and
  `pfsense_get_dns_resolver_settings`. Root cause: for an unconfigured
  optional field (e.g. no DHCP scope domain/gateway set, no DNS-over-TLS
  certificate configured), the platform now returns `null` where the
  original 2.8.1 LAB capture had returned an empty string/list — the
  pinned schema still declares these fields `nullable: false` in both
  cases, so live server behavior was trusted over the schema's stale
  claim (matching this project's own `install_version` precedent).
  `DhcpServer.domain`/`.domainsearchlist`/`.failover_peerip`/`.gateway`/
  `.mac_allow`/`.mac_deny` and `DnsResolverSettings.sslcertref`/
  `.tlsport` are widened to also accept `None`; existing 2.8.1-shaped
  fixtures (empty string/list) continue to validate unchanged. All 51
  tools re-verified passing against the upgraded LAB after the fix; no
  tool count change (51 unchanged), no new capability, no security
  impact — a pure type-widening correctness fix.
- **Release-readiness audit (2026-08-21): three stale-documentation
  findings.** Two model docstrings
  (`firewall_nat_one_to_one_mapping.py`, `firewall_nat_outbound_mapping.py`)
  still said "Not yet cross-checked... verified (False)" despite both
  `Endpoints` entries having been `verified=True` for some time.
  `docs/PYPI_RELEASE.md`'s release checklist hardcoded "Confirm 42 READ
  tools" — would have misdirected the owner during this very release;
  replaced with a pointer to the live registry check instead of a
  number that will go stale again next release.

## [0.4.2] - 2026-08-16

**Documentation/packaging presentation patch — no functional or
security-relevant change, and no new security capability of any kind.**
This release exists solely to make the already-reviewed README and
documentation-site improvements below available through the PyPI
long_description before wider community launch; `v0.4.1`'s own
functional and security state is carried forward unchanged.

### Fixed

- **Portable README links for PyPI.** 29 README link occurrences across
  11 distinct targets were repository-relative (`docs/API.md`,
  `LICENSE`, `SECURITY.md`, etc.) — these resolve on GitHub but silently
  404 when the same file is rendered as the PyPI long_description,
  since PyPI's renderer has no repository filesystem context. Converted
  to either the published MkDocs page (where one exists) or an absolute
  GitHub blob URL, following the same convention `mkdocs.yml` already
  used for its own non-MkDocs-published links. Added a small regression
  check (`readme_portability_errors` in `scripts/validate_docs.py`,
  wired into `make validate`) that fails the build if a repo-relative
  link is ever reintroduced into README.
- **Corrected a stale "41-tool catalog" reference** in README — the
  public MCP contract has been 42 tools (0 WRITE by default) since
  v0.3.1; every other reference in README, `docs/API.md`, and
  `scripts/public_contract.py` already agreed on 42.
- **`docs/ACCEPTANCE_v0.4.0.md`'s status line corrected.** It still read
  "published — the v0.4.0 tag and PyPI release point at this commit,"
  written before v0.4.0's PyPI publish failure was discovered. Corrected
  to accurately describe the failed attempt and point to v0.4.1 as the
  fix. The `v0.4.0` git tag/GitHub Release themselves were not touched.

### Added

- **7 documentation pages exposed in the deployed MkDocs navigation**
  that existed in the repository but were never linked from `mkdocs.yml`'s
  nav: the `v0.3.0`/`v0.3.1`/`v0.4.0`/`v0.4.1` acceptance records and
  `ADR-027`/`ADR-028`/`ADR-029`. The deployed documentation site itself
  was also stale (last built from a 2026-08-09 commit) and has been
  redeployed from current `main`, publishing these plus everything else
  added since then (`ADR-020` through `ADR-026`, the TPM host-witness
  and production-store-bootstrap subsystem specs).
- **Public-facing security description improvements** in README's
  "Security-first by design" section: an added framing sentence
  contrasting this project's multi-party WRITE-approval pipeline
  against the common "API credential behind a tool call" pattern, and a
  more concrete closing evidence paragraph (twice-exercised, each
  independently verified, via a dedicated 4-privilege pfSense identity,
  TPM witness confirmed against physical hardware both times) — every
  claim traces directly to `docs/adr/ADR-026-first-write-capability-adapter.md`'s
  existing evidence chain; nothing new is asserted beyond what that
  document already substantiates. The "42 READ / 0 WRITE" line on the
  first screen now states directly that the one WRITE capability
  requires explicit operator opt-in and a per-mutation authorized
  approval, rather than requiring a scroll to find that out.

## [0.4.1] - 2026-08-16

**Release repair — no functional or security-relevant change from
v0.4.0.** v0.4.0 was tagged and its GitHub Release published, but the
PyPI publish workflow failed before any upload was attempted (see
"Fixed" below); this release corrects that and two documentation
inaccuracies discovered while diagnosing it. All of v0.4.0's
[0.4.0] entry below still applies unchanged — same public MCP contract
(42 READ / 0 WRITE by default), same `verified=True` live-evidence
chain, same Tier 1 architecture.

### Fixed

- **PyPI publish failure**: `publish.yml`'s build step failed
  `twine check --strict` with `InvalidDistribution: Invalid distribution
  metadata: '2.5' is not a valid metadata version`. Root cause: the
  isolated build environment resolved a Hatchling release that emits
  Core Metadata 2.5 by default, which the pinned `twine<7.0` does not
  yet accept. Fixed by tightening `[build-system] requires` to
  `hatchling>=1.25,<1.32` — 1.31.0 is the confirmed, directly-verified
  ceiling that still emits Metadata-Version 2.4 (isolated-equivalent
  build re-run, `Metadata-Version: 2.4` inspected directly in the built
  wheel, `twine check --strict` passing on both artifacts). No PyPI
  upload was ever attempted for v0.4.0 — confirmed via the publish
  workflow's job status (`publish` job: `skipped`, never ran) and a
  live query against the real PyPI API (latest published version
  remained `0.3.0`).
- **README/CHANGELOG incorrectly claimed v0.3.1 was published on
  PyPI.** Investigated read-only from git tag history, GitHub Release
  history, `publish.yml`'s run history, and the live PyPI API: **no
  `v0.3.1` git tag, GitHub Release, publish-workflow run, or PyPI
  upload has ever existed.** v0.3.1 was prepared only — version bumped
  and `docs/ACCEPTANCE_v0.3.1.md`/this changelog's `[0.3.1]` entry
  written — in commit `459262e` (2026-08-09), but the tag/release/
  publish sequence was never carried out, and the "published on PyPI"
  claim that crept into README's status paragraph afterward was false
  for the entire time it stood. `docs/ACCEPTANCE_v0.3.1.md` itself made
  no publication claim and needed no correction — only README and this
  file's `[0.3.1]`/`[0.4.0]` footer links, which pointed at a
  nonexistent tag/release, have been corrected to reference the real
  commit instead.

## [0.4.0] - 2026-08-16

**Public MCP contract is unchanged from v0.3.1: 42 READ tools, 0 WRITE
tools under the default profile.** This release's headline change is
that the one accepted WRITE capability
(`set_firewall_alias_description_v1`) is now `verified=True`, following
two independently-verified live mutations against a disposable LAB
appliance and a strict, owner-confirmed re-check of every ADR-026
acceptance-matrix row. This does **not** enable WRITE by default:
reaching the tool still requires an operator to explicitly select
`PFSENSE_PROFILE=write_protected`, and every individual mutation still
requires the operator to personally drive a real, off-host-signed
authorization → one-time-consumption → `RecoveryContract` → confirmation
→ sealed-executor ceremony — nothing about it is automatic or
AI-triggerable. See `docs/adr/ADR-026-first-write-capability-adapter.md`
for the complete evidence chain and `docs/SECURITY_MODEL.md`'s "Recovery
and WRITE status" for the current, precise description of what is and
is not exposed.

### Migration / upgrade notes

- No breaking change for any existing default (`auditor`/`engineer`)
  deployment — the public contract, tool names, schemas, and behavior
  are byte-identical to v0.3.1's.
- Operators who have not opted into `write_protected` need to do
  nothing.
- Operators who intend to use the now-verified WRITE capability must
  still independently provision the full Tier 1 security material
  (pinned authorities, an encrypted `RecoveryContract` store, TPM witness
  connectivity) — `verified=True` alone does not make the tool reachable
  without it; `build_production_runtime()` returns `None` and no tool is
  registered if any of that material is missing or misconfigured.

### Added

- **Two real pfSense mutations performed and authoritatively verified,
  followed by `WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified=True`**
  (2026-08-16, disposable LAB appliance only, never production/home
  pfSense): a full owner-authorized, per-artifact-independently-verified
  ceremony (fresh authorization → one-time consumption →
  `RecoveryContract` → confirmation → exactly one
  `PATCH /api/v2/firewall/alias`) reached `RecoveryContract` state
  `VERIFIED` with a clean, MAC-authenticated audit trail and no
  rollback/reconciliation event, twice: once establishing the temporary
  Slice 6 marker (TPM witness `2 → 3`), and a second time restoring the
  alias's original description (`Disposable LAB-T1 synthetic test alias`,
  TPM witness `3 → 4`) — the second WRITE performed entirely through a
  newly-provisioned, independently-verified least-privilege pfSense
  identity (`pfsense_mcp_tier1_lab`) holding only the four minimum
  privileges the production path needs, never the admin credential. Both
  witness advances independently confirmed against the persisted
  high-water mark. ADR-026's acceptance-matrix rows 6, 17, and 18 (the
  live-evidence gap) and the remaining seven offline-evidenced rows were
  then re-checked, row by row, against an owner-confirmed strict
  evidentiary standard; all survived, and
  `FIREWALL_ALIAS_DESCRIPTION.verified` was set `True`. This does not
  change the default public MCP contract — still 42 READ / 0 WRITE tools
  under the default profile; reaching the WRITE path still requires an
  operator to explicitly select `PFSENSE_PROFILE=write_protected` and
  personally drive a real, owner-approved signing ceremony for each
  individual mutation. See
  `docs/adr/ADR-026-first-write-capability-adapter.md`'s live-evidence
  and strict-re-check sections for the full chain.
- `pfsense-mcp-security`: a new, separately-installed CLI (`ADR-021`,
  Accepted; Phase B of `docs/SECURITY_POSTURE_PROVISIONING.md`) offering
  one subcommand, `discover`, which reports the current capability-posture
  (`read_only`/`write_protected`) and anchor-assurance
  (`none`/`software`/`hardware_witness`) axis state, read-only, with
  human-readable and deterministic `--json` output. Correctly recognizes
  `read_only` + `hardware_witness` (this project's own real production
  state) as a valid, representable combination. Never calls
  `provision_anchor_baseline()`, `advance()`, or anything else that
  mutates the Tier 1 store, the TPM, or pfSense — proven by dedicated
  structural (AST) and behavioral tests. **Does not change the public
  MCP contract** — still 42 READ tools, 0 WRITE tools; this is a
  standalone CLI (`src/pfsense_mcp/security_cli.py`,
  `src/pfsense_mcp/security_discovery.py`), not an MCP tool. No
  provisioning/setup subcommand exists yet — that is Phase C onward,
  each its own future, separately-authorized work.
- `pfsense-mcp-security plan --capability-posture <value> --anchor-assurance
  <value>`: a second, equally read-only/mutation-free subcommand
  (`src/pfsense_mcp/security_plan.py`) that bridges `discover`'s "what
  state do I have?" to "what would need to happen to reach a selected
  target?" — `DISCOVER → SELECT TARGET → EVALUATE VALIDITY → ASSESS
  PREREQUISITES → GENERATE PLAN`, then stops, before `PROVISIONING`.
  Enforces `ADR-021`'s validity constraint (`write_protected` requires
  anchor assurance `≠ none`), distinguishes a valid-but-unimplemented
  target (`anchor_assurance=software`, and — a finding made by reading
  the actual code — WRITE activation itself, since
  `src/pfsense_mcp/tools/write/` is still an empty placeholder) from an
  invalid one, orders anchor-assurance provisioning before
  capability-posture activation on upgrade and the reverse on a joint
  downgrade (never passing through the disallowed `write_protected` +
  `none` combination even momentarily), and represents downgrades as
  DEACTIVATE only, never DEPROVISION. **A generated plan is never
  authorization to execute it** — every plan states this in its own
  machine-readable `notes` field; no `select`/`apply`/`provision`
  subcommand exists in this build. Never imports `pfsense_mcp.tier1`
  (its only evidence source is `discover_security_posture()` itself) —
  proven structurally and behaviorally, including a test that fails if
  plan generation ever touches `sqlite3.connect`/`open`. An adversarial
  self-review before this was committed found and fixed two real
  defects: (1) a raw string target could bypass the validity constraint
  via an `is`-vs-`==` mismatch on the `(str, Enum)` axis types, now
  closed by coercing both targets through their `Enum` constructor; (2)
  an indeterminate current anchor-assurance state (a malformed/foreign
  file already at the configured store path) was being silently treated
  as a clean slate safe to provision on top of, now surfaced as
  `PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE` instead. **Does
  not change the public MCP contract** — still 42 READ tools, 0 WRITE
  tools.
- ADR-022 (execution-authorization boundary — `Plan → Authorize →
  Execute → Verify`) Accepted, and its own Phase B implemented:
  `security_plan_digest.py`'s `compute_plan_digest()`/`verify_plan_digest()`
  give every `SecurityPosturePlan` a canonical, deterministic
  `PlanDigest` (SHA-256, `tier1.canonical.digest_value()` reused, new
  `DigestPurpose.PLAN` domain separator) — plan identity only, never
  authorization, a secret, a bearer token, or proof of operator consent.
  Third, narrow `pfsense_mcp.tier1` isolation exemption, importing only
  `canonical` (pure hashing, zero I/O), never the store/witness/anchor
  machinery. `pfsense-mcp-security plan` now shows the digest in both
  human output and `--json` (`plan_digest`/`plan_digest_schema_version`
  keys). 54 new tests (46 regression + 8 AST-based isolation), including
  exact per-field participation proofs matching ADR-022's own
  participates/does-not-participate list, duplicate/reordered-step
  handling, schema-version safety, and a no-I/O behavioral proof. No
  authorization artifact, verification, or execution code exists —
  still 42 READ tools, 0 WRITE tools, `WriteEndpoints` empty, WRITE 0/3.
- ADR-022 Phase C implemented: `security_authorization.py` adds
  `PlanAuthorization`/`DeprovisionAuthorization` — signed, expiring,
  narrowly-scoped authorization artifacts (structurally mirroring
  `ConfirmationEvidence`/`ADR-012` one layer up) — their canonical
  signing payloads, and `sign_plan_authorization()`/
  `sign_deprovision_authorization()`, pure Ed25519 signing functions
  over caller-supplied key material. **Signing construction only; no
  verification, consumption, replay tracking, freshness enforcement,
  execution, or `RecoveryContract` creation exists anywhere in this
  repository.** `PlanAuthorization` binds `plan_digest` (exact, via
  `compute_plan_digest()`) and an explicit, non-empty, duplicate-free
  `authorized_step_ids` set (never a wildcard; unknown/disallowed step
  IDs rejected at construction) plus a `risk_class` (`AuthorizationLevel`)
  computed from the authorized steps themselves, not caller-supplied.
  `DeprovisionAuthorization` is a wholly separate artifact type (own
  schema, own `DigestPurpose.DEPROVISION_AUTHORIZATION` domain, no
  `plan_digest`/`authorized_step_ids` field at all) — never a boolean
  flag on `PlanAuthorization`, and no code path anywhere in this
  repository computes a real `target_identity_digest` for it. Both new
  `DigestPurpose` members (`PLAN_AUTHORIZATION`/`DEPROVISION_AUTHORIZATION`)
  are additive; both signing payloads carry an explicit `"digest_purpose"`
  tag for structural domain separation from each other and from
  `ConfirmationEvidence`/`ReconciliationEvidence`. Fourth, narrow
  `pfsense_mcp.tier1` isolation exemption (only `canonical`). No CLI
  subcommand or MCP tool added — this module is never imported by
  `security_cli.py` or any tool-registration code path (proved by AST
  isolation tests). 64 new tests (55 regression/adversarial + 9
  AST-based isolation), including cross-type signature non-verification,
  step-set widening-after-signing detection, and a no-I/O behavioral
  proof. Still 42 READ tools, 0 WRITE tools, `WriteEndpoints` empty,
  WRITE 0/3. **A final adversarial pre-push review found and fixed one
  real coercion-safety defect**: `PlanAuthorization`'s `risk_class`
  validation used dict-membership alone, which a raw string equal to an
  `AuthorizationLevel` member's value could satisfy without being that
  enum type — fixed with an explicit `isinstance()` check matching this
  codebase's own established `(str, Enum)`-field precedent, plus 7 more
  regression/coverage tests (71 total).
- ADR-022 Phase D implemented: `security_authorization_verifier.py`
  adds pure `PlanAuthorization` verification —
  `verify_plan_authorization_signature()` (mirrors
  `Ed25519ConfirmationVerifier.verify()`, reusing
  `PinnedAuthoritySet` unchanged, fifth narrow `pfsense_mcp.tier1`
  isolation exemption), `plan_authorization_is_current()` (independent
  expiry check, no freshness policy invented), and
  `plan_authorization_authorizes_step()` (exact `plan_digest` +
  `authorized_step_ids` binding, never a wildcard/prefix/subset match)
  — three separate, never-composed primitives. New
  `tier1/authorization_consumption_store.py` adds durable, one-time
  `authorization_id` consumption tracking (`AuthorizationConsumptionStore`
  Protocol + `SqliteAuthorizationConsumptionStore`), a wholly separate,
  minimal, HMAC-authenticated store — never extends
  `SqliteRecoveryContractStore`, atomic via the same `BEGIN IMMEDIATE`
  + unique-constraint discipline that store already uses. **Signature
  validity, expiry, and consumption are independently checked; none
  implies another.** No freshness re-check (`ADR-022`'s own Phase E),
  no `RecoveryContract` creation, no execution coordinator, no MCP
  tool, no wiring into `MutationExecutor`/the Tier 1 state machine/
  `WriteApiClient`/`WriteEndpoints`. 60 new tests (23 verifier + 9
  verifier-isolation + 21 store + 4 store-isolation + 3 cross-module
  independence proofs). See
  `docs/adr/ADR-023-authorization-verification-boundary.md`'s "Owner
  decisions"/"Implementation status" sections for the full design
  record. Still 42 READ tools, 0 WRITE tools, `WriteEndpoints` empty,
  WRITE 0/3.

### Changed

- `SecurityPosturePlan.safe_to_proceed`'s meaning clarified (documentation
  only — behavior, computation, and published JSON schema unchanged): a
  class docstring, an inline CLI caveat, and a `plan --help` epilog
  sentence now state explicitly that `True` means only that the target
  is architecturally valid and current evidence shows no detected
  anomaly — never authorized, approved, executable, or that every step
  is unblocked.

### Fixed

- The declared `mcp>=1.0.0` minimum dependency version was false: every
  `mcp` SDK release from `1.0.0` through `1.21.0` either fails to import
  (`mcp.server.fastmcp`/`mcp.types.ToolAnnotations` did not exist yet in
  earlier releases) or crashes during tool registration
  (`TypeError: issubclass() arg 1 must be a class`, inside `mcp`'s own
  code). `mcp>=1.21.1` is the first release confirmed, by installing at
  exactly that floor and running the full test suite, to actually work.
  The floor is now `mcp>=1.21.1,<2.0.0`. A new CI job and
  `make min-deps-check` (wired into `make release-check`) install at
  `--resolution=lowest-direct` going forward so a regression of this kind
  fails CI instead of only surfacing for someone who happens to pin an
  old `mcp` release.

## [0.3.1] - 2026-08-09

### Added

- `pfsense_mcp_info`: a new READ-only server-introspection tool. Reports this
  server's own version, active capability profile, registered tool counts,
  active WRITE capabilities/endpoints (always empty in this build), and
  Tier 1/ADR-017 presence — deterministic local process facts only, no
  pfSense API call. Production contract: **42 READ tools, 0 WRITE tools**
  (up from 41; this is the only functional change in this release). Gated
  by a new `SERVER_INFO_READ` capability, following the same per-capability
  registration pattern as every other tool — an empty capability set still
  registers nothing. `openWorldHint=false` for this tool specifically,
  since it never contacts pfSense (every other tool remains
  `openWorldHint=true`). See `docs/API.md`'s "Server introspection" section.

### Security

- `pfsense_mcp.tier1` and `pfsense_mcp.guidance` presence/import status is
  now independently, mechanically observable at runtime via
  `pfsense_mcp_info` (`tier1_package_present`, `tier1_imported_this_process`,
  `guidance_package_present`, `guidance_imported_this_process`), in addition
  to the existing CI-enforced isolation tests — not a replacement for them.

## [0.3.0] - 2026-08-09

Production contract is unchanged from v0.2.2: **41 READ tools, 0 WRITE
tools.** This release ships the inert v0.3.0 Tier 1 safety architecture
and the inert ADR-017 documentation-guidance layer as implemented,
tested, structurally isolated code — neither is reachable from
production, neither registers an MCP tool, and no mutating capability,
endpoint, or transport path is active.

### Added

- Inert v0.3.0 Tier 1 domain framework: canonical Recovery Contracts, closed
  legal state transitions, authenticated atomic persistence, exact mutation
  policy bindings, fault classification, and value-free audit events.
- Full Tier 1 subsystem implementation, each independently reviewed, tested,
  and still entirely unreachable from production: protected-artifact
  encryption and key lifecycle, a whole-store anti-rollback protocol,
  Ed25519 confirmation and reconciliation authorities, rate/blast-radius
  containment, and a sealed mutation executor composing all of them behind
  exactly one (still-empty) send chokepoint.
- An offline-only disposable-lab fault-injection harness (`lab/`, not
  packaged, not part of the default test run) for exercising Tier 1's fault
  scenarios against `MockTransport` before any real capability adapter or
  live lab VM exists.
- Adversarial offline tests for replay, tampering, stale state, target
  concurrency, restart reconciliation, and injected persistence failures.
- Implementation-ready Tier 1 architecture, an accepted 6-phase
  implementation roadmap, 16 Architecture Decision Records, 10 subsystem
  specifications, a disposable-lab plan, and a conservative inventory of
  writable upstream endpoint classes.
- An MkDocs documentation site organizing the full `docs/` reference into
  a browsable nav, published at
  [night4me.github.io/pfsense-mcp-server](https://night4me.github.io/pfsense-mcp-server/).
- CI hardening: a bandit static-security stage in both `make quick` and
  `make validate` (previously CI-only), a documentation-site build check,
  and a dependency-review check on pull requests.
- Expanded `CONTRIBUTING.md` (local-setup troubleshooting, git/PR workflow,
  a full documentation map) and `SECURITY.md` (explicit security
  guarantees, non-goals, and vulnerability-report scope).
- `make sbom`: generates a CycloneDX JSON Software Bill of Materials from
  a clean, isolated install of a freshly built wheel (never the developer
  host), using a pinned `cyclonedx-bom` version in a separate throwaway
  venv, then verifies the result offline (`scripts/verify_sbom.py`)
  before writing it to the git-ignored `dist/sbom/`. Deliberately outside
  `quick`/`validate`/`release-check` (requires network access to install
  the pinned generator tool); generating the SBOM is not the same as
  publishing it — attaching it to a release remains a separate, explicit
  owner decision (`docs/DEPENDENCY_POLICY.md`).
- ADR-017 and its companion spec (`docs/OFFICIAL_GUIDANCE_LAYER.md`):
  architecture for an official pfSense/Netgate documentation guidance
  layer — a deterministic, capability-keyed registry over a curated
  bundled/offline snapshot corpus, returning structurally non-authorizing,
  provenance-preserved references. Documentation is explicitly treated as
  untrusted content even from a trusted source and can never become
  authorization, enforced by isolation from every safety-authority code
  path, not just by policy. Architecture and inert scaffolding only — no
  READ tool output or Tier 1 PREPARE path consumes it yet; live retrieval
  and semantic search are named and deferred, not built.

### Security

- Production mutation remains unreachable: the Engineer profile is empty, the
  WRITE endpoint allow-list is empty, no WRITE tool registers, and the entire
  Tier 1 package remains absent from production bootstrap — verified by
  dedicated tests after every change, not only documented as intent.
- Stored Tier 1 records are integrity-authenticated; protected payloads use
  AES-256-GCM with domain-separated associated data. Two design flaws were
  found and fixed by tests before any code shipped: an anti-rollback
  comparison that checked the wrong direction for the primary rollback
  threat, and a confirmation-signature scheme that was circular as
  originally specified. Both are documented in their governing
  specifications with the original design and the fix.
- Production activation remains blocked on genuine owner/infrastructure
  decisions (an anti-rollback hardware backend selection; a live
  disposable-lab evidence run) and an explicit capability/endpoint
  authorization — none of which this release grants.
- New `make quick`/`make validate` stage (`scripts/git_identity_check.py`):
  checks configured Git identity and recent commit metadata against a
  small blocklist of known-leaked identity values, stored as SHA-256
  hashes rather than plaintext. Added after a real personal email
  briefly reappeared in two commits following an earlier remediation,
  undetected by any existing check (none inspect commit metadata).

## [0.2.2] - 2026-08-07

### Added

- Public CI across Python 3.11, 3.12, and 3.13.
- Branch coverage reporting, Bandit, and CodeQL configuration.
- Sdist/wheel inspection and clean installed-entry-point verification.
- Security, contribution, release-workflow, and project-agent guidance.
- Threat model, architecture diagrams and decisions, public roadmap, benchmark
  methodology, and MCP client setup guides.
- GitHub issue and pull-request templates.
- Public API, type-quality, documentation, and final repository reviews.
- MCP ToolAnnotations on every production READ tool.
- Deterministic public MCP contract snapshot and offline release-candidate,
  reproducible-build, documentation-consistency, and artifact-manifest checks.
- Implementation-independent Recovery Contract field, canonicalization, state,
  fault, and reconciliation specification for future Tier 1 review.

### Changed

- Package version prepared for v0.2.2 project hardening.
- README expanded for first-time installation and operation.
- Optional exact-name `PFSENSE_ALLOWED_TOOLS` restriction intersects with the
  selected capability profile and fails closed on unknown names.
- Tier 1 roadmap strengthened for canonical target fingerprints, unstable IDs,
  config-history conflicts, atomic rate/concurrency policy, and compensation
  failure reconciliation; Tier 1 remains blocked.
- Auditor profile now derives directly from the supported READ capability set,
  removing a duplicated activation list without changing the capability surface.

### Security

- Tool annotations remain untrusted client hints; capability, endpoint,
  GET-only, credential, audit, and WRITE-inactivity controls remain
  authoritative.
- Bound API-key metadata validation and bounded reading to one non-following
  file descriptor, eliminating path replacement between check and use.
- Replaced certificate inventory fixtures prospectively with wholly synthetic
  `.invalid` certificate identities. No private key is committed; historical
  public certificate material remains in Git history and contained no secret.
- Reject all non-2xx upstream statuses, including redirects, and normalize
  remaining HTTP transport failures without exposing upstream exception text.
- Reject encoded and Unicode control/format characters at configuration
  boundaries that can reach URLs, tool restrictions, or logs.
- Distribution inspection rejects private-key content and additional private,
  generated, database, backup, and SSH artifact paths.

## [0.2.1] - 2026-08-06

### Security

- Removed IPsec PSKs, SMTP passwords, and API-key plaintext from public models
  and MCP schemas.
- Removed the auth-key identifying-metadata disclosure argument.
- Hardened audit records without logging arguments, responses, or exception
  messages.
- Sanitized authentication and malformed-response errors.
- Added fail-closed URL, identity, TLS, key-file, and logging validation.
- Prohibited credential fields in approved fixtures and added negative
  disclosure tests.

## [0.2.0] - 2026-08-06

### Added

- Tier 0 WRITE infrastructure, including recovery, rollback, audit, and write
  client primitives.
- Independent checks for an empty WRITE endpoint allow-list and inactive WRITE
  capabilities.

### Security

- Kept all Tier 0 WRITE infrastructure inert and unreachable from production
  bootstrap. No WRITE tool or endpoint was activated.

## [0.1.0] - 2026-08-06

### Added

- Initial production-ready READ-only MCP server.
- Strongly typed pfSense REST API models and capability-gated tools.
- GET-only transport enforcement, sanitized fixtures, and offline tests.

[Unreleased]: https://github.com/night4me/pfsense-mcp-server/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/night4me/pfsense-mcp-server/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/night4me/pfsense-mcp-server/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/night4me/pfsense-mcp-server/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/night4me/pfsense-mcp-server/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/night4me/pfsense-mcp-server/compare/v0.3.0...v0.4.0
<!-- v0.3.1 was prepared (version bump + changelog entry) but never tagged, released, or published -- no v0.3.1 tag/release exists to link to; this points at the commit that bumped the version instead. See the [0.4.1] entry above for the full finding. -->
[0.3.1]: https://github.com/night4me/pfsense-mcp-server/commit/459262e
[0.3.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.3.0
[0.2.2]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.2
[0.2.1]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.1
[0.2.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.2.0
[0.1.0]: https://github.com/night4me/pfsense-mcp-server/releases/tag/v0.1.0
