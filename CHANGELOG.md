# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

**Focused READ capability expansion — no WRITE change, no security-model
change.** Follows an offline-only comprehensive READ capability discovery
audit (267 OpenAPI paths / 243 GET operations reviewed; every GET given
exactly one disposition) that found the prior 44-tool contract covered
roughly 42% of the useful READ capability universe. Prioritized the
audit's P0 backlog (7 candidates, all zero/near-zero risk) and, for each,
independently re-verified the response schema for secrets before
implementation, then live-verified against a disposable LAB appliance
(`pfsense-test.lab.invalid`, pfSense CE 2.8.1-RELEASE, REST API v2.10 —
never production) before public registration.

### Added

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
- **3 more READ candidates implemented and offline-tested (P1 Batch G,
  REST API + PKI metadata) but NOT yet registered** — public MCP
  contract unchanged at 75: `RESTAPIAccessListEntry`,
  `CertificateRevocationList`/`CertificateRevocationListRevokedCertificate`,
  `AvailablePackage` models, `PfSenseClient.get_system_restapi_access_list()`/
  `get_system_crls()`/`get_system_package_available()`, and their
  `Endpoints` entries (`verified=False`) all exist and are fully
  offline-tested. No `tools/read/` file exists for any of the three
  yet, so they remain structurally unreachable through the MCP
  surface. `RESTAPIAccessListEntry.network` (the REST API's own literal
  IP allow/deny CIDR) is redacted by default, matching
  `GatewayConfig.gateway`'s established convention.
  `CertificateRevocationList.cert`/`.text` are each schema-documented
  as only available for a specific `method` value and are treated as
  genuinely possibly-absent, matching the `InterfaceLAGG` precedent.
  Found during re-verification that
  `CertificateRevocationListRevokedCertificate` has five schema fields
  marked `writeOnly: true` — `crt`, `caref`, `descr`, `type`, and
  **`prv`, confirmed to be the revoked certificate's X509 private
  key** — none of these are ever present in a real GET response, and
  none are modeled, matching the `CertificateAuthority.prv`/
  `SystemCertificate.prv` precedent exactly rather than trusting the
  schema's `writeOnly` promise alone.

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

[Unreleased]: https://github.com/night4me/pfsense-mcp-server/compare/v0.4.2...HEAD
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
