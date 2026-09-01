# MCP tool reference

Version: 1.0.0 release state
Profile: `auditor`  
Registered tools: 121 READ, 2 guidance, 0 WRITE

The normalized public contract is checked into
`tests/contracts/mcp_public_contract_v1.0.0.json`. It records tool names,
descriptions, input/output schemas, annotations, capability ownership, client
methods, and verified GET endpoint ownership. `make validate` fails on drift.
After explicit approval of an intentional public API change, regenerate it with
`python scripts/public_contract.py --update`, inspect the complete diff, and
commit the snapshot with the corresponding implementation and documentation.

## Calling convention

Examples use a transport-neutral representation of an MCP tool call:

```json
{"name": "pfsense_get_system_status", "arguments": {}}
```

Your MCP client constructs the protocol envelope. Tool names and argument
objects below are the public contract.

All tools are read-only and issue only allow-listed GET requests. Configuration,
connection, authentication, upstream API, validation, and response-shape
failures are returned as typed, sanitized errors. Raw upstream bodies,
credentials, request headers, and exception messages are never returned.

Every tool advertises MCP `readOnlyHint=true`. Every tool except
`pfsense_mcp_info` also advertises `openWorldHint=true`; `pfsense_mcp_info`
is `openWorldHint=false` because it makes no pfSense API call and reports
only this server process's own local state. `destructiveHint` and
`idempotentHint` are omitted because those hints are defined for tools that
modify their environment. Annotations are untrusted client metadata only.
They do not authorize a call or weaken capability, endpoint, GET-only,
credential, audit, or WRITE-inactivity controls.

`PFSENSE_ALLOWED_TOOLS` may restrict registration to comma-separated exact
names from this reference. It is intersected with the selected capability
profile: absent preserves the profile, an empty value registers zero tools,
and unknown names or wildcard syntax fail startup. The restriction never adds
a tool. It does not change any tool's name, parameters, return schema, or
security behavior.

Common parameters:

- `limit` — integer from 1 through 100; defaults to 100. It bounds list
  retrieval and is passed to the approved upstream endpoint.
- `include_identifying_metadata` — boolean; defaults to `false`. When true,
  the named tool may include the specific optional sensitive metadata listed
  in its security note. It never enables credential disclosure.

## System and platform

### `pfsense_get_system_status`

- **Purpose:** Return platform, uptime, CPU, memory, load, and system identity
  status.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `SystemStatus`.
- **Security:** The persistent Netgate/device identifier is omitted by default.
  Credentials are never part of the model.
- **Example:** `{"name":"pfsense_get_system_status","arguments":{}}`

### `pfsense_get_system_version`

- **Purpose:** Return installed, latest, and base pfSense version information.
- **Parameters:** None.
- **Returns:** `SystemVersion`.
- **Security:** Version data can aid fingerprinting; share it only with trusted
  MCP callers.
- **Example:** `{"name":"pfsense_get_system_version","arguments":{}}`

### `pfsense_get_system_packages`

- **Purpose:** List installed packages, versions, descriptions, and update
  availability.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[SystemPackage]`.
- **Security:** Package inventory reveals installed services and attack
  surface; results are bounded but not redacted.
- **Example:** `{"name":"pfsense_get_system_packages","arguments":{"limit":20}}`

### `pfsense_get_system_package_available`

- **Purpose:** List packages available for installation: name, version,
  description, and installed status.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[AvailablePackage]`.
- **Security:** Package catalog metadata only; not redacted.
- **Example:** `{"name":"pfsense_get_system_package_available","arguments":{"limit":20}}`

### `pfsense_get_system_tunables`

- **Purpose:** List FreeBSD system tunables with descriptions and current
  values.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[SystemTunable]`.
- **Security:** Tunables can reveal hardening and network-stack configuration;
  no credential value is returned.
- **Example:** `{"name":"pfsense_get_system_tunables","arguments":{"limit":25}}`

### `pfsense_get_system_certificate_authorities`

- **Purpose:** List trusted Certificate Authorities: description,
  trust/serial settings, and the CA certificate itself.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[SystemCertificateAuthority]`.
- **Security:** Public CA certificates are not secrets but can identify
  internal PKI. The CA private key (`prv`) is never returned -- it is not
  modeled at all, mirroring `pfsense_get_system_certificates`'s own
  treatment of the same distinction.
- **Example:** `{"name":"pfsense_get_system_certificate_authorities","arguments":{"limit":10}}`

### `pfsense_get_system_certificates`

- **Purpose:** List certificate inventory, issuer/CA references, validity,
  subject metadata, and public certificate material supplied by the endpoint.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[SystemCertificate]`.
- **Security:** Public certificates are not secrets but can identify hosts,
  organizations, and internal PKI. Private keys and passphrases are never
  returned.
- **Example:** `{"name":"pfsense_get_system_certificates","arguments":{"limit":10}}`

### `pfsense_get_system_crls`

- **Purpose:** List Certificate Revocation Lists (CRLs).
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[CertificateRevocationList]`.
- **Security:** CRLs are inherently public documents by design. No
  `prv`-equivalent field exists on this component; the nested revoked-
  certificate entries never include the revoked certificate's private
  key (`prv`, marked `writeOnly` in the upstream schema and never
  modeled at all).
- **Example:** `{"name":"pfsense_get_system_crls","arguments":{"limit":10}}`

### `pfsense_get_system_restapi_access_list`

- **Purpose:** List the REST API's own IP allow/deny access list entries.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[RESTAPIAccessListEntry]`.
- **Security:** Literal network CIDRs are omitted by default.
- **Example:** `{"name":"pfsense_get_system_restapi_access_list","arguments":{"limit":10}}`

### `pfsense_get_system_restapi_settings`

- **Purpose:** Return pfSense REST API service state, transport/security
  options, and read-only configuration.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `SystemRestApiSettings`.
- **Security:** HA synchronization host metadata is optional and omitted by
  default. HA passwords are excluded unconditionally.
- **Example:** `{"name":"pfsense_get_system_restapi_settings","arguments":{}}`

### `pfsense_get_system_restapi_version`

- **Purpose:** Return the installed pfSense REST API package's current
  version, latest available version, and update availability.
- **Parameters:** None.
- **Returns:** `SystemRestApiVersion`.
- **Security:** Version/update metadata only; no credentials or topology
  data.
- **Example:** `{"name":"pfsense_get_system_restapi_version","arguments":{}}`

### `pfsense_get_system_hasync`

- **Purpose:** Return High Availability configuration and synchronization
  selections.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `SystemHaSync`.
- **Security:** Synchronization peer/account metadata is omitted by default.
  Passwords are never returned.
- **Example:** `{"name":"pfsense_get_system_hasync","arguments":{}}`

### `pfsense_get_carp_status`

- **Purpose:** Return the current CARP availability state.
- **Parameters:** None.
- **Returns:** `CarpStatus`.
- **Security:** Reveals HA role/health but no peer credential or mutation
  control.
- **Example:** `{"name":"pfsense_get_carp_status","arguments":{}}`

### `pfsense_get_system_hostname`

- **Purpose:** Return the current system hostname and domain.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `SystemHostname`.
- **Security:** Literal hostname/domain are omitted by default (a
  conservative-posture judgment call, not a schema-confirmed secret).
- **Example:** `{"name":"pfsense_get_system_hostname","arguments":{}}`

### `pfsense_get_system_timezone`

- **Purpose:** Return the current system timezone.
- **Parameters:** None.
- **Returns:** `SystemTimezone`.
- **Security:** General configuration value; not redacted.
- **Example:** `{"name":"pfsense_get_system_timezone","arguments":{}}`

### `pfsense_get_system_dns`

- **Purpose:** Return the current system DNS settings: override policy,
  local-vs-remote resolution preference, and remote DNS servers.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `SystemDNS`.
- **Security:** Literal remote DNS server addresses are omitted by default.
- **Example:** `{"name":"pfsense_get_system_dns","arguments":{}}`

### `pfsense_get_system_console`

- **Purpose:** Return whether a password is required to access the system
  console.
- **Parameters:** None.
- **Returns:** `SystemConsole`.
- **Security:** A boolean flag only, not the password itself; not redacted.
- **Example:** `{"name":"pfsense_get_system_console","arguments":{}}`

### `pfsense_get_system_webgui_settings`

- **Purpose:** Return the current web GUI listener settings: protocol,
  port, and assigned TLS certificate reference.
- **Parameters:** None.
- **Returns:** `WebGUISettings`.
- **Security:** Listener/service posture only; no credential or key
  material (`sslcertref` is a certificate reference, not the certificate
  itself).
- **Example:** `{"name":"pfsense_get_system_webgui_settings","arguments":{}}`

## Interfaces, routing, and neighbors

### `pfsense_get_interfaces`

- **Purpose:** List assigned interfaces and live link/address status.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `list[InterfaceStatus]`.
- **Security:** Literal addresses, MAC addresses, and related device identifiers
  are omitted by default.
- **Example:** `{"name":"pfsense_get_interfaces","arguments":{}}`

### `pfsense_get_interface_configs`

- **Purpose:** List configured interface assignments, addressing, MTU, and
  administrative settings.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[InterfaceConfig]`.
- **Security:** Literal addresses and hardware/parent identifiers are omitted by
  default.
- **Example:** `{"name":"pfsense_get_interface_configs","arguments":{"limit":20}}`

### `pfsense_get_interface_bridges`

- **Purpose:** List bridge interfaces and their member assignments/options.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[InterfaceBridge]`.
- **Security:** Interface membership reveals topology; results contain no
  credentials.
- **Example:** `{"name":"pfsense_get_interface_bridges","arguments":{"limit":20}}`

### `pfsense_get_interface_vlans`

- **Purpose:** List 802.1Q VLAN interfaces: parent interface, VLAN tag,
  priority code point, and resulting VLAN interface identifier.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[InterfaceVlan]`.
- **Security:** Interface/VLAN identifiers only; no address or credential
  material.
- **Example:** `{"name":"pfsense_get_interface_vlans","arguments":{"limit":20}}`

### `pfsense_get_interface_groups`

- **Purpose:** List interface groups: group name, member interfaces, and
  description. Useful for interpreting firewall rules that target a group
  rather than a single interface.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[InterfaceGroup]`.
- **Security:** Interface identifiers only; no address or credential
  material.
- **Example:** `{"name":"pfsense_get_interface_groups","arguments":{"limit":20}}`

### `pfsense_get_interface_available_interfaces`

- **Purpose:** List all interfaces available for assignment on this pfSense
  appliance (not just already-assigned ones): interface identifier, in-use
  status, and hardware boot message.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[AvailableInterface]`.
- **Security:** Literal MAC addresses are omitted by default.
- **Example:** `{"name":"pfsense_get_interface_available_interfaces","arguments":{"limit":20}}`

### `pfsense_get_interface_gres`

- **Purpose:** List GRE tunnel interfaces: interface identifier and
  description.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[InterfaceGRE]`.
- **Security:** Literal tunnel-endpoint addresses (remote address,
  local/remote tunnel addresses and networks, IPv4 and IPv6) are omitted by
  default.
- **Example:** `{"name":"pfsense_get_interface_gres","arguments":{"limit":20}}`

### `pfsense_get_interface_laggs`

- **Purpose:** List LAGG (link aggregation) interfaces: LAGG interface
  identifier, member interfaces, protocol, and description.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[InterfaceLAGG]`.
- **Security:** Interface identifiers only; no address or credential
  material.
- **Example:** `{"name":"pfsense_get_interface_laggs","arguments":{"limit":20}}`

### `pfsense_get_gateways`

- **Purpose:** List configured gateways and monitoring settings.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `list[GatewayConfig]`.
- **Security:** Literal gateway/monitor addresses are omitted by default.
- **Example:** `{"name":"pfsense_get_gateways","arguments":{}}`

### `pfsense_get_gateway_status`

- **Purpose:** Return live gateway monitoring state, loss, delay, and status.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `list[GatewayStatus]`.
- **Security:** Literal monitoring addresses are omitted by default; health
  data can reveal connectivity incidents.
- **Example:** `{"name":"pfsense_get_gateway_status","arguments":{}}`

### `pfsense_get_routing_gateway_groups`

- **Purpose:** List gateway groups: name, failover trigger, description, and
  prioritized member gateways.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[RoutingGatewayGroup]`.
- **Security:** Literal gateway names and virtual IPs in each group's
  priority list are omitted by default.
- **Example:** `{"name":"pfsense_get_routing_gateway_groups","arguments":{"limit":20}}`

### `pfsense_get_routing_gateway_default`

- **Purpose:** Return the current default IPv4/IPv6 gateway assignment.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `DefaultGateway`.
- **Security:** Literal default gateway names are omitted by default.
- **Example:** `{"name":"pfsense_get_routing_gateway_default","arguments":{}}`

### `pfsense_get_arp_table`

- **Purpose:** List ARP neighbors with IP address, MAC address, hostname,
  interface, and entry type.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[ArpTableEntry]`.
- **Security:** This is sensitive live topology and device-identity data. The
  caller must be trusted even though the request is read-only.
- **Example:** `{"name":"pfsense_get_arp_table","arguments":{"limit":25}}`

### `pfsense_get_routing_static_routes`

- **Purpose:** List configured static routes: destination network, gateway,
  and description.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[RoutingStaticRoute]`.
- **Security:** Literal network/gateway addresses are omitted by default.
- **Example:** `{"name":"pfsense_get_routing_static_routes","arguments":{}}`

### `pfsense_get_interface_apply_status`

- **Purpose:** Get pending interface change status: whether all
  interfaces are applied, and which (if any) have pending changes.
- **Parameters:** None.
- **Returns:** `InterfaceApply`.
- **Security:** No identifying metadata beyond interface names.
- **Example:** `{"name":"pfsense_get_interface_apply_status","arguments":{}}`

### `pfsense_get_routing_apply_status`

- **Purpose:** Get pending routing change status: whether all routing
  changes are applied.
- **Parameters:** None.
- **Returns:** `RoutingApply`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_routing_apply_status","arguments":{}}`

## Firewall and NAT

### `pfsense_get_firewall_rules`

- **Purpose:** List configured filter rules, actions, protocols, logging, and
  policy metadata.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `list[FirewallRule]`.
- **Security:** Literal source/destination networks and related identifiers are
  omitted by default.
- **Example:** `{"name":"pfsense_get_firewall_rules","arguments":{}}`

### `pfsense_get_firewall_states`

- **Purpose:** List bounded active connection/state-table entries.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[FirewallState]`.
- **Security:** Literal endpoints are omitted by default. Even redacted state
  timing/protocol data is operationally sensitive.
- **Example:** `{"name":"pfsense_get_firewall_states","arguments":{"limit":10}}`

### `pfsense_get_firewall_states_size`

- **Purpose:** Return current state count and configured state-table capacity.
- **Parameters:** None.
- **Returns:** `FirewallStatesSize`.
- **Security:** Capacity/utilization can reveal load or exhaustion conditions;
  no connection endpoints are returned.
- **Example:** `{"name":"pfsense_get_firewall_states_size","arguments":{}}`

### `pfsense_get_firewall_apply_status`

- **Purpose:** Report whether firewall configuration changes are pending or
  fully applied.
- **Parameters:** None.
- **Returns:** `FirewallApplyStatus`.
- **Security:** This tool does not apply changes; it exposes status only.
- **Example:** `{"name":"pfsense_get_firewall_apply_status","arguments":{}}`

### `pfsense_get_firewall_aliases`

- **Purpose:** List host, network, port, URL, and URL-table aliases.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[FirewallAlias]`.
- **Security:** Alias addresses/content are omitted by default; alias names and
  policy metadata can still disclose network intent.
- **Example:** `{"name":"pfsense_get_firewall_aliases","arguments":{"limit":25}}`

### `pfsense_get_firewall_nat_port_forwards`

- **Purpose:** List NAT port-forward policy, interfaces, protocols, and target
  settings.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[FirewallNatPortForward]`.
- **Security:** Literal sources, destinations, and redirect targets are omitted
  by default.
- **Example:** `{"name":"pfsense_get_firewall_nat_port_forwards","arguments":{"limit":20}}`

### `pfsense_get_firewall_nat_outbound_mode`

- **Purpose:** Return the outbound NAT operating mode.
- **Parameters:** None.
- **Returns:** `FirewallNatOutboundMode`.
- **Security:** Reveals policy mode but no mapping endpoints or credentials.
- **Example:** `{"name":"pfsense_get_firewall_nat_outbound_mode","arguments":{}}`

### `pfsense_get_firewall_nat_outbound_mappings`

- **Purpose:** List outbound NAT mappings: interface, protocol, NAT port
  behavior, and pool options.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[FirewallNatOutboundMapping]`.
- **Security:** Literal sources, destinations, and NAT targets are omitted by
  default. Live-verified 2026-08-20 against production (zero mappings
  configured at verification time; field-level compatibility confirmed via
  an exact live-schema match to the pinned v2.10 reference).
- **Example:** `{"name":"pfsense_get_firewall_nat_outbound_mappings","arguments":{"limit":20}}`

### `pfsense_get_firewall_nat_one_to_one_mappings`

- **Purpose:** List 1:1 NAT mappings: interface, protocol family, NAT
  reflection, and bi-directional NAT state.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[FirewallNatOneToOneMapping]`.
- **Security:** Literal external/source/destination addresses are omitted by
  default. Live-verified 2026-08-20 against production (zero mappings
  configured at verification time; field-level compatibility confirmed via
  an exact live-schema match to the pinned v2.10 reference).
- **Example:** `{"name":"pfsense_get_firewall_nat_one_to_one_mappings","arguments":{"limit":20}}`

### `pfsense_get_firewall_traffic_shaper_limiters`

- **Purpose:** List limiter bandwidth, scheduling, masking, and queue settings.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[FirewallTrafficShaperLimiter]`.
- **Security:** Reveals traffic policy and capacity; does not return packet
  contents or credentials.
- **Example:** `{"name":"pfsense_get_firewall_traffic_shaper_limiters","arguments":{"limit":20}}`

### `pfsense_get_firewall_traffic_shapers`

- **Purpose:** List traffic shapers: interface, scheduler algorithm,
  bandwidth, and child queues.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[TrafficShaper]`.
- **Security:** Reveals traffic policy and capacity; does not return packet
  contents or credentials. Not redacted (interface identifiers and
  bandwidth-shaping data, no addresses).
- **Example:** `{"name":"pfsense_get_firewall_traffic_shapers","arguments":{"limit":20}}`

### `pfsense_get_firewall_schedules`

- **Purpose:** List time-based firewall schedules: name, description,
  active state, and configured time ranges.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[FirewallSchedule]`.
- **Security:** Reveals rule-scheduling policy; no addresses or credentials
  are returned.
- **Example:** `{"name":"pfsense_get_firewall_schedules","arguments":{"limit":20}}`

### `pfsense_get_firewall_advanced_settings`

- **Purpose:** Return advanced firewall alias URL interval and certificate-
  checking settings.
- **Parameters:** None.
- **Returns:** `FirewallAdvancedSettings`.
- **Security:** Reveals hardening posture; no alias URL contents or credentials
  are returned.
- **Example:** `{"name":"pfsense_get_firewall_advanced_settings","arguments":{}}`

### `pfsense_get_firewall_virtual_ips`

- **Purpose:** List virtual IPs (CARP/IP alias/proxy ARP/other): interface,
  type, mode, and CARP status.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[FirewallVirtualIp]`.
- **Security:** Literal virtual IP/CARP peer addresses are omitted by
  default. The CARP shared secret (`password`) is never returned under any
  argument.
- **Example:** `{"name":"pfsense_get_firewall_virtual_ips","arguments":{}}`

### `pfsense_get_firewall_virtual_ip_apply_status`

- **Purpose:** Get pending virtual IP change status: whether all
  virtual IP changes are applied.
- **Parameters:** None.
- **Returns:** `VirtualIPApply`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_firewall_virtual_ip_apply_status","arguments":{}}`

## VPN

### `pfsense_get_status_ipsec_sas`

- **Purpose:** List live IPsec security association (SA/tunnel) status:
  state, algorithms, timers, and nested child SAs.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[IPsecSaStatus]`.
- **Security:** Literal local/remote host and ID addresses (at both the
  tunnel and nested child-SA level) are omitted by default. No key
  material is present in status data.
- **Example:** `{"name":"pfsense_get_status_ipsec_sas","arguments":{}}`

### `pfsense_get_status_ipsec_child_sas`

- **Purpose:** List live IPsec child SA status: state, algorithms,
  byte/packet counters, and rekey timers.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[IPsecChildSaStatus]`.
- **Security:** Literal local/remote traffic-selector subnets are
  omitted by default.
- **Example:** `{"name":"pfsense_get_status_ipsec_child_sas","arguments":{}}`

### `pfsense_get_vpn_ipsec_phase1s`

- **Purpose:** List IPsec Phase 1 (IKE) tunnel configurations: IKE
  type/mode/protocol, interface, authentication method, rekey/reauth/
  lifetime timing, and NAT-traversal/DPD settings.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[IPsecPhase1]`.
- **Security:** Literal remote gateway address and local/remote tunnel
  identity values are omitted by default. The pre-shared key is never
  returned under any argument; the nested encryption-algorithm list is
  excluded (use `pfsense_get_vpn_ipsec_phase1_encryptions`).
- **Example:** `{"name":"pfsense_get_vpn_ipsec_phase1s","arguments":{}}`

### `pfsense_get_vpn_ipsec_phase2s`

- **Purpose:** List IPsec Phase 2 entries: mode, protocol,
  encryption/hash options, and rekey timing.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[IPsecPhase2]`.
- **Security:** Literal local/NAT/remote endpoint addresses and the
  monitoring ping host are omitted by default. The IPsec PSK is never
  present on Phase 2 (it lives only on Phase 1, which is not exposed).
- **Example:** `{"name":"pfsense_get_vpn_ipsec_phase2s","arguments":{}}`

### `pfsense_get_vpn_ipsec_phase1_encryptions`

- **Purpose:** List IPsec Phase 1 encryption algorithm/hash/DH-group
  capability options.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[IPsecPhase1Encryption]`.
- **Security:** Pure algorithm/cipher capability reference data; not
  redacted.
- **Example:** `{"name":"pfsense_get_vpn_ipsec_phase1_encryptions","arguments":{}}`

### `pfsense_get_vpn_ipsec_phase2_encryptions`

- **Purpose:** List IPsec Phase 2 encryption algorithm capability
  options.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[IPsecPhase2Encryption]`.
- **Security:** Pure algorithm capability reference data; not
  redacted.
- **Example:** `{"name":"pfsense_get_vpn_ipsec_phase2_encryptions","arguments":{}}`

### `pfsense_get_status_wireguard_tunnels`

- **Purpose:** List live WireGuard tunnel status: link state, traffic
  counters, and nested peer status.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[WireGuardTunnelStatus]`.
- **Security:** Literal peer endpoint/allowed-IP addresses nested under
  each tunnel are omitted by default. Private/preshared key material is
  never returned under any argument.
- **Example:** `{"name":"pfsense_get_status_wireguard_tunnels","arguments":{}}`

### `pfsense_get_status_wireguard_peers`

- **Purpose:** List live WireGuard peer status: handshake time, traffic
  counters, and public key.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[WireGuardPeerStatus]`.
- **Security:** Literal peer endpoint address and allowed-IP ranges are
  omitted by default. The preshared key is never returned under any
  argument.
- **Example:** `{"name":"pfsense_get_status_wireguard_peers","arguments":{}}`

### `pfsense_get_vpn_wireguard_tunnels`

- **Purpose:** List WireGuard tunnel configurations: name, enabled
  state, description, listen port, public key, and MTU. Requires
  pfSense-pkg-WireGuard.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[WireGuardTunnel]`.
- **Security:** The private key is never returned under any argument;
  the embedded addresses list is excluded (use
  `pfsense_get_vpn_wireguard_tunnel_addresses`).
- **Example:** `{"name":"pfsense_get_vpn_wireguard_tunnels","arguments":{}}`

### `pfsense_get_vpn_wireguard_peers`

- **Purpose:** List WireGuard peer configurations: enabled state,
  parent tunnel, listen port, description, persistent-keepalive
  interval, and public key. Requires pfSense-pkg-WireGuard.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[WireGuardPeer]`.
- **Security:** Literal endpoint address is omitted by default. The
  pre-shared key is never returned under any argument; the allowed-IPs
  list is excluded (already exposed, redacted, via
  `pfsense_get_status_wireguard_peers`).
- **Example:** `{"name":"pfsense_get_vpn_wireguard_peers","arguments":{}}`

### `pfsense_get_status_openvpn_servers`

- **Purpose:** List live OpenVPN server status: mode, port, and nested
  connection/route status.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[OpenVpnServerStatus]`.
- **Security:** Literal client identity/address fields nested under each
  server's connections and routes are omitted by default.
- **Example:** `{"name":"pfsense_get_status_openvpn_servers","arguments":{}}`

### `pfsense_get_status_openvpn_clients`

- **Purpose:** List live OpenVPN client status: connection state and
  virtual/remote address details.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[OpenVpnClientStatus]`.
- **Security:** Literal local/remote/virtual addresses are omitted by
  default.
- **Example:** `{"name":"pfsense_get_status_openvpn_clients","arguments":{}}`

### `pfsense_get_status_openvpn_server_connections`

- **Purpose:** List live, flat, all-servers OpenVPN client connection
  status: cipher, byte counters, and connect time.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[OpenVpnServerConnectionStatus]`.
- **Security:** Literal client common name, username, and remote/virtual
  addresses are omitted by default.
- **Example:** `{"name":"pfsense_get_status_openvpn_server_connections","arguments":{}}`

### `pfsense_get_status_openvpn_server_routes`

- **Purpose:** List live, flat, all-servers OpenVPN client route status.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[OpenVpnServerRouteStatus]`.
- **Security:** Literal client common name and remote/virtual addresses
  are omitted by default.
- **Example:** `{"name":"pfsense_get_status_openvpn_server_routes","arguments":{}}`

### `pfsense_get_vpn_openvpn_servers`

- **Purpose:** List OpenVPN server configurations: mode, protocol,
  TLS/cert references, ciphers, and topology.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[OpenVpnServer]`.
- **Security:** Literal tunnel/local/remote network ranges, DNS/NTP/WINS
  servers, and server-bridge DHCP range are omitted by default.
  `caref`/`certref` are CA/certificate references, never certificate or
  key material.
- **Example:** `{"name":"pfsense_get_vpn_openvpn_servers","arguments":{}}`

### `pfsense_get_vpn_openvpn_clients`

- **Purpose:** List OpenVPN client configurations: mode, protocol,
  device mode, ports, ciphers/digest, certificate references, and
  keepalive/ping settings.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[OpenVPNClient]`.
- **Security:** Literal server/proxy addresses, tunnel network(s), and
  remote network(s) are omitted by default. The auth password, proxy
  password, and TLS-auth/crypt key material are never returned under
  any argument; free-text custom options are excluded entirely
  (raw-config-injection risk).
- **Example:** `{"name":"pfsense_get_vpn_openvpn_clients","arguments":{}}`

### `pfsense_get_vpn_openvpn_csos`

- **Purpose:** List OpenVPN client-specific overrides: per-client
  tunnel settings, allowed servers, and DNS/NTP/WINS pushes.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[OpenVpnClientSpecificOverride]`.
- **Security:** Literal client common name and tunnel/local/remote
  network ranges plus DNS/NTP/WINS servers are omitted by default.
- **Example:** `{"name":"pfsense_get_vpn_openvpn_csos","arguments":{}}`

### `pfsense_get_ipsec_apply_status`

- **Purpose:** Get pending IPsec change status: whether all IPsec
  changes are applied.
- **Parameters:** None.
- **Returns:** `IPsecApply`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_ipsec_apply_status","arguments":{}}`

### `pfsense_get_wireguard_apply_status`

- **Purpose:** Get pending WireGuard change status: whether all
  WireGuard changes are applied. Requires pfSense-pkg-WireGuard.
- **Parameters:** None.
- **Returns:** `WireGuardApply`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_wireguard_apply_status","arguments":{}}`

### `pfsense_get_vpn_wireguard_tunnel_addresses`

- **Purpose:** List WireGuard tunnel address assignments: description
  and (optionally) the tunnel's own address/subnet mask. Requires
  pfSense-pkg-WireGuard.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[WireGuardTunnelAddress]`.
- **Security:** Literal address/mask are omitted by default.
- **Example:** `{"name":"pfsense_get_vpn_wireguard_tunnel_addresses","arguments":{}}`

### `pfsense_get_vpn_wireguard_settings`

- **Purpose:** Get global pfSense WireGuard service settings: enabled
  state, config-retention-on-uninstall, endpoint hostname
  re-resolution interval, and interface-group membership mode.
  Requires pfSense-pkg-WireGuard.
- **Parameters:** None.
- **Returns:** `WireGuardSettings`.
- **Security:** No identifying metadata. No tunnel/peer configuration
  or key material.
- **Example:** `{"name":"pfsense_get_vpn_wireguard_settings","arguments":{}}`

## Users and API identities

### `pfsense_get_users`

- **Purpose:** List local accounts, status, privileges, scope, and certificate
  associations.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[PfSenseUser]`.
- **Security:** Authorized public SSH keys are optional sensitive metadata and
  omitted by default. IPsec PSKs are excluded unconditionally.
- **Example:** `{"name":"pfsense_get_users","arguments":{"limit":20}}`

### `pfsense_get_user_groups`

- **Purpose:** List local groups, descriptions, GIDs, scope, and privileges.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[PfSenseUserGroup]`.
- **Security:** Group/privilege inventory is authorization-sensitive but
  contains no password material.
- **Example:** `{"name":"pfsense_get_user_groups","arguments":{"limit":20}}`

### `pfsense_get_user_auth_servers`

- **Purpose:** List authentication server (LDAP/RADIUS) configurations:
  type, connectivity settings, and directory/protocol options.
- **Parameters:** `include_identifying_metadata: boolean = false`;
  `limit: integer = 100`.
- **Returns:** `list[PfSenseAuthServer]`.
- **Security:** Literal server host address and LDAP bind DN/base DN/auth
  container/PAM group DN are omitted by default. The LDAP bind password
  and RADIUS shared secret are never returned under any argument.
- **Example:** `{"name":"pfsense_get_user_auth_servers","arguments":{}}`

### `pfsense_get_auth_keys`

- **Purpose:** List REST API key records with description, owner, algorithm,
  identifier, and key length.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[AuthKey]`.
- **Security:** Plaintext keys and stored credential hashes are never returned.
  Account attribution remains sensitive operational metadata.
- **Example:** `{"name":"pfsense_get_auth_keys","arguments":{"limit":10}}`

## DHCP and DNS

### `pfsense_get_dhcp_leases`

- **Purpose:** List active DHCP leases with addresses, hostname, state, and
  timing data.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DhcpLease]`.
- **Security:** Lease IP/MAC/hostname data identifies internal devices and is
  returned to trusted auditor callers; no DHCP credential is involved.
- **Example:** `{"name":"pfsense_get_dhcp_leases","arguments":{"limit":25}}`

### `pfsense_get_dhcp_static_mappings`

- **Purpose:** List static DHCP mappings and host/address assignments.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DhcpStaticMapping]`.
- **Security:** Mapping data exposes internal device identities and topology.
- **Example:** `{"name":"pfsense_get_dhcp_static_mappings","arguments":{"limit":25}}`

### `pfsense_get_dhcp_servers`

- **Purpose:** List DHCP server scopes, ranges, options, and service settings
  by interface.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DhcpServer]`.
- **Security:** Reveals internal address planning and service configuration;
  credential fields are not modeled.
- **Example:** `{"name":"pfsense_get_dhcp_servers","arguments":{"limit":20}}`

### `pfsense_get_dhcp_server_address_pools`

- **Purpose:** List DHCP server address pools (additional scopes) across all
  configured DHCP servers: range, gateway, DNS/NTP/WINS servers, and MAC
  allow/deny lists.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DHCPServerAddressPool]`.
- **Security:** Reveals internal address planning and device identities;
  credential fields are not modeled. Not redacted, matching
  `pfsense_get_dhcp_servers`' own established convention for this
  capability class.
- **Example:** `{"name":"pfsense_get_dhcp_server_address_pools","arguments":{"limit":20}}`

### `pfsense_get_dhcp_server_custom_options`

- **Purpose:** List DHCP server custom options across all configured DHCP
  servers: option number, type, and value.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DHCPServerCustomOption]`.
- **Security:** Admin-authored configuration data only; no credential
  material.
- **Example:** `{"name":"pfsense_get_dhcp_server_custom_options","arguments":{"limit":20}}`

### `pfsense_get_dhcp_relay`

- **Purpose:** Return the current DHCP Relay configuration: enabled state,
  downstream interfaces, and CARP failover selector.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `DHCPRelay`.
- **Security:** Literal relay target server addresses are omitted by
  default.
- **Example:** `{"name":"pfsense_get_dhcp_relay","arguments":{}}`

### `pfsense_get_dns_resolver_host_overrides`

- **Purpose:** List Unbound host overrides, addresses, aliases, and
  descriptions.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DnsResolverHostOverride]`.
- **Security:** Hostnames and addresses disclose internal DNS/topology data.
- **Example:** `{"name":"pfsense_get_dns_resolver_host_overrides","arguments":{"limit":20}}`

### `pfsense_get_dns_resolver_domain_overrides`

- **Purpose:** List Unbound (DNS Resolver) domain overrides: forwarding
  target address and DNS-over-TLS settings.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DnsResolverDomainOverride]`.
- **Security:** Hostnames and addresses disclose internal DNS/topology data.
- **Example:** `{"name":"pfsense_get_dns_resolver_domain_overrides","arguments":{"limit":20}}`

### `pfsense_get_dns_resolver_access_lists`

- **Purpose:** List Unbound (DNS Resolver) access lists: allow/deny action
  and the network ranges each list applies to.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DnsResolverAccessList]`.
- **Security:** Network ranges disclose internal topology data; no
  credential is involved.
- **Example:** `{"name":"pfsense_get_dns_resolver_access_lists","arguments":{"limit":20}}`

### `pfsense_get_dns_forwarder_host_overrides`

- **Purpose:** List dnsmasq (DNS Forwarder) host overrides, addresses,
  aliases, and descriptions.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DnsForwarderHostOverride]`.
- **Security:** Hostnames and addresses disclose internal DNS/topology data.
- **Example:** `{"name":"pfsense_get_dns_forwarder_host_overrides","arguments":{"limit":20}}`

### `pfsense_get_dns_resolver_settings`

- **Purpose:** Return Unbound service, DNSSEC, forwarding, registration, and
  listening settings.
- **Parameters:** None.
- **Returns:** `DnsResolverSettings`.
- **Security:** Reveals DNS security and resolution posture but no secret.
- **Example:** `{"name":"pfsense_get_dns_resolver_settings","arguments":{}}`

### `pfsense_get_bind_settings`

- **Purpose:** Return BIND package enablement, listening, logging, and rate-
  limiting settings.
- **Parameters:** None.
- **Returns:** `BindSettings`.
- **Security:** Listen addresses and service posture are sensitive network
  metadata; no zone-transfer credential is returned. `bind_custom_options`
  and `bind_global_settings` are deliberately excluded (unbounded, operator-
  supplied text spliced verbatim into the generated BIND configuration —
  a potential exfiltration channel for pasted secrets).
- **Example:** `{"name":"pfsense_get_bind_settings","arguments":{}}`

### `pfsense_get_bind_access_lists`

- **Purpose:** List pfSense BIND access lists: name, description, and
  network entries. Requires pfSense-pkg-bind.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[BindAccessList]`.
- **Security:** No secrets; network entries are configuration metadata.
- **Example:** `{"name":"pfsense_get_bind_access_lists","arguments":{}}`

### `pfsense_get_bind_sync_settings`

- **Purpose:** Get pfSense BIND HA sync settings: sync mode, timeout, and
  master server IP. Requires pfSense-pkg-bind. Does not include the
  separate sync remote-host credentials.
- **Parameters:** None.
- **Returns:** `BindSyncSettings`.
- **Security:** No secrets; remote-host credentials live on a separate,
  rejected resource never exposed by this tool.
- **Example:** `{"name":"pfsense_get_bind_sync_settings","arguments":{}}`

### `pfsense_get_bind_views`

- **Purpose:** List pfSense BIND views: name, description, recursion
  setting, and matched/allowed access lists. Requires pfSense-pkg-bind.
  Custom BIND config-file options for each view are not included.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[BindView]`.
- **Security:** `bind_custom_options` is deliberately excluded (raw
  config-injection-risk free text).
- **Example:** `{"name":"pfsense_get_bind_views","arguments":{}}`

### `pfsense_get_bind_zones`

- **Purpose:** List pfSense BIND zones: name, type, SOA settings, and
  access-list associations. Requires pfSense-pkg-bind. Does not include
  each zone's own DNS records (use `pfsense_get_bind_zone_record` for
  individual records) or its custom BIND config-file/zone-file text
  fragments.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[BindZone]`.
- **Security:** `custom`, `customzonerecords`, and `records` are
  deliberately excluded (raw config-injection-risk / unbounded response).
- **Example:** `{"name":"pfsense_get_bind_zones","arguments":{}}`

### `pfsense_get_bind_zone_record`

- **Purpose:** Get a single pfSense BIND zone record: name, type, data,
  and (for MX/SRV records) priority. Requires pfSense-pkg-bind.
- **Parameters:** `parent_id: integer` (the zone's id), `id: integer`
  (the record's id within that zone).
- **Returns:** `BindZoneRecord`.
- **Security:** No secrets.
- **Example:** `{"name":"pfsense_get_bind_zone_record","arguments":{"parent_id":0,"id":0}}`

### `pfsense_get_haproxy_apply_status`

- **Purpose:** Get pfSense HAProxy pending-changes status: whether the
  running configuration matches the last-applied configuration. Requires
  pfSense-pkg-haproxy.
- **Parameters:** None.
- **Returns:** `HAProxyApplyStatus`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_haproxy_apply_status","arguments":{}}`

### `pfsense_get_haproxy_backends`

- **Purpose:** List pfSense HAProxy backends: name, load-balancing
  algorithm, health-check and persistence settings. Requires
  pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyBackend]`.
- **Security:** `stats_password` and `haproxy_cookie_dynamic_cookie_key`
  are deliberately excluded (plaintext-credential fields upstream —
  `stats_password` is marked `sensitive` but not `write_only`, meaning
  it would otherwise be returned in cleartext). `advanced` and
  `advanced_backend` are deliberately excluded (raw config-injection-risk
  free text). Nested `servers`/`acls`/`actions`/`errorfiles` are
  deliberately excluded (use the dedicated tools below instead).
- **Example:** `{"name":"pfsense_get_haproxy_backends","arguments":{}}`

### `pfsense_get_haproxy_backend_acls`

- **Purpose:** List pfSense HAProxy backend ACLs (match conditions) across
  all backends: name, expression type, comparison value. Requires
  pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyBackendAcl]`.
- **Security:** No secrets. When `expression` is `custom`, `value` is
  arbitrary HAProxy ACL-condition syntax rather than a bounded comparison
  string — a narrower, documented residual risk, not a raw-config splice.
- **Example:** `{"name":"pfsense_get_haproxy_backend_acls","arguments":{}}`

### `pfsense_get_haproxy_backend_errorfiles`

- **Purpose:** List pfSense HAProxy backend custom error-file associations
  across all backends: HTTP status code and associated file name.
  Requires pfSense-pkg-haproxy. Does not include the error file's own
  content (use `pfsense_get_haproxy_files`).
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyBackendErrorFile]`.
- **Security:** No secrets; metadata-only mapping.
- **Example:** `{"name":"pfsense_get_haproxy_backend_errorfiles","arguments":{}}`

### `pfsense_get_haproxy_backend_servers`

- **Purpose:** List pfSense HAProxy backend servers across all backends:
  name, status, address, port, weight, and SSL settings. Requires
  pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyBackendServer]`.
- **Security:** `advanced` is deliberately excluded (raw config-injection-
  risk free text).
- **Example:** `{"name":"pfsense_get_haproxy_backend_servers","arguments":{}}`

### `pfsense_get_haproxy_files`

- **Purpose:** List pfSense HAProxy managed files (Lua scripts, custom
  error files, other uploaded files): name and type only. Requires
  pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyFile]`.
- **Security:** `content` is deliberately excluded (arbitrary, unbounded
  file/Lua-script content).
- **Example:** `{"name":"pfsense_get_haproxy_files","arguments":{}}`

### `pfsense_get_haproxy_frontends`

- **Purpose:** List pfSense HAProxy frontends: name, description, status,
  type, backend pool association, and logging settings. Requires
  pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyFrontend]`.
- **Security:** `advanced_bind` and `advanced` are deliberately excluded
  (raw config-injection-risk free text). Nested
  `a_extaddr`/`ha_acls`/`a_actionitems`/`a_errorfiles`/`ha_certificates`
  are deliberately excluded (use the dedicated tools below instead).
- **Example:** `{"name":"pfsense_get_haproxy_frontends","arguments":{}}`

### `pfsense_get_haproxy_frontend_acls`

- **Purpose:** List pfSense HAProxy frontend ACLs (match conditions)
  across all frontends: name, expression type, comparison value.
  Requires pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyFrontendAcl]`.
- **Security:** No secrets. Same `custom`-expression residual risk as
  `pfsense_get_haproxy_backend_acls`.
- **Example:** `{"name":"pfsense_get_haproxy_frontend_acls","arguments":{}}`

### `pfsense_get_haproxy_frontend_addresses`

- **Purpose:** List pfSense HAProxy frontend listen addresses across all
  frontends: interface/address selection, port, and whether SSL
  offloading is enabled. Requires pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyFrontendAddress]`.
- **Security:** `exaddr_advanced` is deliberately excluded (raw
  config-injection-risk free text).
- **Example:** `{"name":"pfsense_get_haproxy_frontend_addresses","arguments":{}}`

### `pfsense_get_haproxy_frontend_certificates`

- **Purpose:** List pfSense HAProxy frontend SNI certificate associations
  across all frontends: a reference ID into the pfSense certificate store
  per association. Requires pfSense-pkg-haproxy. Does not include
  certificate content or private key material (use
  `pfsense_get_system_certificates` for that store).
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyFrontendCertificate]`.
- **Security:** No secrets; a plain reference ID only.
- **Example:** `{"name":"pfsense_get_haproxy_frontend_certificates","arguments":{}}`

### `pfsense_get_haproxy_frontend_error_files`

- **Purpose:** List pfSense HAProxy frontend custom error-file
  associations across all frontends: HTTP status code and associated
  file name. Requires pfSense-pkg-haproxy. Does not include the error
  file's own content (use `pfsense_get_haproxy_files`).
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyFrontendErrorFile]`.
- **Security:** No secrets; metadata-only mapping.
- **Example:** `{"name":"pfsense_get_haproxy_frontend_error_files","arguments":{}}`

### `pfsense_get_haproxy_settings`

- **Purpose:** Get pfSense HAProxy global settings: enabled state,
  connection/thread limits, stats and DNS-resolver timing, and
  logging/SSL-compatibility settings. Requires pfSense-pkg-haproxy.
- **Parameters:** None.
- **Returns:** `HAProxySettings`.
- **Security:** `advanced` is deliberately excluded (raw config-injection-
  risk free text). Nested `dns_resolvers`/`email_mailers` are deliberately
  excluded (use the dedicated tools below instead).
- **Example:** `{"name":"pfsense_get_haproxy_settings","arguments":{}}`

### `pfsense_get_haproxy_dns_resolvers`

- **Purpose:** List pfSense HAProxy DNS resolvers: name, server address,
  and port. Requires pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyDnsResolver]`.
- **Security:** No credential fields exist on this resource.
- **Example:** `{"name":"pfsense_get_haproxy_dns_resolvers","arguments":{}}`

### `pfsense_get_haproxy_email_mailers`

- **Purpose:** List pfSense HAProxy email mailers (SMTP relay targets for
  alerts): name, mail-server address, and port. Requires
  pfSense-pkg-haproxy.
- **Parameters:** `limit: integer = 100` (1-100).
- **Returns:** `list[HAProxyEmailMailer]`.
- **Security:** No SMTP authentication credential fields exist on this
  resource.
- **Example:** `{"name":"pfsense_get_haproxy_email_mailers","arguments":{}}`

### `pfsense_get_dhcp_server_apply_status`

- **Purpose:** Get pending DHCP server change status: whether all
  DHCP server changes are applied.
- **Parameters:** None.
- **Returns:** `DHCPServerApply`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_dhcp_server_apply_status","arguments":{}}`

### `pfsense_get_dns_forwarder_apply_status`

- **Purpose:** Get pending DNS Forwarder change status: whether all
  DNS Forwarder changes are applied.
- **Parameters:** None.
- **Returns:** `DNSForwarderApply`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_dns_forwarder_apply_status","arguments":{}}`

### `pfsense_get_dns_resolver_apply_status`

- **Purpose:** Get pending DNS Resolver change status: whether all
  DNS Resolver changes are applied.
- **Parameters:** None.
- **Returns:** `DNSResolverApply`.
- **Security:** No identifying metadata.
- **Example:** `{"name":"pfsense_get_dns_resolver_apply_status","arguments":{}}`

## Services and scheduled operations

### `pfsense_get_service_status`

- **Purpose:** List service name, description, enablement, and running state.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[ServiceStatus]`.
- **Security:** Service inventory reveals attack surface and outage state.
- **Example:** `{"name":"pfsense_get_service_status","arguments":{"limit":30}}`

### `pfsense_get_services_service_watchdogs`

- **Purpose:** List Service Watchdog entries: which services are
  monitored, whether notifications are sent, and whether each entry is
  enabled. Requires pfSense-pkg-Service_Watchdog.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[ServiceWatchdog]`.
- **Security:** No secret material or address data; all 4 fields are
  plain scalar toggles/labels.
- **Example:** `{"name":"pfsense_get_services_service_watchdogs","arguments":{}}`

### `pfsense_get_email_notification_settings`

- **Purpose:** Return SMTP notification enablement, transport security,
  authentication mechanism, port, and timeout.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `EmailNotificationSettings`.
- **Security:** SMTP username, addresses, and server IP are omitted by default.
  SMTP passwords are excluded unconditionally.
- **Example:** `{"name":"pfsense_get_email_notification_settings","arguments":{}}`

### `pfsense_get_ntp_settings`

- **Purpose:** Return NTP enablement, listening interfaces, access, logging,
  and clock settings.
- **Parameters:** None.
- **Returns:** `NtpSettings`.
- **Security:** Reveals time-service topology and hardening configuration.
- **Example:** `{"name":"pfsense_get_ntp_settings","arguments":{}}`

### `pfsense_get_ntp_time_servers`

- **Purpose:** List configured NTP server hostnames, types, and selection
  preferences.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[NtpTimeServer]`.
- **Security:** Server hostnames can reveal internal infrastructure.
- **Example:** `{"name":"pfsense_get_ntp_time_servers","arguments":{"limit":10}}`

### `pfsense_get_ssh_settings`

- **Purpose:** Return SSH server enablement, listening port/interface,
  authentication policy, and related settings.
- **Parameters:** None.
- **Returns:** `SshSettings`.
- **Security:** Reveals remote-administration posture. Host/private keys and
  passwords are never returned.
- **Example:** `{"name":"pfsense_get_ssh_settings","arguments":{}}`

### `pfsense_get_cron_jobs`

- **Purpose:** List scheduled commands, schedules, and execution users.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[CronJob]`.
- **Security:** Commands and usernames can contain sensitive operational
  context; the model does not expose credential material.
- **Example:** `{"name":"pfsense_get_cron_jobs","arguments":{"limit":20}}`

### `pfsense_get_acme_settings`

- **Purpose:** Return ACME package enablement and package-level settings.
- **Parameters:** None.
- **Returns:** `AcmeSettings`.
- **Security:** Account private keys and challenge credentials are not returned;
  package posture can still be operationally sensitive.
- **Example:** `{"name":"pfsense_get_acme_settings","arguments":{}}`

### `pfsense_get_freeradius_eap`

- **Purpose:** Return FreeRADIUS EAP methods, certificate selections, TLS
  policy, and session settings.
- **Parameters:** None.
- **Returns:** `FreeRadiusEap`.
- **Security:** Reveals authentication policy and certificate references.
  Private keys, passphrases, and user credentials are not returned.
- **Example:** `{"name":"pfsense_get_freeradius_eap","arguments":{}}`

## Diagnostics

### `pfsense_get_diagnostics_tables`

- **Purpose:** List pf firewall tables and member IP/CIDR values.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DiagnosticsTable]`.
- **Security:** Table members disclose live policy/topology data and may include
  blocklists or internal networks.
- **Example:** `{"name":"pfsense_get_diagnostics_tables","arguments":{"limit":20}}`

### `pfsense_get_diagnostics_config_history_revisions`

- **Purpose:** List configuration-history (backup) revisions: when each
  change was made, pfSense's own system-generated audit description, the
  pfSense version at the time, and the backup file size.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[ConfigHistoryRevision]`.
- **Security:** Metadata only. Upstream Model source
  (`ConfigHistoryRevision.inc`) confirmed to never read or return the
  backup file's actual configuration content -- only filesystem-level
  metadata (`get_backups()`). No secret or credential material is
  present in this response shape.
- **Example:** `{"name":"pfsense_get_diagnostics_config_history_revisions","arguments":{"limit":20}}`

### `pfsense_get_status_logs_settings`

- **Purpose:** Get pfSense logging configuration: which categories are
  logged, log rotation/retention settings, and remote syslog
  destination.
- **Parameters:** None.
- **Returns:** `LogSettings`.
- **Security:** Contains no log content or credentials.
- **Example:** `{"name":"pfsense_get_status_logs_settings","arguments":{}}`

## Server introspection

### `pfsense_mcp_info`

- **Purpose:** Report this MCP server's own version, active capability
  profile, registered tool counts, WRITE-inactivity facts, and Tier 1/ADR-017
  presence — so a client can determine actual capability and safety state
  without inference.
- **Parameters:** None.
- **Returns:** `ServerIntrospection`.
- **Security:** Local process facts only — makes no pfSense API call. Every
  field is already independently, redundantly enforced elsewhere (capability
  gating, the empty `WriteEndpoints` allow-list, CI-enforced Tier 1/ADR-017
  isolation tests); this tool only reports already-enforced state and cannot
  itself grant or change any capability. Presence of the `pfsense_mcp.tier1`
  or `pfsense_mcp.guidance` packages is a packaging fact, not a capability —
  neither field means either package is reachable or active.
- **Example:** `{"name":"pfsense_mcp_info","arguments":{}}`

## Security reminders

- `include_identifying_metadata=true` is an explicit disclosure choice for the
  tool invocation and is represented in audit metadata without logging values.
- Passwords, pre-shared keys, private keys, plaintext API keys, and stored
  credential hashes are never public model fields.
- Public cryptographic material can still identify infrastructure.
- The local process controlling stdio is the MCP caller-authentication
  boundary. Do not expose the stdio channel to untrusted users.
- The upstream pfSense API credential should remain least-privilege and
  configured `read_only=true`.
