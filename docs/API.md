# MCP tool reference

Version: 0.3.0 release state
Profile: `auditor`  
Registered tools: 41 READ, 0 WRITE

The normalized public contract is checked into
`tests/contracts/mcp_public_contract_v0.3.0.json`. It records tool names,
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

Every tool advertises MCP `readOnlyHint=true` and `openWorldHint=true`.
`destructiveHint` and `idempotentHint` are omitted because those hints are
defined for tools that modify their environment. Annotations are untrusted
client metadata only. They do not authorize a call or weaken capability,
endpoint, GET-only, credential, audit, or WRITE-inactivity controls.

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

### `pfsense_get_system_tunables`

- **Purpose:** List FreeBSD system tunables with descriptions and current
  values.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[SystemTunable]`.
- **Security:** Tunables can reveal hardening and network-stack configuration;
  no credential value is returned.
- **Example:** `{"name":"pfsense_get_system_tunables","arguments":{"limit":25}}`

### `pfsense_get_system_certificates`

- **Purpose:** List certificate inventory, issuer/CA references, validity,
  subject metadata, and public certificate material supplied by the endpoint.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[SystemCertificate]`.
- **Security:** Public certificates are not secrets but can identify hosts,
  organizations, and internal PKI. Private keys and passphrases are never
  returned.
- **Example:** `{"name":"pfsense_get_system_certificates","arguments":{"limit":10}}`

### `pfsense_get_system_restapi_settings`

- **Purpose:** Return pfSense REST API service state, transport/security
  options, and read-only configuration.
- **Parameters:** `include_identifying_metadata: boolean = false`.
- **Returns:** `SystemRestApiSettings`.
- **Security:** HA synchronization host metadata is optional and omitted by
  default. HA passwords are excluded unconditionally.
- **Example:** `{"name":"pfsense_get_system_restapi_settings","arguments":{}}`

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

### `pfsense_get_arp_table`

- **Purpose:** List ARP neighbors with IP address, MAC address, hostname,
  interface, and entry type.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[ArpTableEntry]`.
- **Security:** This is sensitive live topology and device-identity data. The
  caller must be trusted even though the request is read-only.
- **Example:** `{"name":"pfsense_get_arp_table","arguments":{"limit":25}}`

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

### `pfsense_get_firewall_traffic_shaper_limiters`

- **Purpose:** List limiter bandwidth, scheduling, masking, and queue settings.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[FirewallTrafficShaperLimiter]`.
- **Security:** Reveals traffic policy and capacity; does not return packet
  contents or credentials.
- **Example:** `{"name":"pfsense_get_firewall_traffic_shaper_limiters","arguments":{"limit":20}}`

### `pfsense_get_firewall_advanced_settings`

- **Purpose:** Return advanced firewall alias URL interval and certificate-
  checking settings.
- **Parameters:** None.
- **Returns:** `FirewallAdvancedSettings`.
- **Security:** Reveals hardening posture; no alias URL contents or credentials
  are returned.
- **Example:** `{"name":"pfsense_get_firewall_advanced_settings","arguments":{}}`

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

### `pfsense_get_dns_resolver_host_overrides`

- **Purpose:** List Unbound host overrides, addresses, aliases, and
  descriptions.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[DnsResolverHostOverride]`.
- **Security:** Hostnames and addresses disclose internal DNS/topology data.
- **Example:** `{"name":"pfsense_get_dns_resolver_host_overrides","arguments":{"limit":20}}`

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
  metadata; no zone-transfer credential is returned.
- **Example:** `{"name":"pfsense_get_bind_settings","arguments":{}}`

## Services and scheduled operations

### `pfsense_get_service_status`

- **Purpose:** List service name, description, enablement, and running state.
- **Parameters:** `limit: integer = 100`.
- **Returns:** `list[ServiceStatus]`.
- **Security:** Service inventory reveals attack surface and outage state.
- **Example:** `{"name":"pfsense_get_service_status","arguments":{"limit":30}}`

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
