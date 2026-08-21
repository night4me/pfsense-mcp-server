"""Single source of truth for every pfSense REST API endpoint this
project uses. No other module embeds a literal '/api/...' path
string — RestApiClient is the only place a full path is constructed.

Each entry's `verified` flag must be True only once the endpoint has
been independently tested via an authenticated GET against this
instance. tests/test_endpoints_verified.py enforces this mechanically.
"""

from __future__ import annotations

from dataclasses import dataclass

from .api_version import ApiVersion


@dataclass(frozen=True)
class EndpointInfo:
    path_suffix: str  # e.g. "/status/system" — no "/api/vN" prefix
    verified: bool
    min_api_version: ApiVersion


class Endpoints:
    SYSTEM_STATUS = EndpointInfo(
        path_suffix="/status/system",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_INTERFACES = EndpointInfo(
        path_suffix="/status/interfaces",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    ROUTING_GATEWAYS = EndpointInfo(
        path_suffix="/routing/gateways",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_GATEWAYS = EndpointInfo(
        path_suffix="/status/gateways",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_RULES = EndpointInfo(
        path_suffix="/firewall/rules",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_STATES = EndpointInfo(
        path_suffix="/firewall/states",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_STATES_SIZE = EndpointInfo(
        path_suffix="/firewall/states/size",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_APPLY_STATUS = EndpointInfo(
        path_suffix="/firewall/apply",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_ALIASES = EndpointInfo(
        path_suffix="/firewall/aliases",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_SERVICES = EndpointInfo(
        path_suffix="/status/services",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_VERSION = EndpointInfo(
        path_suffix="/system/version",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    INTERFACES = EndpointInfo(
        path_suffix="/interfaces",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_NAT_PORT_FORWARDS = EndpointInfo(
        path_suffix="/firewall/nat/port_forwards",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_NAT_OUTBOUND_MODE = EndpointInfo(
        path_suffix="/firewall/nat/outbound/mode",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20, owner-authorized live production READ
    # verification): the typed GET succeeded against the production
    # appliance (pfSense Plus 26.07-RELEASE) and returned the expected
    # {"data": [...]} envelope. The live account currently has zero
    # configured mappings, so per-field value parsing was not exercised
    # against real instance data -- compatibility for field types/
    # nullability is instead confirmed by an exact, byte-for-byte match
    # between the live OpenAPI schema's `OutboundNATMapping` component
    # (and this endpoint's full "Allowed privileges" description text)
    # and the pinned v2.10 reference this project's model was already
    # derived from. See docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md.
    FIREWALL_NAT_OUTBOUND_MAPPINGS = EndpointInfo(
        path_suffix="/firewall/nat/outbound/mappings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- see FIREWALL_NAT_OUTBOUND_MAPPINGS's
    # comment immediately above; identical verification method and the
    # same live result (zero configured mappings, schema match exact).
    FIREWALL_NAT_ONE_TO_ONE_MAPPINGS = EndpointInfo(
        path_suffix="/firewall/nat/one_to_one/mappings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    USERS = EndpointInfo(
        path_suffix="/users",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_CERTIFICATES = EndpointInfo(
        path_suffix="/system/certificates",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    USER_GROUPS = EndpointInfo(
        path_suffix="/user/groups",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DIAGNOSTICS_CONFIG_HISTORY_REVISIONS = EndpointInfo(
        path_suffix="/diagnostics/config_history/revisions",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_DHCP_LEASES = EndpointInfo(
        path_suffix="/status/dhcp_server/leases",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DHCP_SERVER_STATIC_MAPPINGS = EndpointInfo(
        path_suffix="/services/dhcp_server/static_mappings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DHCP_SERVERS = EndpointInfo(
        path_suffix="/services/dhcp_servers",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    INTERFACE_BRIDGES = EndpointInfo(
        path_suffix="/interface/bridges",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_CARP = EndpointInfo(
        path_suffix="/status/carp",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_RESTAPI_SETTINGS = EndpointInfo(
        path_suffix="/system/restapi/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_HASYNC = EndpointInfo(
        path_suffix="/system/hasync",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DNS_RESOLVER_HOST_OVERRIDES = EndpointInfo(
        path_suffix="/services/dns_resolver/host_overrides",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DNS_RESOLVER_SETTINGS = EndpointInfo(
        path_suffix="/services/dns_resolver/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DIAGNOSTICS_ARP_TABLE = EndpointInfo(
        path_suffix="/diagnostics/arp_table",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_TRAFFIC_SHAPER_LIMITERS = EndpointInfo(
        path_suffix="/firewall/traffic_shaper/limiters",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_ADVANCED_SETTINGS = EndpointInfo(
        path_suffix="/firewall/advanced_settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_PACKAGES = EndpointInfo(
        path_suffix="/system/packages",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_TUNABLES = EndpointInfo(
        path_suffix="/system/tunables",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS = EndpointInfo(
        path_suffix="/system/notifications/email_settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    BIND_SETTINGS = EndpointInfo(
        path_suffix="/services/bind/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    NTP_SETTINGS = EndpointInfo(
        path_suffix="/services/ntp/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    NTP_TIME_SERVERS = EndpointInfo(
        path_suffix="/services/ntp/time_servers",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SERVICES_SSH = EndpointInfo(
        path_suffix="/services/ssh",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    CRON_JOBS = EndpointInfo(
        path_suffix="/services/cron/jobs",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    ACME_SETTINGS = EndpointInfo(
        path_suffix="/services/acme/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FREERADIUS_EAP = EndpointInfo(
        path_suffix="/services/freeradius/eap",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DIAGNOSTICS_TABLES = EndpointInfo(
        path_suffix="/diagnostics/tables",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    AUTH_KEYS = EndpointInfo(
        path_suffix="/auth/keys",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20, owner-authorized LAB READ verification,
    # Phase 8 of the READ capability audit): confirmed LAB identity first
    # (https://pfsense-test.lab.invalid, pfSense CE 2.8.1-RELEASE,
    # distinct from the production https://pfsense.local target) and
    # confirmed the LAB's REST API package is v2.10 -- an exact,
    # byte-for-byte match (267/267 paths) against the pinned v2.10
    # reference this model was derived from. The typed GET succeeded
    # (HTTP 200, correct {"data": [...]} envelope) with zero configured
    # VLANs on the LAB appliance at verification time --
    # ENDPOINT_VERIFIED, not FIELD_MODEL_LIVE_VERIFIED (no populated
    # object to exercise field parsing); compatibility for field types
    # is instead backed by the exact schema-component match above, the
    # same method already established for the NAT mappings verification.
    INTERFACE_VLANS = EndpointInfo(
        path_suffix="/interface/vlans",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- see INTERFACE_VLANS's comment
    # INTERFACE_VLANS's comment immediately above; identical verification
    # method and the same live result (zero configured static routes,
    # schema match exact).
    ROUTING_STATIC_ROUTES = EndpointInfo(
        path_suffix="/routing/static_routes",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20, READ Expansion phase Batch 2, LAB-only
    # verification against https://pfsense-test.lab.invalid): HTTP 200,
    # correct envelope, zero configured interface groups at verification
    # time -- ENDPOINT_VERIFIED, not FIELD_MODEL_LIVE_VERIFIED; field-type
    # compatibility backed by the exact schema-component match already
    # established for this pass's LAB target (REST API v2.10, 267/267
    # paths matching the pinned reference).
    INTERFACE_GROUPS = EndpointInfo(
        path_suffix="/interface/groups",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- same LAB verification pass as
    # INTERFACE_GROUPS immediately above; identical result (zero
    # configured firewall schedules, ENDPOINT_VERIFIED only).
    FIREWALL_SCHEDULES = EndpointInfo(
        path_suffix="/firewall/schedules",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- same LAB verification pass, but this
    # one reached FIELD_MODEL_LIVE_VERIFIED: the LAB's REST API package
    # returned a fully populated singleton object (current_version,
    # latest_version, latest_version_release_date, update_available,
    # available_versions all present; install_version genuinely absent
    # from the response, confirming SystemRestApiVersion.install_version's
    # optional-field design against real live data, not just schema).
    SYSTEM_RESTAPI_VERSION = EndpointInfo(
        path_suffix="/system/restapi/version",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20, READ Expansion phase Batch 3, LAB-only
    # verification against https://pfsense-test.lab.invalid): HTTP 200,
    # correct envelope, zero configured virtual IPs at verification time
    # -- ENDPOINT_VERIFIED, not FIELD_MODEL_LIVE_VERIFIED. The confirmed
    # secret field (VirtualIP.password) is never modeled at all -- see
    # FirewallVirtualIp's docstring.
    FIREWALL_VIRTUAL_IPS = EndpointInfo(
        path_suffix="/firewall/virtual_ips",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- same LAB verification pass, and this
    # one reached FIELD_MODEL_LIVE_VERIFIED: the LAB returned one real,
    # populated CertificateAuthority object (its own internal CA). The
    # parsed model has no `prv` attribute at all -- proven by
    # construction (SystemCertificateAuthority never declares the
    # field), not merely by redacting a captured value.
    SYSTEM_CERTIFICATE_AUTHORITIES = EndpointInfo(
        path_suffix="/system/certificate_authorities",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch A, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, zero configured IPsec SAs at
    # verification time -- ENDPOINT_VERIFIED, not FIELD_MODEL_LIVE_VERIFIED;
    # field-type compatibility backed by the pinned schema-component
    # match (267/267 paths, same as every prior LAB verification).
    STATUS_IPSEC_SAS = EndpointInfo(
        path_suffix="/status/ipsec/sas",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass as
    # STATUS_IPSEC_SAS immediately above; identical result (zero
    # configured child SAs, ENDPOINT_VERIFIED only).
    STATUS_IPSEC_CHILD_SAS = EndpointInfo(
        path_suffix="/status/ipsec/child_sas",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- owner explicitly authorized
    # installing pfSense-pkg-WireGuard on this LAB (non-production,
    # READ-verification only) after the earlier HTTP 404/
    # MODEL_MISSING_REQUIRED_PACKAGE blocker. Preflight: confirmed LAB
    # identity (pfsense-test.lab.invalid, distinct from production) and
    # took a Proxmox snapshot (vmid 250 "pfSense-LAB",
    # "pre-wireguard-ce290") before installing. Post-install: pfSense/
    # pfREST confirmed healthy, a full 52-tool regression subset passed
    # unchanged, then this endpoint's own live GET succeeded (HTTP 200,
    # correct envelope, zero configured tunnels -- ENDPOINT_VERIFIED).
    # The raw response body was inspected directly for unexpected nested
    # fields (none present, since no data). WireGuardPeerStatus.
    # preshared_key remains never-modeled regardless -- that constraint
    # is independent of this verification and was re-confirmed via
    # offline sentinel-injection tests, not merely by an empty live list.
    STATUS_WIREGUARD_TUNNELS = EndpointInfo(
        path_suffix="/status/wireguard/tunnels",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass as
    # STATUS_WIREGUARD_TUNNELS immediately above; identical result (zero
    # configured peers, ENDPOINT_VERIFIED only).
    STATUS_WIREGUARD_PEERS = EndpointInfo(
        path_suffix="/status/wireguard/peers",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch B, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, zero configured OpenVPN servers at
    # verification time -- ENDPOINT_VERIFIED, not FIELD_MODEL_LIVE_VERIFIED.
    # No package required (base pfSense feature).
    STATUS_OPENVPN_SERVERS = EndpointInfo(
        path_suffix="/status/openvpn/servers",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured OpenVPN clients, ENDPOINT_VERIFIED only.
    STATUS_OPENVPN_CLIENTS = EndpointInfo(
        path_suffix="/status/openvpn/clients",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # active connections, ENDPOINT_VERIFIED only. Schema-declared
    # "Parent model: OpenVPNServerStatus", the same structural
    # relationship already established as non-redundant between
    # IPsecSaStatus/IPsecChildSaStatus -- implemented as a genuinely
    # independent, non-duplicative endpoint on that basis.
    STATUS_OPENVPN_SERVER_CONNECTIONS = EndpointInfo(
        path_suffix="/status/openvpn/server/connections",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass and same
    # non-redundancy basis as STATUS_OPENVPN_SERVER_CONNECTIONS
    # immediately above.
    STATUS_OPENVPN_SERVER_ROUTES = EndpointInfo(
        path_suffix="/status/openvpn/server/routes",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch C, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, zero configured host overrides at
    # verification time -- ENDPOINT_VERIFIED only.
    DNS_FORWARDER_HOST_OVERRIDES = EndpointInfo(
        path_suffix="/services/dns_forwarder/host_overrides",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured domain overrides, ENDPOINT_VERIFIED only.
    DNS_RESOLVER_DOMAIN_OVERRIDES = EndpointInfo(
        path_suffix="/services/dns_resolver/domain_overrides",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured access lists, ENDPOINT_VERIFIED only.
    DNS_RESOLVER_ACCESS_LISTS = EndpointInfo(
        path_suffix="/services/dns_resolver/access_lists",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch D, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, FIELD_MODEL_LIVE_VERIFIED -- the LAB
    # returned 2 real populated objects (vtnet0/vtnet1, the LAB's actual
    # WAN/LAN interfaces), not just an empty list. Redaction confirmed
    # against real data: default call returned mac=None for both; the
    # literal MAC only appeared with include_identifying_metadata=True.
    INTERFACE_AVAILABLE_INTERFACES = EndpointInfo(
        path_suffix="/interface/available_interfaces",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured GRE tunnels, ENDPOINT_VERIFIED only.
    INTERFACE_GRES = EndpointInfo(
        path_suffix="/interface/gres",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured LAGGs, ENDPOINT_VERIFIED only.
    INTERFACE_LAGGS = EndpointInfo(
        path_suffix="/interface/laggs",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch E, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, zero configured gateway groups at
    # verification time -- ENDPOINT_VERIFIED only.
    ROUTING_GATEWAY_GROUPS = EndpointInfo(
        path_suffix="/routing/gateway/groups",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; HTTP
    # 200, both fields genuinely null (no default gateway assigned on
    # this LAB) -- ENDPOINT_VERIFIED only.
    ROUTING_GATEWAY_DEFAULT = EndpointInfo(
        path_suffix="/routing/gateway/default",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; found a
    # CE 2.9.0 nullability discrepancy (DHCPRelay.interface returned
    # null despite nullable: false in the pinned schema) and fixed it
    # by widening the field before promoting -- see
    # DHCPRelay's own docstring. HTTP 200, ENDPOINT_VERIFIED only (DHCP
    # Relay disabled on this LAB).
    DHCP_RELAY = EndpointInfo(
        path_suffix="/services/dhcp_relay",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured address pools, ENDPOINT_VERIFIED only.
    DHCP_SERVER_ADDRESS_POOLS = EndpointInfo(
        path_suffix="/services/dhcp_server/address_pools",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured custom options, ENDPOINT_VERIFIED only.
    DHCP_SERVER_CUSTOM_OPTIONS = EndpointInfo(
        path_suffix="/services/dhcp_server/custom_options",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch F, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, FIELD_MODEL_LIVE_VERIFIED -- the LAB
    # returned a real populated hostname/domain ("pfSenseLAB"/"test.arpa").
    SYSTEM_HOSTNAME = EndpointInfo(
        path_suffix="/system/hostname",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass;
    # FIELD_MODEL_LIVE_VERIFIED -- "Etc/UTC" returned.
    SYSTEM_TIMEZONE = EndpointInfo(
        path_suffix="/system/timezone",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; HTTP
    # 200, ENDPOINT_VERIFIED (dnsserver/dnslocalhost both null on this
    # LAB -- no remote DNS servers configured).
    SYSTEM_DNS = EndpointInfo(
        path_suffix="/system/dns",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass;
    # FIELD_MODEL_LIVE_VERIFIED -- passwd_protect_console=False returned.
    SYSTEM_CONSOLE = EndpointInfo(
        path_suffix="/system/console",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass;
    # FIELD_MODEL_LIVE_VERIFIED -- a real populated sslcertref returned.
    SYSTEM_WEBGUI_SETTINGS = EndpointInfo(
        path_suffix="/system/webgui/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch G, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, FIELD_MODEL_LIVE_VERIFIED -- the LAB
    # returned 2 real populated entries (the default allow-all IPv4/IPv6
    # rules). Redaction confirmed against real data: default call
    # returned network=None for both; the literal network only appeared
    # with include_identifying_metadata=True.
    SYSTEM_RESTAPI_ACCESS_LIST = EndpointInfo(
        path_suffix="/system/restapi/access_list",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass; zero
    # configured CRLs, ENDPOINT_VERIFIED only. Found that
    # CertificateRevocationListRevokedCertificate.prv is the revoked
    # certificate's X509 PRIVATE KEY (marked writeOnly in the schema,
    # confirmed never modeled at all -- see that model's own docstring).
    SYSTEM_CRLS = EndpointInfo(
        path_suffix="/system/crls",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21) -- same LAB verification pass;
    # FIELD_MODEL_LIVE_VERIFIED -- 69 real available packages returned.
    SYSTEM_PACKAGE_AVAILABLE = EndpointInfo(
        path_suffix="/system/package/available",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-21, P1 Batch H, LAB-only verification
    # against https://pfsense-test.lab.invalid, pfSense CE 2.9.0-RELEASE):
    # HTTP 200, correct envelope, zero configured traffic shapers at
    # verification time -- ENDPOINT_VERIFIED only.
    FIREWALL_TRAFFIC_SHAPERS = EndpointInfo(
        path_suffix="/firewall/traffic_shapers",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # P1 Batch H candidate -- re-checked against the pinned schema for
    # secrets before implementation (none found; addr redacted by
    # default). Requires pfSense-pkg-freeradius3, confirmed NOT
    # installed on this LAB (only pfSense-pkg-WireGuard is installed) --
    # implemented and offline-tested only per the package-conditional
    # candidate rule; owner decision required before LAB installation.
    SERVICES_FREERADIUS_INTERFACES = EndpointInfo(
        path_suffix="/services/freeradius/interfaces",
        verified=False,
        min_api_version=ApiVersion.V2,
    )
    # P1 Batch H candidate -- re-checked against the pinned schema for
    # secrets before implementation (none found; mac + 5 framed_*
    # address fields redacted by default). Requires
    # pfSense-pkg-freeradius3, confirmed NOT installed on this LAB --
    # implemented and offline-tested only per the package-conditional
    # candidate rule; owner decision required before LAB installation.
    SERVICES_FREERADIUS_MACS = EndpointInfo(
        path_suffix="/services/freeradius/macs",
        verified=False,
        min_api_version=ApiVersion.V2,
    )
    # P1 Batch H candidate -- re-checked against the pinned schema for
    # secrets before implementation (none found). Requires
    # pfSense-pkg-Service_Watchdog, confirmed NOT installed on this LAB --
    # implemented and offline-tested only per the package-conditional
    # candidate rule; owner decision required before LAB installation.
    SERVICES_SERVICE_WATCHDOGS = EndpointInfo(
        path_suffix="/services/service_watchdogs",
        verified=False,
        min_api_version=ApiVersion.V2,
    )
    # P1 Batch I candidate -- re-checked against the pinned schema for
    # secrets before implementation. Re-confirmed the PSK lives only on
    # IPsecPhase1, already REJECTed separately -- no secret material on
    # Phase 2 itself. localid_address/natlocalid_address/
    # remoteid_address/pinghost redacted by default. No package
    # required (base pfSense feature). Not yet LAB-verified.
    VPN_IPSEC_PHASE2S = EndpointInfo(
        path_suffix="/vpn/ipsec/phase2s",
        verified=False,
        min_api_version=ApiVersion.V2,
    )
    # P1 Batch I candidate -- re-checked against the pinned schema for
    # secrets before implementation (none found; pure algorithm/cipher
    # capability reference data). No package required. Not yet
    # LAB-verified.
    VPN_IPSEC_PHASE1_ENCRYPTIONS = EndpointInfo(
        path_suffix="/vpn/ipsec/phase1/encryptions",
        verified=False,
        min_api_version=ApiVersion.V2,
    )
    # P1 Batch I candidate -- re-checked against the pinned schema for
    # secrets before implementation (none found). No package required.
    # Not yet LAB-verified.
    VPN_IPSEC_PHASE2_ENCRYPTIONS = EndpointInfo(
        path_suffix="/vpn/ipsec/phase2/encryptions",
        verified=False,
        min_api_version=ApiVersion.V2,
    )
