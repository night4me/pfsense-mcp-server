"""PfSenseClient — domain layer. Every method returns a typed model,
never a raw dict. Tool code depends only on this class."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import ValidationError

from .endpoints import Endpoints
from .errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from .models.acme_settings import AcmeSettings
from .models.arp_table_entry import ArpTableEntry
from .models.auth_key import AuthKey
from .models.available_interface import AvailableInterface
from .models.available_package import AvailablePackage
from .models.bind_access_list import BindAccessList
from .models.bind_settings import BindSettings
from .models.bind_sync_settings import BindSyncSettings
from .models.bind_view import BindView
from .models.bind_zone import BindZone
from .models.bind_zone_record import BindZoneRecord
from .models.carp_status import CarpStatus
from .models.certificate_revocation_list import CertificateRevocationList
from .models.config_history_revision import ConfigHistoryRevision
from .models.cron_job import CronJob
from .models.default_gateway import DefaultGateway
from .models.dhcp_lease import DhcpLease
from .models.dhcp_relay import DHCPRelay
from .models.dhcp_server import DhcpServer
from .models.dhcp_server_address_pool import DHCPServerAddressPool
from .models.dhcp_server_apply import DHCPServerApply
from .models.dhcp_server_custom_option import DHCPServerCustomOption
from .models.dhcp_static_mapping import DhcpStaticMapping
from .models.diagnostics_table import DiagnosticsTable
from .models.dns_forwarder_apply import DNSForwarderApply
from .models.dns_forwarder_host_override import DnsForwarderHostOverride
from .models.dns_resolver_access_list import DnsResolverAccessList
from .models.dns_resolver_apply import DNSResolverApply
from .models.dns_resolver_domain_override import DnsResolverDomainOverride
from .models.dns_resolver_host_override import DnsResolverHostOverride
from .models.dns_resolver_settings import DnsResolverSettings
from .models.email_notification_settings import EmailNotificationSettings
from .models.firewall import FirewallApplyStatus, FirewallRule, FirewallState, FirewallStatesSize
from .models.firewall_advanced_settings import FirewallAdvancedSettings
from .models.firewall_alias import FirewallAlias
from .models.firewall_nat_one_to_one_mapping import FirewallNatOneToOneMapping
from .models.firewall_nat_outbound_mapping import FirewallNatOutboundMapping
from .models.firewall_nat_outbound_mode import FirewallNatOutboundMode
from .models.firewall_nat_port_forward import FirewallNatPortForward
from .models.firewall_schedule import FirewallSchedule
from .models.firewall_traffic_shaper_limiter import FirewallTrafficShaperLimiter
from .models.firewall_virtual_ip import FirewallVirtualIp
from .models.free_radius_eap import FreeRadiusEap
from .models.free_radius_interface import FreeRADIUSInterface
from .models.free_radius_mac import FreeRADIUSMAC
from .models.gateways import GatewayConfig, GatewayStatus
from .models.interface_apply import InterfaceApply
from .models.interface_bridge import InterfaceBridge
from .models.interface_config import InterfaceConfig
from .models.interface_gre import InterfaceGRE
from .models.interface_group import InterfaceGroup
from .models.interface_lagg import InterfaceLAGG
from .models.interface_vlan import InterfaceVlan
from .models.interfaces import InterfaceStatus
from .models.ipsec_apply import IPsecApply
from .models.ipsec_child_sa_status import IPsecChildSaStatus
from .models.ipsec_phase1_encryption import IPsecPhase1Encryption
from .models.ipsec_phase2 import IPsecPhase2
from .models.ipsec_phase2_encryption import IPsecPhase2Encryption
from .models.ipsec_sa_status import IPsecSaStatus
from .models.log_settings import LogSettings
from .models.ntp_settings import NtpSettings
from .models.ntp_time_server import NtpTimeServer
from .models.openvpn_client_specific_override import OpenVpnClientSpecificOverride
from .models.openvpn_client_status import OpenVpnClientStatus
from .models.openvpn_server import OpenVpnServer
from .models.openvpn_server_connection_status import OpenVpnServerConnectionStatus
from .models.openvpn_server_route_status import OpenVpnServerRouteStatus
from .models.openvpn_server_status import OpenVpnServerStatus
from .models.pf_sense_user import PfSenseUser
from .models.pf_sense_user_group import PfSenseUserGroup
from .models.restapi_access_list_entry import RESTAPIAccessListEntry
from .models.routing_apply import RoutingApply
from .models.routing_gateway_group import RoutingGatewayGroup
from .models.routing_static_route import RoutingStaticRoute
from .models.service_status import ServiceStatus
from .models.service_watchdog import ServiceWatchdog
from .models.ssh_settings import SshSettings
from .models.system import SystemStatus
from .models.system_certificate import SystemCertificate
from .models.system_certificate_authority import SystemCertificateAuthority
from .models.system_console import SystemConsole
from .models.system_dns import SystemDNS
from .models.system_ha_sync import SystemHaSync
from .models.system_hostname import SystemHostname
from .models.system_package import SystemPackage
from .models.system_rest_api_settings import SystemRestApiSettings
from .models.system_restapi_version import SystemRestApiVersion
from .models.system_timezone import SystemTimezone
from .models.system_tunable import SystemTunable
from .models.system_version import SystemVersion
from .models.traffic_shaper import TrafficShaper
from .models.virtual_ip_apply import VirtualIPApply
from .models.web_gui_settings import WebGUISettings
from .models.wireguard_apply import WireGuardApply
from .models.wireguard_peer_status import WireGuardPeerStatus
from .models.wireguard_settings import WireGuardSettings
from .models.wireguard_tunnel_address import WireGuardTunnelAddress
from .models.wireguard_tunnel_status import WireGuardTunnelStatus
from .rest_api_client import RestApiClient

FIREWALL_STATES_MIN_LIMIT = 1
FIREWALL_STATES_MAX_LIMIT = 500


FIREWALL_ALIASES_MIN_LIMIT = 1
FIREWALL_ALIASES_MAX_LIMIT = 500


SERVICE_STATUS_MIN_LIMIT = 1
SERVICE_STATUS_MAX_LIMIT = 100


INTERFACE_CONFIGS_MIN_LIMIT = 1
INTERFACE_CONFIGS_MAX_LIMIT = 100


FIREWALL_NAT_PORT_FORWARDS_MIN_LIMIT = 1
FIREWALL_NAT_PORT_FORWARDS_MAX_LIMIT = 500


FIREWALL_NAT_OUTBOUND_MAPPINGS_MIN_LIMIT = 1
FIREWALL_NAT_OUTBOUND_MAPPINGS_MAX_LIMIT = 500


FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_MIN_LIMIT = 1
FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_MAX_LIMIT = 500


USERS_MIN_LIMIT = 1
USERS_MAX_LIMIT = 100


SYSTEM_CERTIFICATES_MIN_LIMIT = 1
SYSTEM_CERTIFICATES_MAX_LIMIT = 100


CONFIG_HISTORY_REVISIONS_MIN_LIMIT = 1
CONFIG_HISTORY_REVISIONS_MAX_LIMIT = 100


USER_GROUPS_MIN_LIMIT = 1
USER_GROUPS_MAX_LIMIT = 100


DHCP_LEASES_MIN_LIMIT = 1
DHCP_LEASES_MAX_LIMIT = 100


DHCP_STATIC_MAPPINGS_MIN_LIMIT = 1
DHCP_STATIC_MAPPINGS_MAX_LIMIT = 100


BIND_ACCESS_LISTS_MIN_LIMIT = 1
BIND_ACCESS_LISTS_MAX_LIMIT = 100


BIND_VIEWS_MIN_LIMIT = 1
BIND_VIEWS_MAX_LIMIT = 100


BIND_ZONES_MIN_LIMIT = 1
BIND_ZONES_MAX_LIMIT = 100


DHCP_SERVERS_MIN_LIMIT = 1
DHCP_SERVERS_MAX_LIMIT = 100


INTERFACE_BRIDGES_MIN_LIMIT = 1
INTERFACE_BRIDGES_MAX_LIMIT = 100


DNS_RESOLVER_HOST_OVERRIDES_MIN_LIMIT = 1
DNS_RESOLVER_HOST_OVERRIDES_MAX_LIMIT = 100


ARP_TABLE_MIN_LIMIT = 1
ARP_TABLE_MAX_LIMIT = 100


FIREWALL_TRAFFIC_SHAPER_LIMITERS_MIN_LIMIT = 1
FIREWALL_TRAFFIC_SHAPER_LIMITERS_MAX_LIMIT = 100


SYSTEM_PACKAGES_MIN_LIMIT = 1
SYSTEM_PACKAGES_MAX_LIMIT = 100


SYSTEM_TUNABLES_MIN_LIMIT = 1
SYSTEM_TUNABLES_MAX_LIMIT = 100


NTP_TIME_SERVERS_MIN_LIMIT = 1
NTP_TIME_SERVERS_MAX_LIMIT = 100


CRON_JOBS_MIN_LIMIT = 1
CRON_JOBS_MAX_LIMIT = 100


DIAGNOSTICS_TABLES_MIN_LIMIT = 1
DIAGNOSTICS_TABLES_MAX_LIMIT = 100


AUTH_KEYS_MIN_LIMIT = 1
AUTH_KEYS_MAX_LIMIT = 100


INTERFACE_VLANS_MIN_LIMIT = 1
INTERFACE_VLANS_MAX_LIMIT = 100


ROUTING_STATIC_ROUTES_MIN_LIMIT = 1
ROUTING_STATIC_ROUTES_MAX_LIMIT = 100


INTERFACE_GROUPS_MIN_LIMIT = 1
INTERFACE_GROUPS_MAX_LIMIT = 100


FIREWALL_SCHEDULES_MIN_LIMIT = 1
FIREWALL_SCHEDULES_MAX_LIMIT = 100


FIREWALL_VIRTUAL_IPS_MIN_LIMIT = 1
FIREWALL_VIRTUAL_IPS_MAX_LIMIT = 100


SYSTEM_CERTIFICATE_AUTHORITIES_MIN_LIMIT = 1
SYSTEM_CERTIFICATE_AUTHORITIES_MAX_LIMIT = 100


STATUS_IPSEC_SAS_MIN_LIMIT = 1
STATUS_IPSEC_SAS_MAX_LIMIT = 100


STATUS_IPSEC_CHILD_SAS_MIN_LIMIT = 1
STATUS_IPSEC_CHILD_SAS_MAX_LIMIT = 100


STATUS_WIREGUARD_TUNNELS_MIN_LIMIT = 1
STATUS_WIREGUARD_TUNNELS_MAX_LIMIT = 100


STATUS_WIREGUARD_PEERS_MIN_LIMIT = 1
STATUS_WIREGUARD_PEERS_MAX_LIMIT = 100


STATUS_OPENVPN_SERVERS_MIN_LIMIT = 1
STATUS_OPENVPN_SERVERS_MAX_LIMIT = 100


STATUS_OPENVPN_CLIENTS_MIN_LIMIT = 1
STATUS_OPENVPN_CLIENTS_MAX_LIMIT = 100


STATUS_OPENVPN_SERVER_CONNECTIONS_MIN_LIMIT = 1
STATUS_OPENVPN_SERVER_CONNECTIONS_MAX_LIMIT = 100


STATUS_OPENVPN_SERVER_ROUTES_MIN_LIMIT = 1
STATUS_OPENVPN_SERVER_ROUTES_MAX_LIMIT = 100


DNS_FORWARDER_HOST_OVERRIDES_MIN_LIMIT = 1
DNS_FORWARDER_HOST_OVERRIDES_MAX_LIMIT = 100


DNS_RESOLVER_DOMAIN_OVERRIDES_MIN_LIMIT = 1
DNS_RESOLVER_DOMAIN_OVERRIDES_MAX_LIMIT = 100


DNS_RESOLVER_ACCESS_LISTS_MIN_LIMIT = 1
DNS_RESOLVER_ACCESS_LISTS_MAX_LIMIT = 100


INTERFACE_AVAILABLE_INTERFACES_MIN_LIMIT = 1
INTERFACE_AVAILABLE_INTERFACES_MAX_LIMIT = 100


INTERFACE_GRES_MIN_LIMIT = 1
INTERFACE_GRES_MAX_LIMIT = 100


INTERFACE_LAGGS_MIN_LIMIT = 1
INTERFACE_LAGGS_MAX_LIMIT = 100


ROUTING_GATEWAY_GROUPS_MIN_LIMIT = 1
ROUTING_GATEWAY_GROUPS_MAX_LIMIT = 100


DHCP_SERVER_ADDRESS_POOLS_MIN_LIMIT = 1
DHCP_SERVER_ADDRESS_POOLS_MAX_LIMIT = 100


DHCP_SERVER_CUSTOM_OPTIONS_MIN_LIMIT = 1
DHCP_SERVER_CUSTOM_OPTIONS_MAX_LIMIT = 100


SYSTEM_RESTAPI_ACCESS_LIST_MIN_LIMIT = 1
SYSTEM_RESTAPI_ACCESS_LIST_MAX_LIMIT = 100


SYSTEM_CRLS_MIN_LIMIT = 1
SYSTEM_CRLS_MAX_LIMIT = 100


SYSTEM_PACKAGE_AVAILABLE_MIN_LIMIT = 1
SYSTEM_PACKAGE_AVAILABLE_MAX_LIMIT = 100


FIREWALL_TRAFFIC_SHAPERS_MIN_LIMIT = 1
FIREWALL_TRAFFIC_SHAPERS_MAX_LIMIT = 100


SERVICES_FREERADIUS_INTERFACES_MIN_LIMIT = 1
SERVICES_FREERADIUS_INTERFACES_MAX_LIMIT = 100


SERVICES_FREERADIUS_MACS_MIN_LIMIT = 1
SERVICES_FREERADIUS_MACS_MAX_LIMIT = 100


SERVICES_SERVICE_WATCHDOGS_MIN_LIMIT = 1
SERVICES_SERVICE_WATCHDOGS_MAX_LIMIT = 100


VPN_IPSEC_PHASE2S_MIN_LIMIT = 1
VPN_IPSEC_PHASE2S_MAX_LIMIT = 100


VPN_IPSEC_PHASE1_ENCRYPTIONS_MIN_LIMIT = 1
VPN_IPSEC_PHASE1_ENCRYPTIONS_MAX_LIMIT = 100


VPN_IPSEC_PHASE2_ENCRYPTIONS_MIN_LIMIT = 1
VPN_IPSEC_PHASE2_ENCRYPTIONS_MAX_LIMIT = 100


VPN_OPENVPN_SERVERS_MIN_LIMIT = 1
VPN_OPENVPN_SERVERS_MAX_LIMIT = 100


VPN_OPENVPN_CSOS_MIN_LIMIT = 1
VPN_OPENVPN_CSOS_MAX_LIMIT = 100

VPN_WIREGUARD_TUNNEL_ADDRESSES_MIN_LIMIT = 1
VPN_WIREGUARD_TUNNEL_ADDRESSES_MAX_LIMIT = 100

T = TypeVar("T")


def _parse_object_response(raw: dict[str, Any], response_label: str, factory: Callable[[dict[str, Any]], T]) -> T:
    if "data" not in raw:
        raise PfSenseResponseShapeError(f"pfSense {response_label} response did not contain 'data'.")
    data = raw["data"]
    if not isinstance(data, dict):
        raise PfSenseResponseShapeError(f"pfSense {response_label} response 'data' was not an object.")
    try:
        return factory(data)
    except (KeyError, TypeError, ValidationError):
        raise PfSenseResponseShapeError(f"pfSense {response_label} response failed schema validation.") from None


def _parse_list_response(raw: dict[str, Any], response_label: str, factory: Callable[[dict[str, Any]], T]) -> list[T]:
    if "data" not in raw:
        raise PfSenseResponseShapeError(f"pfSense {response_label} response did not contain 'data'.")
    data = raw["data"]
    if not isinstance(data, list):
        raise PfSenseResponseShapeError(f"pfSense {response_label} response 'data' was not a list.")
    results: list[T] = []
    for item in data:
        if not isinstance(item, dict):
            raise PfSenseResponseShapeError(
                f"pfSense {response_label} response contained a non-object entry in 'data'."
            )
        try:
            results.append(factory(item))
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                f"pfSense {response_label} response contained an entry that failed schema validation."
            ) from None
    return results


class PfSenseClient:
    def __init__(self, rest_client: RestApiClient) -> None:
        self._rest = rest_client

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus:
        raw = self._rest.get(Endpoints.SYSTEM_STATUS)
        return _parse_object_response(
            raw,
            "status/system",
            lambda data: SystemStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_interfaces(self, *, include_identifying_metadata: bool = False) -> list[InterfaceStatus]:
        raw = self._rest.get(Endpoints.STATUS_INTERFACES)
        return _parse_list_response(
            raw,
            "status/interfaces",
            lambda data: InterfaceStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_gateways(self, *, include_identifying_metadata: bool = False) -> list[GatewayConfig]:
        raw = self._rest.get(Endpoints.ROUTING_GATEWAYS)
        return _parse_list_response(
            raw,
            "routing/gateways",
            lambda data: GatewayConfig.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_gateway_status(self, *, include_identifying_metadata: bool = False) -> list[GatewayStatus]:
        raw = self._rest.get(Endpoints.STATUS_GATEWAYS)
        return _parse_list_response(
            raw,
            "status/gateways",
            lambda data: GatewayStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_firewall_rules(self, *, include_identifying_metadata: bool = False) -> list[FirewallRule]:
        raw = self._rest.get(Endpoints.FIREWALL_RULES)
        return _parse_list_response(
            raw,
            "firewall/rules",
            lambda data: FirewallRule.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_firewall_states(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallState]:
        if not (FIREWALL_STATES_MIN_LIMIT <= limit <= FIREWALL_STATES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_STATES_MIN_LIMIT} and {FIREWALL_STATES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_STATES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "firewall/states",
            lambda data: FirewallState.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_firewall_states_size(self) -> FirewallStatesSize:
        raw = self._rest.get(Endpoints.FIREWALL_STATES_SIZE)
        return _parse_object_response(raw, "firewall/states/size", FirewallStatesSize.from_api)

    def get_firewall_apply_status(self) -> FirewallApplyStatus:
        raw = self._rest.get(Endpoints.FIREWALL_APPLY_STATUS)
        return _parse_object_response(raw, "firewall/apply", FirewallApplyStatus.from_api)

    def get_firewall_aliases(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallAlias]:
        if not (FIREWALL_ALIASES_MIN_LIMIT <= limit <= FIREWALL_ALIASES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_ALIASES_MIN_LIMIT} and {FIREWALL_ALIASES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_ALIASES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/firewall/aliases",
            lambda data: FirewallAlias.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_service_status(self, *, limit: int = 100) -> list[ServiceStatus]:
        if not (SERVICE_STATUS_MIN_LIMIT <= limit <= SERVICE_STATUS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SERVICE_STATUS_MIN_LIMIT} and {SERVICE_STATUS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_SERVICES, params={"limit": limit})
        return _parse_list_response(raw, "/status/services", ServiceStatus.from_api)

    def get_system_version(self) -> SystemVersion:
        raw = self._rest.get(Endpoints.SYSTEM_VERSION)
        return _parse_object_response(raw, "/system/version", SystemVersion.from_api)

    def get_interface_configs(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[InterfaceConfig]:
        if not (INTERFACE_CONFIGS_MIN_LIMIT <= limit <= INTERFACE_CONFIGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_CONFIGS_MIN_LIMIT} and {INTERFACE_CONFIGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/interfaces",
            lambda data: InterfaceConfig.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_firewall_nat_port_forwards(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatPortForward]:
        if not (FIREWALL_NAT_PORT_FORWARDS_MIN_LIMIT <= limit <= FIREWALL_NAT_PORT_FORWARDS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_NAT_PORT_FORWARDS_MIN_LIMIT} and "
                f"{FIREWALL_NAT_PORT_FORWARDS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_NAT_PORT_FORWARDS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/firewall/nat/port_forwards",
            lambda data: FirewallNatPortForward.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_firewall_nat_outbound_mode(self) -> FirewallNatOutboundMode:
        raw = self._rest.get(Endpoints.FIREWALL_NAT_OUTBOUND_MODE)
        return _parse_object_response(raw, "/firewall/nat/outbound/mode", FirewallNatOutboundMode.from_api)

    def get_firewall_nat_outbound_mappings(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatOutboundMapping]:
        if not (FIREWALL_NAT_OUTBOUND_MAPPINGS_MIN_LIMIT <= limit <= FIREWALL_NAT_OUTBOUND_MAPPINGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_NAT_OUTBOUND_MAPPINGS_MIN_LIMIT} and "
                f"{FIREWALL_NAT_OUTBOUND_MAPPINGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_NAT_OUTBOUND_MAPPINGS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/firewall/nat/outbound/mappings",
            lambda data: FirewallNatOutboundMapping.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_firewall_nat_one_to_one_mappings(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatOneToOneMapping]:
        if not (FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_MIN_LIMIT <= limit <= FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_MIN_LIMIT} and "
                f"{FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_NAT_ONE_TO_ONE_MAPPINGS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/firewall/nat/one_to_one/mappings",
            lambda data: FirewallNatOneToOneMapping.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_users(self, *, include_identifying_metadata: bool = False, limit: int = 100) -> list[PfSenseUser]:
        if not (USERS_MIN_LIMIT <= limit <= USERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {USERS_MIN_LIMIT} and {USERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.USERS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/users",
            lambda data: PfSenseUser.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_config_history_revisions(self, *, limit: int = 100) -> list[ConfigHistoryRevision]:
        """Read-only config-history/backup revision list. Added 2026-08-16
        for ADR-026 row 18 side-effect evidence-gathering (previously
        `DIAGNOSTICS_CONFIG_HISTORY_READ` in docs/READ_BACKLOG.md, planned
        but unimplemented) -- confirms whether a given mutation created a
        config-revision/backup entry, distinct from `get_firewall_apply_status()`'s
        pending-subsystem/applied signal."""

        if not (CONFIG_HISTORY_REVISIONS_MIN_LIMIT <= limit <= CONFIG_HISTORY_REVISIONS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {CONFIG_HISTORY_REVISIONS_MIN_LIMIT} and "
                f"{CONFIG_HISTORY_REVISIONS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DIAGNOSTICS_CONFIG_HISTORY_REVISIONS, params={"limit": limit})
        return _parse_list_response(raw, "/diagnostics/config_history/revisions", ConfigHistoryRevision.from_api)

    def get_system_certificates(self, *, limit: int = 100) -> list[SystemCertificate]:
        if not (SYSTEM_CERTIFICATES_MIN_LIMIT <= limit <= SYSTEM_CERTIFICATES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_CERTIFICATES_MIN_LIMIT} and "
                f"{SYSTEM_CERTIFICATES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_CERTIFICATES, params={"limit": limit})
        return _parse_list_response(raw, "/system/certificates", SystemCertificate.from_api)

    def get_user_groups(self, *, limit: int = 100) -> list[PfSenseUserGroup]:
        if not (USER_GROUPS_MIN_LIMIT <= limit <= USER_GROUPS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {USER_GROUPS_MIN_LIMIT} and {USER_GROUPS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.USER_GROUPS, params={"limit": limit})
        return _parse_list_response(raw, "/user/groups", PfSenseUserGroup.from_api)

    def get_dhcp_leases(self, *, limit: int = 100) -> list[DhcpLease]:
        if not (DHCP_LEASES_MIN_LIMIT <= limit <= DHCP_LEASES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_LEASES_MIN_LIMIT} and {DHCP_LEASES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_DHCP_LEASES, params={"limit": limit})
        return _parse_list_response(raw, "/status/dhcp_server/leases", DhcpLease.from_api)

    def get_dhcp_static_mappings(self, *, limit: int = 100) -> list[DhcpStaticMapping]:
        if not (DHCP_STATIC_MAPPINGS_MIN_LIMIT <= limit <= DHCP_STATIC_MAPPINGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_STATIC_MAPPINGS_MIN_LIMIT} and "
                f"{DHCP_STATIC_MAPPINGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DHCP_SERVER_STATIC_MAPPINGS, params={"limit": limit})
        return _parse_list_response(raw, "/services/dhcp_server/static_mappings", DhcpStaticMapping.from_api)

    def get_dhcp_servers(self, *, limit: int = 100) -> list[DhcpServer]:
        if not (DHCP_SERVERS_MIN_LIMIT <= limit <= DHCP_SERVERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_SERVERS_MIN_LIMIT} and {DHCP_SERVERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DHCP_SERVERS, params={"limit": limit})
        return _parse_list_response(raw, "/services/dhcp_servers", DhcpServer.from_api)

    def get_interface_bridges(self, *, limit: int = 100) -> list[InterfaceBridge]:
        if not (INTERFACE_BRIDGES_MIN_LIMIT <= limit <= INTERFACE_BRIDGES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_BRIDGES_MIN_LIMIT} and {INTERFACE_BRIDGES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACE_BRIDGES, params={"limit": limit})
        return _parse_list_response(raw, "/interface/bridges", InterfaceBridge.from_api)

    def get_carp_status(self) -> CarpStatus:
        raw = self._rest.get(Endpoints.STATUS_CARP)
        return _parse_object_response(raw, "/status/carp", CarpStatus.from_api)

    def get_system_restapi_settings(self, *, include_identifying_metadata: bool = False) -> SystemRestApiSettings:
        raw = self._rest.get(Endpoints.SYSTEM_RESTAPI_SETTINGS)
        return _parse_object_response(
            raw,
            "/system/restapi/settings",
            lambda data: SystemRestApiSettings.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync:
        raw = self._rest.get(Endpoints.SYSTEM_HASYNC)
        return _parse_object_response(
            raw,
            "/system/hasync",
            lambda data: SystemHaSync.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_dns_resolver_host_overrides(self, *, limit: int = 100) -> list[DnsResolverHostOverride]:
        if not (DNS_RESOLVER_HOST_OVERRIDES_MIN_LIMIT <= limit <= DNS_RESOLVER_HOST_OVERRIDES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DNS_RESOLVER_HOST_OVERRIDES_MIN_LIMIT} and "
                f"{DNS_RESOLVER_HOST_OVERRIDES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DNS_RESOLVER_HOST_OVERRIDES, params={"limit": limit})
        return _parse_list_response(raw, "/services/dns_resolver/host_overrides", DnsResolverHostOverride.from_api)

    def get_dns_resolver_settings(self) -> DnsResolverSettings:
        raw = self._rest.get(Endpoints.DNS_RESOLVER_SETTINGS)
        return _parse_object_response(raw, "/services/dns_resolver/settings", DnsResolverSettings.from_api)

    def get_arp_table(self, *, limit: int = 100) -> list[ArpTableEntry]:
        if not (ARP_TABLE_MIN_LIMIT <= limit <= ARP_TABLE_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {ARP_TABLE_MIN_LIMIT} and {ARP_TABLE_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DIAGNOSTICS_ARP_TABLE, params={"limit": limit})
        return _parse_list_response(raw, "/diagnostics/arp_table", ArpTableEntry.from_api)

    def get_firewall_traffic_shaper_limiters(self, *, limit: int = 100) -> list[FirewallTrafficShaperLimiter]:
        if not (FIREWALL_TRAFFIC_SHAPER_LIMITERS_MIN_LIMIT <= limit <= FIREWALL_TRAFFIC_SHAPER_LIMITERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_TRAFFIC_SHAPER_LIMITERS_MIN_LIMIT} and "
                f"{FIREWALL_TRAFFIC_SHAPER_LIMITERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_TRAFFIC_SHAPER_LIMITERS, params={"limit": limit})
        return _parse_list_response(raw, "/firewall/traffic_shaper/limiters", FirewallTrafficShaperLimiter.from_api)

    def get_firewall_advanced_settings(self) -> FirewallAdvancedSettings:
        raw = self._rest.get(Endpoints.FIREWALL_ADVANCED_SETTINGS)
        return _parse_object_response(raw, "/firewall/advanced_settings", FirewallAdvancedSettings.from_api)

    def get_system_packages(self, *, limit: int = 100) -> list[SystemPackage]:
        if not (SYSTEM_PACKAGES_MIN_LIMIT <= limit <= SYSTEM_PACKAGES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_PACKAGES_MIN_LIMIT} and {SYSTEM_PACKAGES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_PACKAGES, params={"limit": limit})
        return _parse_list_response(raw, "/system/packages", SystemPackage.from_api)

    def get_system_tunables(self, *, limit: int = 100) -> list[SystemTunable]:
        if not (SYSTEM_TUNABLES_MIN_LIMIT <= limit <= SYSTEM_TUNABLES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_TUNABLES_MIN_LIMIT} and {SYSTEM_TUNABLES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_TUNABLES, params={"limit": limit})
        return _parse_list_response(raw, "/system/tunables", SystemTunable.from_api)

    def get_email_notification_settings(
        self, *, include_identifying_metadata: bool = False
    ) -> EmailNotificationSettings:
        raw = self._rest.get(Endpoints.SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS)
        return _parse_object_response(
            raw,
            "/system/notifications/email_settings",
            lambda data: EmailNotificationSettings.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_bind_settings(self) -> BindSettings:
        raw = self._rest.get(Endpoints.BIND_SETTINGS)
        return _parse_object_response(raw, "/services/bind/settings", BindSettings.from_api)

    def get_bind_access_lists(self, *, limit: int = 100) -> list[BindAccessList]:
        if not (BIND_ACCESS_LISTS_MIN_LIMIT <= limit <= BIND_ACCESS_LISTS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {BIND_ACCESS_LISTS_MIN_LIMIT} and {BIND_ACCESS_LISTS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.BIND_ACCESS_LISTS, params={"limit": limit})
        return _parse_list_response(raw, "/services/bind/access_lists", BindAccessList.from_api)

    def get_bind_sync_settings(self) -> BindSyncSettings:
        raw = self._rest.get(Endpoints.BIND_SYNC_SETTINGS)
        return _parse_object_response(raw, "/services/bind/sync/settings", BindSyncSettings.from_api)

    def get_bind_views(self, *, limit: int = 100) -> list[BindView]:
        if not (BIND_VIEWS_MIN_LIMIT <= limit <= BIND_VIEWS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {BIND_VIEWS_MIN_LIMIT} and {BIND_VIEWS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.BIND_VIEWS, params={"limit": limit})
        return _parse_list_response(raw, "/services/bind/views", BindView.from_api)

    def get_bind_zones(self, *, limit: int = 100) -> list[BindZone]:
        if not (BIND_ZONES_MIN_LIMIT <= limit <= BIND_ZONES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {BIND_ZONES_MIN_LIMIT} and {BIND_ZONES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.BIND_ZONES, params={"limit": limit})
        return _parse_list_response(raw, "/services/bind/zones", BindZone.from_api)

    def get_bind_zone_record(self, *, parent_id: int, id: int) -> BindZoneRecord:
        raw = self._rest.get(Endpoints.BIND_ZONE_RECORD, params={"parent_id": parent_id, "id": id})
        return _parse_object_response(raw, "/services/bind/zone/record", BindZoneRecord.from_api)

    def get_ntp_settings(self) -> NtpSettings:
        raw = self._rest.get(Endpoints.NTP_SETTINGS)
        return _parse_object_response(raw, "/services/ntp/settings", NtpSettings.from_api)

    def get_ntp_time_servers(self, *, limit: int = 100) -> list[NtpTimeServer]:
        if not (NTP_TIME_SERVERS_MIN_LIMIT <= limit <= NTP_TIME_SERVERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {NTP_TIME_SERVERS_MIN_LIMIT} and {NTP_TIME_SERVERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.NTP_TIME_SERVERS, params={"limit": limit})
        return _parse_list_response(raw, "/services/ntp/time_servers", NtpTimeServer.from_api)

    def get_ssh_settings(self) -> SshSettings:
        raw = self._rest.get(Endpoints.SERVICES_SSH)
        return _parse_object_response(raw, "/services/ssh", SshSettings.from_api)

    def get_cron_jobs(self, *, limit: int = 100) -> list[CronJob]:
        if not (CRON_JOBS_MIN_LIMIT <= limit <= CRON_JOBS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {CRON_JOBS_MIN_LIMIT} and {CRON_JOBS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.CRON_JOBS, params={"limit": limit})
        return _parse_list_response(raw, "/services/cron/jobs", CronJob.from_api)

    def get_acme_settings(self) -> AcmeSettings:
        raw = self._rest.get(Endpoints.ACME_SETTINGS)
        return _parse_object_response(raw, "/services/acme/settings", AcmeSettings.from_api)

    def get_freeradius_eap(self) -> FreeRadiusEap:
        raw = self._rest.get(Endpoints.FREERADIUS_EAP)
        return _parse_object_response(raw, "/services/freeradius/eap", FreeRadiusEap.from_api)

    def get_diagnostics_tables(self, *, limit: int = 100) -> list[DiagnosticsTable]:
        if not (DIAGNOSTICS_TABLES_MIN_LIMIT <= limit <= DIAGNOSTICS_TABLES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DIAGNOSTICS_TABLES_MIN_LIMIT} and "
                f"{DIAGNOSTICS_TABLES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DIAGNOSTICS_TABLES, params={"limit": limit})
        return _parse_list_response(raw, "/diagnostics/tables", DiagnosticsTable.from_api)

    def get_auth_keys(self, *, limit: int = 100) -> list[AuthKey]:
        if not (AUTH_KEYS_MIN_LIMIT <= limit <= AUTH_KEYS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {AUTH_KEYS_MIN_LIMIT} and {AUTH_KEYS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.AUTH_KEYS, params={"limit": limit})
        return _parse_list_response(raw, "/auth/keys", AuthKey.from_api)

    def get_interface_vlans(self, *, limit: int = 100) -> list[InterfaceVlan]:
        if not (INTERFACE_VLANS_MIN_LIMIT <= limit <= INTERFACE_VLANS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_VLANS_MIN_LIMIT} and {INTERFACE_VLANS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACE_VLANS, params={"limit": limit})
        return _parse_list_response(raw, "/interface/vlans", InterfaceVlan.from_api)

    def get_routing_static_routes(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[RoutingStaticRoute]:
        if not (ROUTING_STATIC_ROUTES_MIN_LIMIT <= limit <= ROUTING_STATIC_ROUTES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {ROUTING_STATIC_ROUTES_MIN_LIMIT} and "
                f"{ROUTING_STATIC_ROUTES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.ROUTING_STATIC_ROUTES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/routing/static_routes",
            lambda data: RoutingStaticRoute.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_interface_groups(self, *, limit: int = 100) -> list[InterfaceGroup]:
        if not (INTERFACE_GROUPS_MIN_LIMIT <= limit <= INTERFACE_GROUPS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_GROUPS_MIN_LIMIT} and {INTERFACE_GROUPS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACE_GROUPS, params={"limit": limit})
        return _parse_list_response(raw, "/interface/groups", InterfaceGroup.from_api)

    def get_firewall_schedules(self, *, limit: int = 100) -> list[FirewallSchedule]:
        if not (FIREWALL_SCHEDULES_MIN_LIMIT <= limit <= FIREWALL_SCHEDULES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_SCHEDULES_MIN_LIMIT} and "
                f"{FIREWALL_SCHEDULES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_SCHEDULES, params={"limit": limit})
        return _parse_list_response(raw, "/firewall/schedules", FirewallSchedule.from_api)

    def get_system_restapi_version(self) -> SystemRestApiVersion:
        raw = self._rest.get(Endpoints.SYSTEM_RESTAPI_VERSION)
        return _parse_object_response(raw, "/system/restapi/version", SystemRestApiVersion.from_api)

    def get_system_schema_openapi(self) -> dict[str, Any]:
        """The appliance's own full OpenAPI document. Deliberately
        returns the raw parsed dict, never a typed model -- this is not
        a pfSense domain object, and no consumer needs more than a
        handful of top-level keys (`paths`, `components.schemas`) from a
        document that can be several megabytes. Internal-only: no public
        MCP tool calls this method directly (see Endpoints.SYSTEM_SCHEMA_OPENAPI's
        own comment) -- pfsense_mcp.pfrest_docs.appliance_schema is the
        one caller, mirroring resolve_appliance_identity()'s reuse
        pattern for pfsense_get_official_guidance.
        """
        return self._rest.get(Endpoints.SYSTEM_SCHEMA_OPENAPI)

    def get_firewall_virtual_ips(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallVirtualIp]:
        if not (FIREWALL_VIRTUAL_IPS_MIN_LIMIT <= limit <= FIREWALL_VIRTUAL_IPS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_VIRTUAL_IPS_MIN_LIMIT} and "
                f"{FIREWALL_VIRTUAL_IPS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_VIRTUAL_IPS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/firewall/virtual_ips",
            lambda data: FirewallVirtualIp.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_system_certificate_authorities(self, *, limit: int = 100) -> list[SystemCertificateAuthority]:
        if not (SYSTEM_CERTIFICATE_AUTHORITIES_MIN_LIMIT <= limit <= SYSTEM_CERTIFICATE_AUTHORITIES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_CERTIFICATE_AUTHORITIES_MIN_LIMIT} and "
                f"{SYSTEM_CERTIFICATE_AUTHORITIES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_CERTIFICATE_AUTHORITIES, params={"limit": limit})
        return _parse_list_response(raw, "/system/certificate_authorities", SystemCertificateAuthority.from_api)

    def get_status_ipsec_sas(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[IPsecSaStatus]:
        if not (STATUS_IPSEC_SAS_MIN_LIMIT <= limit <= STATUS_IPSEC_SAS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_IPSEC_SAS_MIN_LIMIT} and {STATUS_IPSEC_SAS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_IPSEC_SAS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/ipsec/sas",
            lambda data: IPsecSaStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_status_ipsec_child_sas(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[IPsecChildSaStatus]:
        if not (STATUS_IPSEC_CHILD_SAS_MIN_LIMIT <= limit <= STATUS_IPSEC_CHILD_SAS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_IPSEC_CHILD_SAS_MIN_LIMIT} and "
                f"{STATUS_IPSEC_CHILD_SAS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_IPSEC_CHILD_SAS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/ipsec/child_sas",
            lambda data: IPsecChildSaStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_status_wireguard_tunnels(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[WireGuardTunnelStatus]:
        if not (STATUS_WIREGUARD_TUNNELS_MIN_LIMIT <= limit <= STATUS_WIREGUARD_TUNNELS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_WIREGUARD_TUNNELS_MIN_LIMIT} and "
                f"{STATUS_WIREGUARD_TUNNELS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_WIREGUARD_TUNNELS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/wireguard/tunnels",
            lambda data: WireGuardTunnelStatus.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_status_wireguard_peers(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[WireGuardPeerStatus]:
        if not (STATUS_WIREGUARD_PEERS_MIN_LIMIT <= limit <= STATUS_WIREGUARD_PEERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_WIREGUARD_PEERS_MIN_LIMIT} and "
                f"{STATUS_WIREGUARD_PEERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_WIREGUARD_PEERS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/wireguard/peers",
            lambda data: WireGuardPeerStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_status_openvpn_servers(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServerStatus]:
        if not (STATUS_OPENVPN_SERVERS_MIN_LIMIT <= limit <= STATUS_OPENVPN_SERVERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_OPENVPN_SERVERS_MIN_LIMIT} and "
                f"{STATUS_OPENVPN_SERVERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_OPENVPN_SERVERS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/openvpn/servers",
            lambda data: OpenVpnServerStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_status_openvpn_clients(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnClientStatus]:
        if not (STATUS_OPENVPN_CLIENTS_MIN_LIMIT <= limit <= STATUS_OPENVPN_CLIENTS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_OPENVPN_CLIENTS_MIN_LIMIT} and "
                f"{STATUS_OPENVPN_CLIENTS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_OPENVPN_CLIENTS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/openvpn/clients",
            lambda data: OpenVpnClientStatus.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_status_openvpn_server_connections(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServerConnectionStatus]:
        if not (STATUS_OPENVPN_SERVER_CONNECTIONS_MIN_LIMIT <= limit <= STATUS_OPENVPN_SERVER_CONNECTIONS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_OPENVPN_SERVER_CONNECTIONS_MIN_LIMIT} and "
                f"{STATUS_OPENVPN_SERVER_CONNECTIONS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_OPENVPN_SERVER_CONNECTIONS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/openvpn/server/connections",
            lambda data: OpenVpnServerConnectionStatus.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_status_openvpn_server_routes(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServerRouteStatus]:
        if not (STATUS_OPENVPN_SERVER_ROUTES_MIN_LIMIT <= limit <= STATUS_OPENVPN_SERVER_ROUTES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {STATUS_OPENVPN_SERVER_ROUTES_MIN_LIMIT} and "
                f"{STATUS_OPENVPN_SERVER_ROUTES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_OPENVPN_SERVER_ROUTES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/status/openvpn/server/routes",
            lambda data: OpenVpnServerRouteStatus.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_dns_forwarder_host_overrides(self, *, limit: int = 100) -> list[DnsForwarderHostOverride]:
        if not (DNS_FORWARDER_HOST_OVERRIDES_MIN_LIMIT <= limit <= DNS_FORWARDER_HOST_OVERRIDES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DNS_FORWARDER_HOST_OVERRIDES_MIN_LIMIT} and "
                f"{DNS_FORWARDER_HOST_OVERRIDES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DNS_FORWARDER_HOST_OVERRIDES, params={"limit": limit})
        return _parse_list_response(raw, "/services/dns_forwarder/host_overrides", DnsForwarderHostOverride.from_api)

    def get_dns_resolver_domain_overrides(self, *, limit: int = 100) -> list[DnsResolverDomainOverride]:
        if not (DNS_RESOLVER_DOMAIN_OVERRIDES_MIN_LIMIT <= limit <= DNS_RESOLVER_DOMAIN_OVERRIDES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DNS_RESOLVER_DOMAIN_OVERRIDES_MIN_LIMIT} and "
                f"{DNS_RESOLVER_DOMAIN_OVERRIDES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DNS_RESOLVER_DOMAIN_OVERRIDES, params={"limit": limit})
        return _parse_list_response(raw, "/services/dns_resolver/domain_overrides", DnsResolverDomainOverride.from_api)

    def get_dns_resolver_access_lists(self, *, limit: int = 100) -> list[DnsResolverAccessList]:
        if not (DNS_RESOLVER_ACCESS_LISTS_MIN_LIMIT <= limit <= DNS_RESOLVER_ACCESS_LISTS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DNS_RESOLVER_ACCESS_LISTS_MIN_LIMIT} and "
                f"{DNS_RESOLVER_ACCESS_LISTS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DNS_RESOLVER_ACCESS_LISTS, params={"limit": limit})
        return _parse_list_response(raw, "/services/dns_resolver/access_lists", DnsResolverAccessList.from_api)

    def get_interface_available_interfaces(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[AvailableInterface]:
        if not (INTERFACE_AVAILABLE_INTERFACES_MIN_LIMIT <= limit <= INTERFACE_AVAILABLE_INTERFACES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_AVAILABLE_INTERFACES_MIN_LIMIT} and "
                f"{INTERFACE_AVAILABLE_INTERFACES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACE_AVAILABLE_INTERFACES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/interface/available_interfaces",
            lambda data: AvailableInterface.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_interface_gres(self, *, include_identifying_metadata: bool = False, limit: int = 100) -> list[InterfaceGRE]:
        if not (INTERFACE_GRES_MIN_LIMIT <= limit <= INTERFACE_GRES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_GRES_MIN_LIMIT} and {INTERFACE_GRES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACE_GRES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/interface/gres",
            lambda data: InterfaceGRE.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_interface_laggs(self, *, limit: int = 100) -> list[InterfaceLAGG]:
        if not (INTERFACE_LAGGS_MIN_LIMIT <= limit <= INTERFACE_LAGGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_LAGGS_MIN_LIMIT} and {INTERFACE_LAGGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACE_LAGGS, params={"limit": limit})
        return _parse_list_response(raw, "/interface/laggs", InterfaceLAGG.from_api)

    def get_routing_gateway_groups(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[RoutingGatewayGroup]:
        if not (ROUTING_GATEWAY_GROUPS_MIN_LIMIT <= limit <= ROUTING_GATEWAY_GROUPS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {ROUTING_GATEWAY_GROUPS_MIN_LIMIT} and "
                f"{ROUTING_GATEWAY_GROUPS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.ROUTING_GATEWAY_GROUPS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/routing/gateway/groups",
            lambda data: RoutingGatewayGroup.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_routing_gateway_default(self, *, include_identifying_metadata: bool = False) -> DefaultGateway:
        raw = self._rest.get(Endpoints.ROUTING_GATEWAY_DEFAULT)
        return _parse_object_response(
            raw,
            "/routing/gateway/default",
            lambda data: DefaultGateway.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_dhcp_relay(self, *, include_identifying_metadata: bool = False) -> DHCPRelay:
        raw = self._rest.get(Endpoints.DHCP_RELAY)
        return _parse_object_response(
            raw,
            "/services/dhcp_relay",
            lambda data: DHCPRelay.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_dhcp_server_address_pools(self, *, limit: int = 100) -> list[DHCPServerAddressPool]:
        if not (DHCP_SERVER_ADDRESS_POOLS_MIN_LIMIT <= limit <= DHCP_SERVER_ADDRESS_POOLS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_SERVER_ADDRESS_POOLS_MIN_LIMIT} and "
                f"{DHCP_SERVER_ADDRESS_POOLS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DHCP_SERVER_ADDRESS_POOLS, params={"limit": limit})
        return _parse_list_response(raw, "/services/dhcp_server/address_pools", DHCPServerAddressPool.from_api)

    def get_dhcp_server_custom_options(self, *, limit: int = 100) -> list[DHCPServerCustomOption]:
        if not (DHCP_SERVER_CUSTOM_OPTIONS_MIN_LIMIT <= limit <= DHCP_SERVER_CUSTOM_OPTIONS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_SERVER_CUSTOM_OPTIONS_MIN_LIMIT} and "
                f"{DHCP_SERVER_CUSTOM_OPTIONS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DHCP_SERVER_CUSTOM_OPTIONS, params={"limit": limit})
        return _parse_list_response(raw, "/services/dhcp_server/custom_options", DHCPServerCustomOption.from_api)

    def get_system_hostname(self, *, include_identifying_metadata: bool = False) -> SystemHostname:
        raw = self._rest.get(Endpoints.SYSTEM_HOSTNAME)
        return _parse_object_response(
            raw,
            "/system/hostname",
            lambda data: SystemHostname.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_system_timezone(self) -> SystemTimezone:
        raw = self._rest.get(Endpoints.SYSTEM_TIMEZONE)
        return _parse_object_response(raw, "/system/timezone", SystemTimezone.from_api)

    def get_system_dns(self, *, include_identifying_metadata: bool = False) -> SystemDNS:
        raw = self._rest.get(Endpoints.SYSTEM_DNS)
        return _parse_object_response(
            raw,
            "/system/dns",
            lambda data: SystemDNS.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_system_console(self) -> SystemConsole:
        raw = self._rest.get(Endpoints.SYSTEM_CONSOLE)
        return _parse_object_response(raw, "/system/console", SystemConsole.from_api)

    def get_system_webgui_settings(self) -> WebGUISettings:
        raw = self._rest.get(Endpoints.SYSTEM_WEBGUI_SETTINGS)
        return _parse_object_response(raw, "/system/webgui/settings", WebGUISettings.from_api)

    def get_system_restapi_access_list(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[RESTAPIAccessListEntry]:
        if not (SYSTEM_RESTAPI_ACCESS_LIST_MIN_LIMIT <= limit <= SYSTEM_RESTAPI_ACCESS_LIST_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_RESTAPI_ACCESS_LIST_MIN_LIMIT} and "
                f"{SYSTEM_RESTAPI_ACCESS_LIST_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_RESTAPI_ACCESS_LIST, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/system/restapi/access_list",
            lambda data: RESTAPIAccessListEntry.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_system_crls(self, *, limit: int = 100) -> list[CertificateRevocationList]:
        if not (SYSTEM_CRLS_MIN_LIMIT <= limit <= SYSTEM_CRLS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_CRLS_MIN_LIMIT} and {SYSTEM_CRLS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_CRLS, params={"limit": limit})
        return _parse_list_response(raw, "/system/crls", CertificateRevocationList.from_api)

    def get_system_package_available(self, *, limit: int = 100) -> list[AvailablePackage]:
        if not (SYSTEM_PACKAGE_AVAILABLE_MIN_LIMIT <= limit <= SYSTEM_PACKAGE_AVAILABLE_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_PACKAGE_AVAILABLE_MIN_LIMIT} and "
                f"{SYSTEM_PACKAGE_AVAILABLE_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_PACKAGE_AVAILABLE, params={"limit": limit})
        return _parse_list_response(raw, "/system/package/available", AvailablePackage.from_api)

    def get_firewall_traffic_shapers(self, *, limit: int = 100) -> list[TrafficShaper]:
        if not (FIREWALL_TRAFFIC_SHAPERS_MIN_LIMIT <= limit <= FIREWALL_TRAFFIC_SHAPERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_TRAFFIC_SHAPERS_MIN_LIMIT} and "
                f"{FIREWALL_TRAFFIC_SHAPERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_TRAFFIC_SHAPERS, params={"limit": limit})
        return _parse_list_response(raw, "/firewall/traffic_shapers", TrafficShaper.from_api)

    def get_services_freeradius_interfaces(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FreeRADIUSInterface]:
        if not (SERVICES_FREERADIUS_INTERFACES_MIN_LIMIT <= limit <= SERVICES_FREERADIUS_INTERFACES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SERVICES_FREERADIUS_INTERFACES_MIN_LIMIT} and "
                f"{SERVICES_FREERADIUS_INTERFACES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SERVICES_FREERADIUS_INTERFACES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/services/freeradius/interfaces",
            lambda data: FreeRADIUSInterface.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_services_freeradius_macs(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FreeRADIUSMAC]:
        if not (SERVICES_FREERADIUS_MACS_MIN_LIMIT <= limit <= SERVICES_FREERADIUS_MACS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SERVICES_FREERADIUS_MACS_MIN_LIMIT} and "
                f"{SERVICES_FREERADIUS_MACS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SERVICES_FREERADIUS_MACS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/services/freeradius/macs",
            lambda data: FreeRADIUSMAC.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_services_service_watchdogs(self, *, limit: int = 100) -> list[ServiceWatchdog]:
        if not (SERVICES_SERVICE_WATCHDOGS_MIN_LIMIT <= limit <= SERVICES_SERVICE_WATCHDOGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SERVICES_SERVICE_WATCHDOGS_MIN_LIMIT} and "
                f"{SERVICES_SERVICE_WATCHDOGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SERVICES_SERVICE_WATCHDOGS, params={"limit": limit})
        return _parse_list_response(raw, "/services/service_watchdogs", ServiceWatchdog.from_api)

    def get_vpn_ipsec_phase2s(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[IPsecPhase2]:
        if not (VPN_IPSEC_PHASE2S_MIN_LIMIT <= limit <= VPN_IPSEC_PHASE2S_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {VPN_IPSEC_PHASE2S_MIN_LIMIT} and {VPN_IPSEC_PHASE2S_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.VPN_IPSEC_PHASE2S, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/vpn/ipsec/phase2s",
            lambda data: IPsecPhase2.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_vpn_ipsec_phase1_encryptions(self, *, limit: int = 100) -> list[IPsecPhase1Encryption]:
        if not (VPN_IPSEC_PHASE1_ENCRYPTIONS_MIN_LIMIT <= limit <= VPN_IPSEC_PHASE1_ENCRYPTIONS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {VPN_IPSEC_PHASE1_ENCRYPTIONS_MIN_LIMIT} and "
                f"{VPN_IPSEC_PHASE1_ENCRYPTIONS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.VPN_IPSEC_PHASE1_ENCRYPTIONS, params={"limit": limit})
        return _parse_list_response(raw, "/vpn/ipsec/phase1/encryptions", IPsecPhase1Encryption.from_api)

    def get_vpn_ipsec_phase2_encryptions(self, *, limit: int = 100) -> list[IPsecPhase2Encryption]:
        if not (VPN_IPSEC_PHASE2_ENCRYPTIONS_MIN_LIMIT <= limit <= VPN_IPSEC_PHASE2_ENCRYPTIONS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {VPN_IPSEC_PHASE2_ENCRYPTIONS_MIN_LIMIT} and "
                f"{VPN_IPSEC_PHASE2_ENCRYPTIONS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.VPN_IPSEC_PHASE2_ENCRYPTIONS, params={"limit": limit})
        return _parse_list_response(raw, "/vpn/ipsec/phase2/encryptions", IPsecPhase2Encryption.from_api)

    def get_vpn_openvpn_servers(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServer]:
        if not (VPN_OPENVPN_SERVERS_MIN_LIMIT <= limit <= VPN_OPENVPN_SERVERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {VPN_OPENVPN_SERVERS_MIN_LIMIT} and "
                f"{VPN_OPENVPN_SERVERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.VPN_OPENVPN_SERVERS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/vpn/openvpn/servers",
            lambda data: OpenVpnServer.from_api(data, include_identifying_metadata=include_identifying_metadata),
        )

    def get_vpn_openvpn_csos(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnClientSpecificOverride]:
        if not (VPN_OPENVPN_CSOS_MIN_LIMIT <= limit <= VPN_OPENVPN_CSOS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {VPN_OPENVPN_CSOS_MIN_LIMIT} and {VPN_OPENVPN_CSOS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.VPN_OPENVPN_CSOS, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/vpn/openvpn/csos",
            lambda data: OpenVpnClientSpecificOverride.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_status_logs_settings(self) -> LogSettings:
        raw = self._rest.get(Endpoints.STATUS_LOGS_SETTINGS)
        return _parse_object_response(raw, "/status/logs/settings", LogSettings.from_api)

    def get_firewall_virtual_ip_apply_status(self) -> VirtualIPApply:
        raw = self._rest.get(Endpoints.FIREWALL_VIRTUAL_IP_APPLY)
        return _parse_object_response(raw, "/firewall/virtual_ip/apply", VirtualIPApply.from_api)

    def get_interface_apply_status(self) -> InterfaceApply:
        raw = self._rest.get(Endpoints.INTERFACE_APPLY)
        return _parse_object_response(raw, "/interface/apply", InterfaceApply.from_api)

    def get_routing_apply_status(self) -> RoutingApply:
        raw = self._rest.get(Endpoints.ROUTING_APPLY)
        return _parse_object_response(raw, "/routing/apply", RoutingApply.from_api)

    def get_dhcp_server_apply_status(self) -> DHCPServerApply:
        raw = self._rest.get(Endpoints.DHCP_SERVER_APPLY)
        return _parse_object_response(raw, "/services/dhcp_server/apply", DHCPServerApply.from_api)

    def get_dns_forwarder_apply_status(self) -> DNSForwarderApply:
        raw = self._rest.get(Endpoints.DNS_FORWARDER_APPLY)
        return _parse_object_response(raw, "/services/dns_forwarder/apply", DNSForwarderApply.from_api)

    def get_dns_resolver_apply_status(self) -> DNSResolverApply:
        raw = self._rest.get(Endpoints.DNS_RESOLVER_APPLY)
        return _parse_object_response(raw, "/services/dns_resolver/apply", DNSResolverApply.from_api)

    def get_ipsec_apply_status(self) -> IPsecApply:
        raw = self._rest.get(Endpoints.VPN_IPSEC_APPLY)
        return _parse_object_response(raw, "/vpn/ipsec/apply", IPsecApply.from_api)

    def get_wireguard_apply_status(self) -> WireGuardApply:
        raw = self._rest.get(Endpoints.VPN_WIREGUARD_APPLY)
        return _parse_object_response(raw, "/vpn/wireguard/apply", WireGuardApply.from_api)

    def get_vpn_wireguard_tunnel_addresses(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[WireGuardTunnelAddress]:
        if not (VPN_WIREGUARD_TUNNEL_ADDRESSES_MIN_LIMIT <= limit <= VPN_WIREGUARD_TUNNEL_ADDRESSES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {VPN_WIREGUARD_TUNNEL_ADDRESSES_MIN_LIMIT} and "
                f"{VPN_WIREGUARD_TUNNEL_ADDRESSES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.VPN_WIREGUARD_TUNNEL_ADDRESSES, params={"limit": limit})
        return _parse_list_response(
            raw,
            "/vpn/wireguard/tunnel/addresses",
            lambda data: WireGuardTunnelAddress.from_api(
                data, include_identifying_metadata=include_identifying_metadata
            ),
        )

    def get_vpn_wireguard_settings(self) -> WireGuardSettings:
        raw = self._rest.get(Endpoints.VPN_WIREGUARD_SETTINGS)
        return _parse_object_response(raw, "/vpn/wireguard/settings", WireGuardSettings.from_api)
