"""PfSenseClient — domain layer. Every method returns a typed model,
never a raw dict. Tool code depends only on this class."""

from __future__ import annotations

from pydantic import ValidationError

from .endpoints import Endpoints
from .errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from .models.acme_settings import AcmeSettings
from .models.arp_table_entry import ArpTableEntry
from .models.bind_settings import BindSettings
from .models.carp_status import CarpStatus
from .models.cron_job import CronJob
from .models.dhcp_lease import DhcpLease
from .models.dhcp_server import DhcpServer
from .models.dhcp_static_mapping import DhcpStaticMapping
from .models.dns_resolver_host_override import DnsResolverHostOverride
from .models.dns_resolver_settings import DnsResolverSettings
from .models.email_notification_settings import EmailNotificationSettings
from .models.firewall import FirewallApplyStatus, FirewallRule, FirewallState, FirewallStatesSize
from .models.firewall_advanced_settings import FirewallAdvancedSettings
from .models.firewall_alias import FirewallAlias
from .models.firewall_nat_outbound_mode import FirewallNatOutboundMode
from .models.firewall_nat_port_forward import FirewallNatPortForward
from .models.firewall_traffic_shaper_limiter import FirewallTrafficShaperLimiter
from .models.free_radius_eap import FreeRadiusEap
from .models.gateways import GatewayConfig, GatewayStatus
from .models.interface_bridge import InterfaceBridge
from .models.interface_config import InterfaceConfig
from .models.interfaces import InterfaceStatus
from .models.ntp_settings import NtpSettings
from .models.ntp_time_server import NtpTimeServer
from .models.pf_sense_user import PfSenseUser
from .models.pf_sense_user_group import PfSenseUserGroup
from .models.service_status import ServiceStatus
from .models.ssh_settings import SshSettings
from .models.system import SystemStatus
from .models.system_certificate import SystemCertificate
from .models.system_ha_sync import SystemHaSync
from .models.system_package import SystemPackage
from .models.system_rest_api_settings import SystemRestApiSettings
from .models.system_tunable import SystemTunable
from .models.system_version import SystemVersion
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


USERS_MIN_LIMIT = 1
USERS_MAX_LIMIT = 100


SYSTEM_CERTIFICATES_MIN_LIMIT = 1
SYSTEM_CERTIFICATES_MAX_LIMIT = 100


USER_GROUPS_MIN_LIMIT = 1
USER_GROUPS_MAX_LIMIT = 100


DHCP_LEASES_MIN_LIMIT = 1
DHCP_LEASES_MAX_LIMIT = 100


DHCP_STATIC_MAPPINGS_MIN_LIMIT = 1
DHCP_STATIC_MAPPINGS_MAX_LIMIT = 100


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


class PfSenseClient:
    def __init__(self, rest_client: RestApiClient) -> None:
        self._rest = rest_client

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus:
        raw = self._rest.get(Endpoints.SYSTEM_STATUS)
        return SystemStatus.from_api(raw.get("data", {}), include_identifying_metadata=include_identifying_metadata)

    def get_interfaces(self, *, include_identifying_metadata: bool = False) -> list[InterfaceStatus]:
        raw = self._rest.get(Endpoints.STATUS_INTERFACES)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense status/interfaces response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense status/interfaces response 'data' was not a list.")

        interfaces: list[InterfaceStatus] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense status/interfaces response contained a non-object entry in 'data'."
                )
            try:
                interfaces.append(
                    InterfaceStatus.from_api(item, include_identifying_metadata=include_identifying_metadata)
                )
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense status/interfaces response contained an entry that failed schema validation."
                ) from None
        return interfaces

    def get_gateways(self, *, include_identifying_metadata: bool = False) -> list[GatewayConfig]:
        raw = self._rest.get(Endpoints.ROUTING_GATEWAYS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense routing/gateways response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense routing/gateways response 'data' was not a list.")

        gateways: list[GatewayConfig] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense routing/gateways response contained a non-object entry in 'data'."
                )
            try:
                gateways.append(GatewayConfig.from_api(item, include_identifying_metadata=include_identifying_metadata))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense routing/gateways response contained an entry that failed schema validation."
                ) from None
        return gateways

    def get_gateway_status(self, *, include_identifying_metadata: bool = False) -> list[GatewayStatus]:
        raw = self._rest.get(Endpoints.STATUS_GATEWAYS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense status/gateways response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense status/gateways response 'data' was not a list.")

        statuses: list[GatewayStatus] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense status/gateways response contained a non-object entry in 'data'."
                )
            try:
                statuses.append(GatewayStatus.from_api(item, include_identifying_metadata=include_identifying_metadata))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense status/gateways response contained an entry that failed schema validation."
                ) from None
        return statuses

    def get_firewall_rules(self, *, include_identifying_metadata: bool = False) -> list[FirewallRule]:
        raw = self._rest.get(Endpoints.FIREWALL_RULES)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense firewall/rules response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense firewall/rules response 'data' was not a list.")

        rules: list[FirewallRule] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense firewall/rules response contained a non-object entry in 'data'."
                )
            try:
                rules.append(FirewallRule.from_api(item, include_identifying_metadata=include_identifying_metadata))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense firewall/rules response contained an entry that failed schema validation."
                ) from None
        return rules

    def get_firewall_states(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallState]:
        if not (FIREWALL_STATES_MIN_LIMIT <= limit <= FIREWALL_STATES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_STATES_MIN_LIMIT} and {FIREWALL_STATES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_STATES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense firewall/states response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense firewall/states response 'data' was not a list.")

        states: list[FirewallState] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense firewall/states response contained a non-object entry in 'data'."
                )
            try:
                states.append(FirewallState.from_api(item, include_identifying_metadata=include_identifying_metadata))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense firewall/states response contained an entry that failed schema validation."
                ) from None
        return states

    def get_firewall_states_size(self) -> FirewallStatesSize:
        raw = self._rest.get(Endpoints.FIREWALL_STATES_SIZE)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense firewall/states/size response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense firewall/states/size response 'data' was not an object.")
        try:
            return FirewallStatesSize.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError("pfSense firewall/states/size response failed schema validation.") from None

    def get_firewall_apply_status(self) -> FirewallApplyStatus:
        raw = self._rest.get(Endpoints.FIREWALL_APPLY_STATUS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense firewall/apply response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense firewall/apply response 'data' was not an object.")
        try:
            return FirewallApplyStatus.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError("pfSense firewall/apply response failed schema validation.") from None

    def get_firewall_aliases(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallAlias]:
        if not (FIREWALL_ALIASES_MIN_LIMIT <= limit <= FIREWALL_ALIASES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_ALIASES_MIN_LIMIT} and {FIREWALL_ALIASES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_ALIASES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /firewall/aliases response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /firewall/aliases response 'data' was not a list.")

        results: list[FirewallAlias] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /firewall/aliases response contained a non-object entry in 'data'."
                )
            try:
                results.append(FirewallAlias.from_api(item, include_identifying_metadata=include_identifying_metadata))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /firewall/aliases response contained an entry that failed schema validation."
                ) from None
        return results

    def get_service_status(self, *, limit: int = 100) -> list[ServiceStatus]:
        if not (SERVICE_STATUS_MIN_LIMIT <= limit <= SERVICE_STATUS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SERVICE_STATUS_MIN_LIMIT} and {SERVICE_STATUS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_SERVICES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /status/services response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /status/services response 'data' was not a list.")

        results: list[ServiceStatus] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /status/services response contained a non-object entry in 'data'."
                )
            try:
                results.append(ServiceStatus.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /status/services response contained an entry that failed schema validation."
                ) from None
        return results

    def get_system_version(self) -> SystemVersion:
        raw = self._rest.get(Endpoints.SYSTEM_VERSION)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /system/version response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /system/version response 'data' was not an object.")
        try:
            return SystemVersion.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError("pfSense /system/version response failed schema validation.") from None

    def get_interface_configs(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[InterfaceConfig]:
        if not (INTERFACE_CONFIGS_MIN_LIMIT <= limit <= INTERFACE_CONFIGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_CONFIGS_MIN_LIMIT} and {INTERFACE_CONFIGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /interfaces response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /interfaces response 'data' was not a list.")

        results: list[InterfaceConfig] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError("pfSense /interfaces response contained a non-object entry in 'data'.")
            try:
                results.append(
                    InterfaceConfig.from_api(item, include_identifying_metadata=include_identifying_metadata)
                )
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /interfaces response contained an entry that failed schema validation."
                ) from None
        return results

    def get_firewall_nat_port_forwards(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatPortForward]:
        if not (FIREWALL_NAT_PORT_FORWARDS_MIN_LIMIT <= limit <= FIREWALL_NAT_PORT_FORWARDS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_NAT_PORT_FORWARDS_MIN_LIMIT} and "
                f"{FIREWALL_NAT_PORT_FORWARDS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_NAT_PORT_FORWARDS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /firewall/nat/port_forwards response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /firewall/nat/port_forwards response 'data' was not a list.")

        results: list[FirewallNatPortForward] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /firewall/nat/port_forwards response contained a non-object entry in 'data'."
                )
            try:
                results.append(
                    FirewallNatPortForward.from_api(item, include_identifying_metadata=include_identifying_metadata)
                )
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /firewall/nat/port_forwards response contained an entry that failed schema validation."
                ) from None
        return results

    def get_firewall_nat_outbound_mode(self) -> FirewallNatOutboundMode:
        raw = self._rest.get(Endpoints.FIREWALL_NAT_OUTBOUND_MODE)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /firewall/nat/outbound/mode response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /firewall/nat/outbound/mode response 'data' was not an object.")
        try:
            return FirewallNatOutboundMode.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /firewall/nat/outbound/mode response failed schema validation."
            ) from None

    def get_users(self, *, include_identifying_metadata: bool = False, limit: int = 100) -> list[PfSenseUser]:
        if not (USERS_MIN_LIMIT <= limit <= USERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {USERS_MIN_LIMIT} and {USERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.USERS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /users response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /users response 'data' was not a list.")

        results: list[PfSenseUser] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError("pfSense /users response contained a non-object entry in 'data'.")
            try:
                results.append(PfSenseUser.from_api(item, include_identifying_metadata=include_identifying_metadata))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /users response contained an entry that failed schema validation."
                ) from None
        return results

    def get_system_certificates(self, *, limit: int = 100) -> list[SystemCertificate]:
        if not (SYSTEM_CERTIFICATES_MIN_LIMIT <= limit <= SYSTEM_CERTIFICATES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_CERTIFICATES_MIN_LIMIT} and "
                f"{SYSTEM_CERTIFICATES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_CERTIFICATES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /system/certificates response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /system/certificates response 'data' was not a list.")

        results: list[SystemCertificate] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /system/certificates response contained a non-object entry in 'data'."
                )
            try:
                results.append(SystemCertificate.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /system/certificates response contained an entry that failed schema validation."
                ) from None
        return results

    def get_user_groups(self, *, limit: int = 100) -> list[PfSenseUserGroup]:
        if not (USER_GROUPS_MIN_LIMIT <= limit <= USER_GROUPS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {USER_GROUPS_MIN_LIMIT} and {USER_GROUPS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.USER_GROUPS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /user/groups response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /user/groups response 'data' was not a list.")

        results: list[PfSenseUserGroup] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError("pfSense /user/groups response contained a non-object entry in 'data'.")
            try:
                results.append(PfSenseUserGroup.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /user/groups response contained an entry that failed schema validation."
                ) from None
        return results

    def get_dhcp_leases(self, *, limit: int = 100) -> list[DhcpLease]:
        if not (DHCP_LEASES_MIN_LIMIT <= limit <= DHCP_LEASES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_LEASES_MIN_LIMIT} and {DHCP_LEASES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.STATUS_DHCP_LEASES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /status/dhcp_server/leases response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /status/dhcp_server/leases response 'data' was not a list.")

        results: list[DhcpLease] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /status/dhcp_server/leases response contained a non-object entry in 'data'."
                )
            try:
                results.append(DhcpLease.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /status/dhcp_server/leases response contained an entry that failed schema validation."
                ) from None
        return results

    def get_dhcp_static_mappings(self, *, limit: int = 100) -> list[DhcpStaticMapping]:
        if not (DHCP_STATIC_MAPPINGS_MIN_LIMIT <= limit <= DHCP_STATIC_MAPPINGS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_STATIC_MAPPINGS_MIN_LIMIT} and "
                f"{DHCP_STATIC_MAPPINGS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DHCP_SERVER_STATIC_MAPPINGS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError(
                "pfSense /services/dhcp_server/static_mappings response did not contain 'data'."
            )
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError(
                "pfSense /services/dhcp_server/static_mappings response 'data' was not a list."
            )

        results: list[DhcpStaticMapping] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /services/dhcp_server/static_mappings response contained a non-object entry in 'data'."
                )
            try:
                results.append(DhcpStaticMapping.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /services/dhcp_server/static_mappings response contained an entry "
                    "that failed schema validation."
                ) from None
        return results

    def get_dhcp_servers(self, *, limit: int = 100) -> list[DhcpServer]:
        if not (DHCP_SERVERS_MIN_LIMIT <= limit <= DHCP_SERVERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DHCP_SERVERS_MIN_LIMIT} and {DHCP_SERVERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DHCP_SERVERS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/dhcp_servers response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /services/dhcp_servers response 'data' was not a list.")

        results: list[DhcpServer] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /services/dhcp_servers response contained a non-object entry in 'data'."
                )
            try:
                results.append(DhcpServer.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /services/dhcp_servers response contained an entry that failed schema validation."
                ) from None
        return results

    def get_interface_bridges(self, *, limit: int = 100) -> list[InterfaceBridge]:
        if not (INTERFACE_BRIDGES_MIN_LIMIT <= limit <= INTERFACE_BRIDGES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {INTERFACE_BRIDGES_MIN_LIMIT} and {INTERFACE_BRIDGES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.INTERFACE_BRIDGES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /interface/bridges response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /interface/bridges response 'data' was not a list.")

        results: list[InterfaceBridge] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /interface/bridges response contained a non-object entry in 'data'."
                )
            try:
                results.append(InterfaceBridge.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /interface/bridges response contained an entry that failed schema validation."
                ) from None
        return results

    def get_carp_status(self) -> CarpStatus:
        raw = self._rest.get(Endpoints.STATUS_CARP)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /status/carp response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /status/carp response 'data' was not an object.")
        try:
            return CarpStatus.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError("pfSense /status/carp response failed schema validation.") from None

    def get_system_restapi_settings(self, *, include_identifying_metadata: bool = False) -> SystemRestApiSettings:
        raw = self._rest.get(Endpoints.SYSTEM_RESTAPI_SETTINGS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /system/restapi/settings response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /system/restapi/settings response 'data' was not an object.")
        try:
            return SystemRestApiSettings.from_api(data, include_identifying_metadata=include_identifying_metadata)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /system/restapi/settings response failed schema validation."
            ) from None

    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync:
        raw = self._rest.get(Endpoints.SYSTEM_HASYNC)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /system/hasync response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /system/hasync response 'data' was not an object.")
        try:
            return SystemHaSync.from_api(data, include_identifying_metadata=include_identifying_metadata)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError("pfSense /system/hasync response failed schema validation.") from None

    def get_dns_resolver_host_overrides(self, *, limit: int = 100) -> list[DnsResolverHostOverride]:
        if not (DNS_RESOLVER_HOST_OVERRIDES_MIN_LIMIT <= limit <= DNS_RESOLVER_HOST_OVERRIDES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {DNS_RESOLVER_HOST_OVERRIDES_MIN_LIMIT} and "
                f"{DNS_RESOLVER_HOST_OVERRIDES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DNS_RESOLVER_HOST_OVERRIDES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError(
                "pfSense /services/dns_resolver/host_overrides response did not contain 'data'."
            )
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError(
                "pfSense /services/dns_resolver/host_overrides response 'data' was not a list."
            )

        results: list[DnsResolverHostOverride] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /services/dns_resolver/host_overrides response contained a non-object entry in 'data'."
                )
            try:
                results.append(DnsResolverHostOverride.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /services/dns_resolver/host_overrides response contained an entry "
                    "that failed schema validation."
                ) from None
        return results

    def get_dns_resolver_settings(self) -> DnsResolverSettings:
        raw = self._rest.get(Endpoints.DNS_RESOLVER_SETTINGS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/dns_resolver/settings response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError(
                "pfSense /services/dns_resolver/settings response 'data' was not an object."
            )
        try:
            return DnsResolverSettings.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /services/dns_resolver/settings response failed schema validation."
            ) from None

    def get_arp_table(self, *, limit: int = 100) -> list[ArpTableEntry]:
        if not (ARP_TABLE_MIN_LIMIT <= limit <= ARP_TABLE_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {ARP_TABLE_MIN_LIMIT} and {ARP_TABLE_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.DIAGNOSTICS_ARP_TABLE, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /diagnostics/arp_table response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /diagnostics/arp_table response 'data' was not a list.")

        results: list[ArpTableEntry] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /diagnostics/arp_table response contained a non-object entry in 'data'."
                )
            try:
                results.append(ArpTableEntry.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /diagnostics/arp_table response contained an entry that failed schema validation."
                ) from None
        return results

    def get_firewall_traffic_shaper_limiters(self, *, limit: int = 100) -> list[FirewallTrafficShaperLimiter]:
        if not (FIREWALL_TRAFFIC_SHAPER_LIMITERS_MIN_LIMIT <= limit <= FIREWALL_TRAFFIC_SHAPER_LIMITERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {FIREWALL_TRAFFIC_SHAPER_LIMITERS_MIN_LIMIT} and "
                f"{FIREWALL_TRAFFIC_SHAPER_LIMITERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.FIREWALL_TRAFFIC_SHAPER_LIMITERS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError(
                "pfSense /firewall/traffic_shaper/limiters response did not contain 'data'."
            )
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /firewall/traffic_shaper/limiters response 'data' was not a list.")

        results: list[FirewallTrafficShaperLimiter] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /firewall/traffic_shaper/limiters response contained a non-object entry in 'data'."
                )
            try:
                results.append(FirewallTrafficShaperLimiter.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /firewall/traffic_shaper/limiters response contained an entry "
                    "that failed schema validation."
                ) from None
        return results

    def get_firewall_advanced_settings(self) -> FirewallAdvancedSettings:
        raw = self._rest.get(Endpoints.FIREWALL_ADVANCED_SETTINGS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /firewall/advanced_settings response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /firewall/advanced_settings response 'data' was not an object.")
        try:
            return FirewallAdvancedSettings.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /firewall/advanced_settings response failed schema validation."
            ) from None

    def get_system_packages(self, *, limit: int = 100) -> list[SystemPackage]:
        if not (SYSTEM_PACKAGES_MIN_LIMIT <= limit <= SYSTEM_PACKAGES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_PACKAGES_MIN_LIMIT} and {SYSTEM_PACKAGES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_PACKAGES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /system/packages response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /system/packages response 'data' was not a list.")

        results: list[SystemPackage] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /system/packages response contained a non-object entry in 'data'."
                )
            try:
                results.append(SystemPackage.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /system/packages response contained an entry that failed schema validation."
                ) from None
        return results

    def get_system_tunables(self, *, limit: int = 100) -> list[SystemTunable]:
        if not (SYSTEM_TUNABLES_MIN_LIMIT <= limit <= SYSTEM_TUNABLES_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {SYSTEM_TUNABLES_MIN_LIMIT} and {SYSTEM_TUNABLES_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.SYSTEM_TUNABLES, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /system/tunables response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /system/tunables response 'data' was not a list.")

        results: list[SystemTunable] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /system/tunables response contained a non-object entry in 'data'."
                )
            try:
                results.append(SystemTunable.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /system/tunables response contained an entry that failed schema validation."
                ) from None
        return results

    def get_email_notification_settings(
        self, *, include_identifying_metadata: bool = False
    ) -> EmailNotificationSettings:
        raw = self._rest.get(Endpoints.SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS)

        if "data" not in raw:
            raise PfSenseResponseShapeError(
                "pfSense /system/notifications/email_settings response did not contain 'data'."
            )
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError(
                "pfSense /system/notifications/email_settings response 'data' was not an object."
            )
        try:
            return EmailNotificationSettings.from_api(data, include_identifying_metadata=include_identifying_metadata)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /system/notifications/email_settings response failed schema validation."
            ) from None

    def get_bind_settings(self) -> BindSettings:
        raw = self._rest.get(Endpoints.BIND_SETTINGS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/bind/settings response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /services/bind/settings response 'data' was not an object.")
        try:
            return BindSettings.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /services/bind/settings response failed schema validation."
            ) from None

    def get_ntp_settings(self) -> NtpSettings:
        raw = self._rest.get(Endpoints.NTP_SETTINGS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/ntp/settings response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /services/ntp/settings response 'data' was not an object.")
        try:
            return NtpSettings.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /services/ntp/settings response failed schema validation."
            ) from None

    def get_ntp_time_servers(self, *, limit: int = 100) -> list[NtpTimeServer]:
        if not (NTP_TIME_SERVERS_MIN_LIMIT <= limit <= NTP_TIME_SERVERS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {NTP_TIME_SERVERS_MIN_LIMIT} and {NTP_TIME_SERVERS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.NTP_TIME_SERVERS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/ntp/time_servers response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /services/ntp/time_servers response 'data' was not a list.")

        results: list[NtpTimeServer] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /services/ntp/time_servers response contained a non-object entry in 'data'."
                )
            try:
                results.append(NtpTimeServer.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /services/ntp/time_servers response contained an entry that failed schema validation."
                ) from None
        return results

    def get_ssh_settings(self) -> SshSettings:
        raw = self._rest.get(Endpoints.SERVICES_SSH)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/ssh response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /services/ssh response 'data' was not an object.")
        try:
            return SshSettings.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError("pfSense /services/ssh response failed schema validation.") from None

    def get_cron_jobs(self, *, limit: int = 100) -> list[CronJob]:
        if not (CRON_JOBS_MIN_LIMIT <= limit <= CRON_JOBS_MAX_LIMIT):
            raise PfSenseRequestValidationError(
                f"limit must be between {CRON_JOBS_MIN_LIMIT} and {CRON_JOBS_MAX_LIMIT} (got {limit})."
            )

        raw = self._rest.get(Endpoints.CRON_JOBS, params={"limit": limit})

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/cron/jobs response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, list):
            raise PfSenseResponseShapeError("pfSense /services/cron/jobs response 'data' was not a list.")

        results: list[CronJob] = []
        for item in data:
            if not isinstance(item, dict):
                raise PfSenseResponseShapeError(
                    "pfSense /services/cron/jobs response contained a non-object entry in 'data'."
                )
            try:
                results.append(CronJob.from_api(item))
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense /services/cron/jobs response contained an entry that failed schema validation."
                ) from None
        return results

    def get_acme_settings(self) -> AcmeSettings:
        raw = self._rest.get(Endpoints.ACME_SETTINGS)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/acme/settings response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /services/acme/settings response 'data' was not an object.")
        try:
            return AcmeSettings.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /services/acme/settings response failed schema validation."
            ) from None

    def get_freeradius_eap(self) -> FreeRadiusEap:
        raw = self._rest.get(Endpoints.FREERADIUS_EAP)

        if "data" not in raw:
            raise PfSenseResponseShapeError("pfSense /services/freeradius/eap response did not contain 'data'.")
        data = raw["data"]
        if not isinstance(data, dict):
            raise PfSenseResponseShapeError("pfSense /services/freeradius/eap response 'data' was not an object.")
        try:
            return FreeRadiusEap.from_api(data)
        except (KeyError, TypeError, ValidationError):
            raise PfSenseResponseShapeError(
                "pfSense /services/freeradius/eap response failed schema validation."
            ) from None
