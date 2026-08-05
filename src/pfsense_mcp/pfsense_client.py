"""PfSenseClient — domain layer. Every method returns a typed model,
never a raw dict. Tool code depends only on this class."""

from __future__ import annotations

from pydantic import ValidationError

from .endpoints import Endpoints
from .errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from .models.dhcp_lease import DhcpLease
from .models.dhcp_static_mapping import DhcpStaticMapping
from .models.firewall import FirewallApplyStatus, FirewallRule, FirewallState, FirewallStatesSize
from .models.firewall_alias import FirewallAlias
from .models.firewall_nat_outbound_mode import FirewallNatOutboundMode
from .models.firewall_nat_port_forward import FirewallNatPortForward
from .models.gateways import GatewayConfig, GatewayStatus
from .models.interface_config import InterfaceConfig
from .models.interfaces import InterfaceStatus
from .models.pf_sense_user import PfSenseUser
from .models.pf_sense_user_group import PfSenseUserGroup
from .models.service_status import ServiceStatus
from .models.system import SystemStatus
from .models.system_certificate import SystemCertificate
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
