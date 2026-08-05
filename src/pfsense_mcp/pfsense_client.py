"""PfSenseClient — domain layer. Every method returns a typed model,
never a raw dict. Tool code depends only on this class."""

from __future__ import annotations

from pydantic import ValidationError

from .endpoints import Endpoints
from .errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from .models.firewall import FirewallApplyStatus, FirewallRule, FirewallState, FirewallStatesSize
from .models.gateways import GatewayConfig, GatewayStatus
from .models.interfaces import InterfaceStatus
from .models.system import SystemStatus
from .rest_api_client import RestApiClient

FIREWALL_STATES_MIN_LIMIT = 1
FIREWALL_STATES_MAX_LIMIT = 500


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
