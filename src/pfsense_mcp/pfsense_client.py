"""PfSenseClient — domain layer. Every method returns a typed model,
never a raw dict. Tool code depends only on this class."""

from __future__ import annotations

from pydantic import ValidationError

from .endpoints import Endpoints
from .errors import PfSenseResponseShapeError
from .models.gateways import GatewayConfig, GatewayStatus
from .models.interfaces import InterfaceStatus
from .models.system import SystemStatus
from .rest_api_client import RestApiClient


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
                gateways.append(
                    GatewayConfig.from_api(item, include_identifying_metadata=include_identifying_metadata)
                )
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
                statuses.append(
                    GatewayStatus.from_api(item, include_identifying_metadata=include_identifying_metadata)
                )
            except (KeyError, TypeError, ValidationError):
                raise PfSenseResponseShapeError(
                    "pfSense status/gateways response contained an entry that failed schema validation."
                ) from None
        return statuses
