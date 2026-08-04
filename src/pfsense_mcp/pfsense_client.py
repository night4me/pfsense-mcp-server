"""PfSenseClient — domain layer. Every method returns a typed model,
never a raw dict. Tool code depends only on this class."""

from __future__ import annotations

from pydantic import ValidationError

from .endpoints import Endpoints
from .errors import PfSenseResponseShapeError
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
