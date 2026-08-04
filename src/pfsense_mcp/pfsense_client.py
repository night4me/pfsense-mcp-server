"""PfSenseClient — domain layer. Every method returns a typed model,
never a raw dict. Tool code depends only on this class."""

from __future__ import annotations

from .endpoints import Endpoints
from .models.system import SystemStatus
from .rest_api_client import RestApiClient


class PfSenseClient:
    def __init__(self, rest_client: RestApiClient) -> None:
        self._rest = rest_client

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus:
        raw = self._rest.get(Endpoints.SYSTEM_STATUS)
        return SystemStatus.from_api(raw.get("data", {}), include_identifying_metadata=include_identifying_metadata)
