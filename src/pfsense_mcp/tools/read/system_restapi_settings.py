"""pfsense_get_system_restapi_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_rest_api_settings import SystemRestApiSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemRestApiSettings]:
    def pfsense_get_system_restapi_settings(include_identifying_metadata: bool = False) -> SystemRestApiSettings:
        """Get pfSense's REST API service configuration: enabled
        state, auth methods, allowed interfaces, JWT expiry, logging,
        and HA sync settings. Read-only.

        include_identifying_metadata: if True, includes the HA sync
        username in the response. Defaults to False."""
        return client.get_system_restapi_settings(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_system_restapi_settings
