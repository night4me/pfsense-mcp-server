"""pfsense_get_system_restapi_access_list tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.restapi_access_list_entry import RESTAPIAccessListEntry
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[RESTAPIAccessListEntry]]:
    def pfsense_get_system_restapi_access_list(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[RESTAPIAccessListEntry]:
        """List the REST API's own IP allow/deny access list entries.
        Read-only.

        include_identifying_metadata: if True, includes the literal
        network CIDR each entry applies to. Defaults to False.

        limit: maximum number of entries to return (1-100, default
        100)."""
        return client.get_system_restapi_access_list(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_system_restapi_access_list
