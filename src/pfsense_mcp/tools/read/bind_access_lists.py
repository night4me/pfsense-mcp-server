"""pfsense_get_bind_access_lists tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.bind_access_list import BindAccessList
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[BindAccessList]]:
    def pfsense_get_bind_access_lists(limit: int = 100) -> list[BindAccessList]:
        """List pfSense BIND (DNS server) access lists: name,
        description, and network entries. Requires pfSense-pkg-bind.
        Read-only.

        limit: maximum number of access lists to return (1-100,
        default 100)."""
        return client.get_bind_access_lists(limit=limit)

    return pfsense_get_bind_access_lists
