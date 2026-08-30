"""pfsense_get_bind_views tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.bind_view import BindView
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[BindView]]:
    def pfsense_get_bind_views(limit: int = 100) -> list[BindView]:
        """List pfSense BIND (DNS server) views: name, description,
        recursion setting, and matched/allowed access lists. Requires
        pfSense-pkg-bind. Read-only. Custom BIND config-file options
        for each view are not included.

        limit: maximum number of views to return (1-100, default
        100)."""
        return client.get_bind_views(limit=limit)

    return pfsense_get_bind_views
