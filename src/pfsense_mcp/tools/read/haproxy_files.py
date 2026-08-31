"""pfsense_get_haproxy_files tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_file import HAProxyFile
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyFile]]:
    def pfsense_get_haproxy_files(limit: int = 100) -> list[HAProxyFile]:
        """List pfSense HAProxy managed files (Lua scripts, custom
        error files, other uploaded files): name and type only.
        Requires pfSense-pkg-haproxy. Read-only. Does not include file
        content.

        limit: maximum number of files to return (1-100, default
        100)."""
        return client.get_haproxy_files(limit=limit)

    return pfsense_get_haproxy_files
