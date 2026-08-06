"""pfsense_get_ntp_time_servers tool definition. GENERATED PROPOSAL — review before use."""

from __future__ import annotations

from typing import Callable

from ...models.ntp_time_server import NtpTimeServer
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[NtpTimeServer]]:
    def pfsense_get_ntp_time_servers(limit: int = 100) -> list[NtpTimeServer]:
        """List pfSense configured NTP time servers (hostname, type, and selection preferences)."""
        return client.get_ntp_time_servers(limit=limit)

    return pfsense_get_ntp_time_servers
