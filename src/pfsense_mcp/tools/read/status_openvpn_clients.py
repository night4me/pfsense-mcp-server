"""pfsense_get_status_openvpn_clients tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.openvpn_client_status import OpenVpnClientStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[OpenVpnClientStatus]]:
    def pfsense_get_status_openvpn_clients(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnClientStatus]:
        """List live OpenVPN client status: connection state and
        virtual/remote address details. Read-only.

        include_identifying_metadata: if True, includes the literal
        local/remote/virtual addresses. Defaults to False.

        limit: maximum number of clients to return (1-100, default
        100)."""
        return client.get_status_openvpn_clients(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_status_openvpn_clients
