"""pfsense_get_vpn_openvpn_clients tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.openvpn_client import OpenVPNClient
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[OpenVPNClient]]:
    def pfsense_get_vpn_openvpn_clients(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVPNClient]:
        """List OpenVPN client configurations: mode, protocol, device
        mode, ports, ciphers/digest, certificate references, and
        keepalive/ping settings. Read-only. Does not include the
        client's auth password, proxy password, TLS-auth/crypt key
        material, or free-text custom options.

        include_identifying_metadata: if True, includes the literal
        server/proxy addresses, tunnel network(s), and remote
        network(s). Defaults to False.

        limit: maximum number of clients to return (1-100, default
        100)."""
        return client.get_vpn_openvpn_clients(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_vpn_openvpn_clients
