"""pfsense_get_vpn_openvpn_servers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.openvpn_server import OpenVpnServer
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[OpenVpnServer]]:
    def pfsense_get_vpn_openvpn_servers(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServer]:
        """List OpenVPN server configurations: mode, protocol, TLS/cert
        references, ciphers, and topology. Read-only.

        include_identifying_metadata: if True, includes the literal
        tunnel/local/remote network ranges, DNS/NTP/WINS servers, and
        server-bridge DHCP range. Defaults to False.

        limit: maximum number of OpenVPN servers to return (1-100,
        default 100)."""
        return client.get_vpn_openvpn_servers(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_vpn_openvpn_servers
