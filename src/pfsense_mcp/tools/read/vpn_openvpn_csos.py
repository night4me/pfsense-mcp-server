"""pfsense_get_vpn_openvpn_csos tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.openvpn_client_specific_override import OpenVpnClientSpecificOverride
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[OpenVpnClientSpecificOverride]]:
    def pfsense_get_vpn_openvpn_csos(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnClientSpecificOverride]:
        """List OpenVPN client-specific overrides: per-client tunnel
        settings, allowed servers, and DNS/NTP/WINS pushes. Read-only.

        include_identifying_metadata: if True, includes the literal
        client common name and tunnel/local/remote network ranges plus
        DNS/NTP/WINS servers. Defaults to False.

        limit: maximum number of client-specific overrides to return
        (1-100, default 100)."""
        return client.get_vpn_openvpn_csos(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_vpn_openvpn_csos
