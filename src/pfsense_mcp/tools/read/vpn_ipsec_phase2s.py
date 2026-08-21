"""pfsense_get_vpn_ipsec_phase2s tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ipsec_phase2 import IPsecPhase2
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[IPsecPhase2]]:
    def pfsense_get_vpn_ipsec_phase2s(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[IPsecPhase2]:
        """List IPsec Phase 2 entries: mode, protocol, encryption/hash
        options, and rekey timing. Read-only.

        include_identifying_metadata: if True, includes the literal
        local/NAT/remote endpoint addresses and monitoring ping host.
        Defaults to False.

        limit: maximum number of Phase 2 entries to return (1-100,
        default 100)."""
        return client.get_vpn_ipsec_phase2s(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_vpn_ipsec_phase2s
