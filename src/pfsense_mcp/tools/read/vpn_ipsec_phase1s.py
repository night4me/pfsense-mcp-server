"""pfsense_get_vpn_ipsec_phase1s tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ipsec_phase1 import IPsecPhase1
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[IPsecPhase1]]:
    def pfsense_get_vpn_ipsec_phase1s(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[IPsecPhase1]:
        """List IPsec Phase 1 (IKE) tunnel configurations: IKE
        type/mode/protocol, interface, authentication method, rekey/
        reauth/lifetime timing, and NAT-traversal/DPD settings.
        Read-only. Does not include the pre-shared key or the nested
        encryption-algorithm list (use
        pfsense_get_vpn_ipsec_phase1_encryptions for the latter).

        include_identifying_metadata: if True, includes the literal
        remote gateway address and local/remote tunnel identity
        values. Defaults to False.

        limit: maximum number of Phase 1 entries to return (1-100,
        default 100)."""
        return client.get_vpn_ipsec_phase1s(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_vpn_ipsec_phase1s
