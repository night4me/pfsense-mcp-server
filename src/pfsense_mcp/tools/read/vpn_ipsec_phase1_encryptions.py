"""pfsense_get_vpn_ipsec_phase1_encryptions tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ipsec_phase1_encryption import IPsecPhase1Encryption
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[IPsecPhase1Encryption]]:
    def pfsense_get_vpn_ipsec_phase1_encryptions(limit: int = 100) -> list[IPsecPhase1Encryption]:
        """List IPsec Phase 1 encryption algorithm/hash/DH-group
        capability options. Read-only.

        limit: maximum number of encryption options to return (1-100,
        default 100)."""
        return client.get_vpn_ipsec_phase1_encryptions(limit=limit)

    return pfsense_get_vpn_ipsec_phase1_encryptions
