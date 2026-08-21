"""pfsense_get_vpn_ipsec_phase2_encryptions tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ipsec_phase2_encryption import IPsecPhase2Encryption
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[IPsecPhase2Encryption]]:
    def pfsense_get_vpn_ipsec_phase2_encryptions(limit: int = 100) -> list[IPsecPhase2Encryption]:
        """List IPsec Phase 2 encryption algorithm capability options.
        Read-only.

        limit: maximum number of encryption options to return (1-100,
        default 100)."""
        return client.get_vpn_ipsec_phase2_encryptions(limit=limit)

    return pfsense_get_vpn_ipsec_phase2_encryptions
