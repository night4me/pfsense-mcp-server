"""pfsense_get_ipsec_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ipsec_apply import IPsecApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], IPsecApply]:
    def pfsense_get_ipsec_apply_status() -> IPsecApply:
        """Get pfSense pending IPsec change status: whether all IPsec
        changes are applied. Read-only. Contains no identifying
        metadata."""
        return client.get_ipsec_apply_status()

    return pfsense_get_ipsec_apply_status
