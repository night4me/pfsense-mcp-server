"""pfsense_get_status_ipsec_sas tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ipsec_sa_status import IPsecSaStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[IPsecSaStatus]]:
    def pfsense_get_status_ipsec_sas(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[IPsecSaStatus]:
        """List live IPsec security association (SA/tunnel) status:
        state, algorithms, timers, and nested child SAs. Read-only.

        include_identifying_metadata: if True, includes the literal
        local/remote host and ID addresses (at both the tunnel and
        nested child-SA level). Defaults to False.

        limit: maximum number of SAs to return (1-100, default 100)."""
        return client.get_status_ipsec_sas(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_status_ipsec_sas
