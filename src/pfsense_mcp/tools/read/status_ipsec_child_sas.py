"""pfsense_get_status_ipsec_child_sas tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ipsec_child_sa_status import IPsecChildSaStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[IPsecChildSaStatus]]:
    def pfsense_get_status_ipsec_child_sas(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[IPsecChildSaStatus]:
        """List live IPsec child SA status: state, algorithms, byte/
        packet counters, and rekey timers. Read-only.

        include_identifying_metadata: if True, includes the literal
        local/remote traffic-selector subnets. Defaults to False.

        limit: maximum number of child SAs to return (1-100, default
        100)."""
        return client.get_status_ipsec_child_sas(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_status_ipsec_child_sas
