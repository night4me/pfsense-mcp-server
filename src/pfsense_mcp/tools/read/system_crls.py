"""pfsense_get_system_crls tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.certificate_revocation_list import CertificateRevocationList
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[CertificateRevocationList]]:
    def pfsense_get_system_crls(limit: int = 100) -> list[CertificateRevocationList]:
        """List Certificate Revocation Lists (CRLs). Read-only.

        limit: maximum number of CRLs to return (1-100, default
        100)."""
        return client.get_system_crls(limit=limit)

    return pfsense_get_system_crls
