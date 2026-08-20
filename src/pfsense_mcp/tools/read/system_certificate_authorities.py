"""pfsense_get_system_certificate_authorities tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_certificate_authority import SystemCertificateAuthority
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[SystemCertificateAuthority]]:
    def pfsense_get_system_certificate_authorities(limit: int = 100) -> list[SystemCertificateAuthority]:
        """List pfSense trusted Certificate Authorities: description,
        trust/serial settings, and the CA certificate itself. The CA
        private key is never returned by this tool. Read-only.

        limit: maximum number of certificate authorities to return
        (1-100, default 100)."""
        return client.get_system_certificate_authorities(limit=limit)

    return pfsense_get_system_certificate_authorities
