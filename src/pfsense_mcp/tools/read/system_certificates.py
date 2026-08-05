"""pfsense_get_system_certificates tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_certificate import SystemCertificate
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[SystemCertificate]]:
    def pfsense_get_system_certificates(limit: int = 100) -> list[SystemCertificate]:
        """List pfSense certificates: name, type, CA reference,
        validity window, and public certificate/CSR content
        (never the private key — pfSense never returns it via GET).
        Read-only.

        limit: maximum number of certificates to return (1-100,
        default 100)."""
        return client.get_system_certificates(limit=limit)

    return pfsense_get_system_certificates
