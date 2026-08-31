"""pfsense_get_haproxy_frontend_certificates tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_frontend_certificate import HAProxyFrontendCertificate
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyFrontendCertificate]]:
    def pfsense_get_haproxy_frontend_certificates(limit: int = 100) -> list[HAProxyFrontendCertificate]:
        """List pfSense HAProxy frontend SNI certificate associations
        across all frontends: a reference ID into the pfSense
        certificate store per association. Requires
        pfSense-pkg-haproxy. Read-only. Does not include certificate
        content/private key material (use pfsense_get_system_certificates
        for that store).

        limit: maximum number of associations to return (1-100,
        default 100)."""
        return client.get_haproxy_frontend_certificates(limit=limit)

    return pfsense_get_haproxy_frontend_certificates
