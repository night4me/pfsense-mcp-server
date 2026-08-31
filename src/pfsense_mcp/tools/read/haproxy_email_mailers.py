"""pfsense_get_haproxy_email_mailers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_email_mailer import HAProxyEmailMailer
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyEmailMailer]]:
    def pfsense_get_haproxy_email_mailers(limit: int = 100) -> list[HAProxyEmailMailer]:
        """List pfSense HAProxy email mailers (SMTP relay targets for
        alerts): name, mail-server address, and port. Requires
        pfSense-pkg-haproxy. Read-only. No SMTP authentication
        credential fields exist on this resource.

        limit: maximum number of mailers to return (1-100, default
        100)."""
        return client.get_haproxy_email_mailers(limit=limit)

    return pfsense_get_haproxy_email_mailers
