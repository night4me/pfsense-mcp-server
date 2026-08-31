"""pfsense_get_haproxy_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_settings import HAProxySettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., HAProxySettings]:
    def pfsense_get_haproxy_settings() -> HAProxySettings:
        """Get pfSense HAProxy global settings: enabled state,
        connection/thread limits, stats and DNS-resolver timing, and
        logging/SSL-compatibility settings. Requires
        pfSense-pkg-haproxy. Read-only. `advanced` (raw
        config-injection-risk free text) and the nested DNS-resolver/
        email-mailer lists are deliberately excluded (use
        pfsense_get_haproxy_dns_resolvers/pfsense_get_haproxy_email_mailers
        instead)."""
        return client.get_haproxy_settings()

    return pfsense_get_haproxy_settings
