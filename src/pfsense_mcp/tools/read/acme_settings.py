"""pfsense_get_acme_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.acme_settings import AcmeSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., AcmeSettings]:
    def pfsense_get_acme_settings() -> AcmeSettings:
        """Get pfSense ACME (Let's Encrypt) package settings: whether
        the service is enabled and whether issued certificates are
        written to disk. Read-only."""
        return client.get_acme_settings()

    return pfsense_get_acme_settings
