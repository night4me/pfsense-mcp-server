"""pfsense_get_bind_settings tool definition. GENERATED PROPOSAL — review before use."""

from __future__ import annotations

from typing import Callable

from ...models.bind_settings import BindSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., BindSettings]:
    def pfsense_get_bind_settings() -> BindSettings:
        """Get pfSense BIND DNS server settings: enabled state, listen address/port, logging, and rate limiting."""
        return client.get_bind_settings()

    return pfsense_get_bind_settings
