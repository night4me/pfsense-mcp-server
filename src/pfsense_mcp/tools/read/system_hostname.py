"""pfsense_get_system_hostname tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_hostname import SystemHostname
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemHostname]:
    def pfsense_get_system_hostname(include_identifying_metadata: bool = False) -> SystemHostname:
        """Return the current system hostname and domain. Read-only.

        include_identifying_metadata: if True, includes the literal
        hostname and domain. Defaults to False."""
        return client.get_system_hostname(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_system_hostname
