"""pfsense_get_haproxy_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_apply_status import HAProxyApplyStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., HAProxyApplyStatus]:
    def pfsense_get_haproxy_apply_status() -> HAProxyApplyStatus:
        """Get pfSense HAProxy pending-changes status: whether the
        running configuration matches the last-applied configuration.
        Requires pfSense-pkg-haproxy. Read-only."""
        return client.get_haproxy_apply_status()

    return pfsense_get_haproxy_apply_status
