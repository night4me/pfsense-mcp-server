"""pfsense_get_ssh_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ssh_settings import SshSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SshSettings]:
    def pfsense_get_ssh_settings() -> SshSettings:
        """Get pfSense SSH server settings: enabled state, listening
        port, agent forwarding, and key-only authentication mode.
        Read-only."""
        return client.get_ssh_settings()

    return pfsense_get_ssh_settings
