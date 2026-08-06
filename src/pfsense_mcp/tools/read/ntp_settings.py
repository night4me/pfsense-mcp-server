"""pfsense_get_ntp_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.ntp_settings import NtpSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., NtpSettings]:
    def pfsense_get_ntp_settings() -> NtpSettings:
        """Get pfSense NTP service settings: enabled state, listening
        interfaces, poll intervals, and peer authentication
        configuration. Read-only."""
        return client.get_ntp_settings()

    return pfsense_get_ntp_settings
