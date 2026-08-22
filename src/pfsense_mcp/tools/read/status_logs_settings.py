"""pfsense_get_status_logs_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.log_settings import LogSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], LogSettings]:
    def pfsense_get_status_logs_settings() -> LogSettings:
        """Get pfSense logging configuration: which categories are
        logged, log rotation/retention settings, and remote syslog
        destination. Read-only. Contains no log content or
        credentials."""
        return client.get_status_logs_settings()

    return pfsense_get_status_logs_settings
