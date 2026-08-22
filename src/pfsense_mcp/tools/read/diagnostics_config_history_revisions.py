"""pfsense_get_diagnostics_config_history_revisions tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.config_history_revision import ConfigHistoryRevision
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[ConfigHistoryRevision]]:
    def pfsense_get_diagnostics_config_history_revisions(limit: int = 100) -> list[ConfigHistoryRevision]:
        """List configuration-history (backup) revisions: when each
        change was made, its system-generated audit description, the
        pfSense version at the time, and the backup file size. Metadata
        only -- never the configuration content itself. Read-only.

        limit: maximum number of revisions to return (1-100, default
        100)."""
        return client.get_config_history_revisions(limit=limit)

    return pfsense_get_diagnostics_config_history_revisions
