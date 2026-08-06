"""pfsense_get_cron_jobs tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.cron_job import CronJob
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[CronJob]]:
    def pfsense_get_cron_jobs(limit: int = 100) -> list[CronJob]:
        """List pfSense scheduled cron jobs (command, schedule, and running user)."""
        return client.get_cron_jobs(limit=limit)

    return pfsense_get_cron_jobs
