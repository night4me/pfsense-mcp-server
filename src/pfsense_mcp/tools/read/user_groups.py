"""pfsense_get_user_groups tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.pf_sense_user_group import PfSenseUserGroup
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[PfSenseUserGroup]]:
    def pfsense_get_user_groups(limit: int = 100) -> list[PfSenseUserGroup]:
        """List pfSense local user groups: name, description, GID,
        member usernames, privileges, and scope. Read-only.

        limit: maximum number of groups to return (1-100, default
        100)."""
        return client.get_user_groups(limit=limit)

    return pfsense_get_user_groups
