"""pfsense_get_users tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.pf_sense_user import PfSenseUser
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[PfSenseUser]]:
    def pfsense_get_users(include_identifying_metadata: bool = False, limit: int = 100) -> list[PfSenseUser]:
        """List pfSense local user accounts: username, description,
        id, UID, privileges, certificate references, disabled state,
        expiration, and scope. Read-only.

        include_identifying_metadata: if True, also includes
        authorized SSH keys and the IPsec pre-shared key (the only
        genuinely secret fields). Defaults to False.

        limit: maximum number of accounts to return (1-100, default
        100)."""
        return client.get_users(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_users
