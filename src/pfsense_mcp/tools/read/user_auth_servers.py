"""pfsense_get_user_auth_servers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.pf_sense_auth_server import PfSenseAuthServer
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[PfSenseAuthServer]]:
    def pfsense_get_user_auth_servers(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[PfSenseAuthServer]:
        """List authentication server configurations (LDAP/RADIUS):
        type, connectivity settings, and directory/protocol options.
        Read-only. Does not include the LDAP bind password or the
        RADIUS shared secret under any argument.

        include_identifying_metadata: if True, includes the literal
        server host address and LDAP bind DN/base DN/auth container/
        PAM group DN. Defaults to False.

        limit: maximum number of servers to return (1-100, default
        100)."""
        return client.get_user_auth_servers(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_user_auth_servers
