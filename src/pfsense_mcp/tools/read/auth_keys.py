"""pfsense_get_auth_keys tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.auth_key import AuthKey
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[AuthKey]]:
    def pfsense_get_auth_keys(include_identifying_metadata: bool = False, limit: int = 100) -> list[AuthKey]:
        """List pfSense REST API keys: description, owning username,
        hash algorithm, and key length. Read-only.

        include_identifying_metadata: if True, includes the key
        material (pfSense only returns this once, at creation time --
        it is null on every subsequent read). Defaults to False."""
        return client.get_auth_keys(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_auth_keys
