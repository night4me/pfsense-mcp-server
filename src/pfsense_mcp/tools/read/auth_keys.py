"""pfsense_get_auth_keys tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.auth_key import AuthKey
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[AuthKey]]:
    def pfsense_get_auth_keys(limit: int = 100) -> list[AuthKey]:
        """List pfSense REST API keys: description, owning username,
        hash algorithm, and key length. Read-only.

        Plaintext key material is never returned.

        limit: maximum number of key records to return (1-100,
        default 100)."""
        return client.get_auth_keys(limit=limit)

    return pfsense_get_auth_keys
