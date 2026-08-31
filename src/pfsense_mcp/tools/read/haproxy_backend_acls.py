"""pfsense_get_haproxy_backend_acls tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_backend_acl import HAProxyBackendAcl
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyBackendAcl]]:
    def pfsense_get_haproxy_backend_acls(limit: int = 100) -> list[HAProxyBackendAcl]:
        """List pfSense HAProxy backend ACLs (match conditions) across
        all backends: name, expression type, comparison value.
        Requires pfSense-pkg-haproxy. Read-only. Note: when
        `expression` is `custom`, `value` is arbitrary HAProxy
        ACL-condition syntax rather than a bounded comparison string.

        limit: maximum number of ACLs to return (1-100, default
        100)."""
        return client.get_haproxy_backend_acls(limit=limit)

    return pfsense_get_haproxy_backend_acls
