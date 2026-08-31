"""pfsense_get_haproxy_frontend_acls tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_frontend_acl import HAProxyFrontendAcl
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyFrontendAcl]]:
    def pfsense_get_haproxy_frontend_acls(limit: int = 100) -> list[HAProxyFrontendAcl]:
        """List pfSense HAProxy frontend ACLs (match conditions)
        across all frontends: name, expression type, comparison value.
        Requires pfSense-pkg-haproxy. Read-only. Note: when
        `expression` is `custom`, `value` is arbitrary HAProxy
        ACL-condition syntax rather than a bounded comparison string.

        limit: maximum number of ACLs to return (1-100, default
        100)."""
        return client.get_haproxy_frontend_acls(limit=limit)

    return pfsense_get_haproxy_frontend_acls
