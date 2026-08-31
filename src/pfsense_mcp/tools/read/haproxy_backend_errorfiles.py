"""pfsense_get_haproxy_backend_errorfiles tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_backend_error_file import HAProxyBackendErrorFile
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyBackendErrorFile]]:
    def pfsense_get_haproxy_backend_errorfiles(limit: int = 100) -> list[HAProxyBackendErrorFile]:
        """List pfSense HAProxy backend custom error-file associations
        across all backends: HTTP status code and the associated file
        name. Requires pfSense-pkg-haproxy. Read-only. Does not
        include the error file's own content (use
        pfsense_get_haproxy_files for the file inventory).

        limit: maximum number of associations to return (1-100,
        default 100)."""
        return client.get_haproxy_backend_errorfiles(limit=limit)

    return pfsense_get_haproxy_backend_errorfiles
