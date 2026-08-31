"""pfsense_get_haproxy_frontend_error_files tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_frontend_error_file import HAProxyFrontendErrorFile
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyFrontendErrorFile]]:
    def pfsense_get_haproxy_frontend_error_files(limit: int = 100) -> list[HAProxyFrontendErrorFile]:
        """List pfSense HAProxy frontend custom error-file
        associations across all frontends: HTTP status code and the
        associated file name. Requires pfSense-pkg-haproxy. Read-only.
        Does not include the error file's own content (use
        pfsense_get_haproxy_files for the file inventory).

        limit: maximum number of associations to return (1-100,
        default 100)."""
        return client.get_haproxy_frontend_error_files(limit=limit)

    return pfsense_get_haproxy_frontend_error_files
