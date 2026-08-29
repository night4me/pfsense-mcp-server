"""Single authoritative source for this package's own installed version.

Both the `--version` CLI flag (server.py) and the MCP `initialize`
response's `serverInfo.version` (application.py) resolve through this
one function, so there is exactly one place that ever calls
`importlib.metadata.version("pfsense-mcp-server")`."""

from __future__ import annotations

import importlib.metadata

_UNKNOWN_VERSION = "unknown (not installed as a package)"


def resolve_package_version() -> str:
    try:
        return importlib.metadata.version("pfsense-mcp-server")
    except importlib.metadata.PackageNotFoundError:
        return _UNKNOWN_VERSION
