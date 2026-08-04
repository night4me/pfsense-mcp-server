"""Single source of truth for every pfSense REST API endpoint this
project uses. No other module embeds a literal '/api/...' path
string — RestApiClient is the only place a full path is constructed.

Each entry's `verified` flag must be True only once the endpoint has
been independently tested via an authenticated GET against this
instance. tests/test_endpoints_verified.py enforces this mechanically.
"""

from __future__ import annotations

from dataclasses import dataclass

from .api_version import ApiVersion


@dataclass(frozen=True)
class EndpointInfo:
    path_suffix: str  # e.g. "/status/system" — no "/api/vN" prefix
    verified: bool
    min_api_version: ApiVersion


class Endpoints:
    SYSTEM_STATUS = EndpointInfo(
        path_suffix="/status/system",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_INTERFACES = EndpointInfo(
        path_suffix="/status/interfaces",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    ROUTING_GATEWAYS = EndpointInfo(
        path_suffix="/routing/gateways",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_GATEWAYS = EndpointInfo(
        path_suffix="/status/gateways",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # Future entries added only after individual verification, e.g.:
    # INTERFACES = EndpointInfo("/interfaces", verified=False, min_api_version=ApiVersion.V2)
