"""Model for the OpenVpnServerStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OpenVPNServerStatus` component (already-captured evidence).
No secret material or address-bearing field at this level (`mgmt` is a
local management socket reference, not network-reachable data).

`conns`/`routes` are schema-confirmed (`$ref`) to embed full
`OpenVpnServerConnectionStatus`/`OpenVpnServerRouteStatus` objects and
are constructed through those models' own `from_api()` for every item,
never passed through as a raw dict, so their identifying-field
redaction gates stay in effect for the nested case.

`status/openvpn/server/connections` and `status/openvpn/server/routes`
are separately implemented, standalone, non-redundant endpoints (the
pinned schema declares `Parent model: OpenVPNServerStatus` for both,
the same structural relationship already established as non-redundant
between `IPsecSaStatus`/`IPsecChildSaStatus`): the nested fields here
give convenient per-server grouping, while the standalone endpoints
give a flat, independently-paginated view across all servers.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .openvpn_server_connection_status import OpenVpnServerConnectionStatus
from .openvpn_server_route_status import OpenVpnServerRouteStatus


class OpenVpnServerStatus(BaseModel):
    mgmt: str | None
    mode: str | None
    name: str | None
    port: str | None
    vpnid: int | None
    conns: list[OpenVpnServerConnectionStatus] | None
    routes: list[OpenVpnServerRouteStatus] | None

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "OpenVpnServerStatus":
        raw_conns = data["conns"]
        conns = (
            [
                OpenVpnServerConnectionStatus.from_api(item, include_identifying_metadata=include_identifying_metadata)
                for item in raw_conns
            ]
            if raw_conns is not None
            else None
        )
        raw_routes = data["routes"]
        routes = (
            [
                OpenVpnServerRouteStatus.from_api(item, include_identifying_metadata=include_identifying_metadata)
                for item in raw_routes
            ]
            if raw_routes is not None
            else None
        )
        return cls(
            mgmt=data["mgmt"],
            mode=data["mode"],
            name=data["name"],
            port=data["port"],
            vpnid=data["vpnid"],
            conns=conns,
            routes=routes,
        )
