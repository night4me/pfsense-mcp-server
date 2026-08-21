"""Model for the DnsResolverAccessList capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `DNSResolverAccessList` component (already-captured evidence).
No secret material. `networks` is not redacted, matching the
already-shipped `DnsResolverHostOverride`'s established precedent --
the network definitions are the whole point of an access-list
capability, not identifying metadata to hide.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DnsResolverAccessList(BaseModel):
    action: str
    description: str
    name: str
    networks: list[Any]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DnsResolverAccessList":
        return cls(
            action=data["action"],
            description=data["description"],
            name=data["name"],
            networks=data["networks"],
        )
