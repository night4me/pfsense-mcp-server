"""Model for the DnsForwarderHostOverride capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `DNSForwarderHostOverride` component (already-captured
evidence). No secret material. `host`/`domain`/`ip`/`aliases` are not
redacted, matching the already-shipped `DnsResolverHostOverride`'s
established precedent for the exact same capability shape (a different
DNS backend, dnsmasq instead of Unbound) -- host/address data is the
whole point of a host-override capability, not identifying metadata to
hide, the same reasoning already documented for `DhcpServer`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DnsForwarderHostOverride(BaseModel):
    aliases: list[Any]
    descr: str
    domain: str
    host: str
    ip: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DnsForwarderHostOverride":
        return cls(
            aliases=data["aliases"],
            descr=data["descr"],
            domain=data["domain"],
            host=data["host"],
            ip=data["ip"],
        )
