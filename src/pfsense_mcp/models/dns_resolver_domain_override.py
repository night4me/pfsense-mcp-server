"""Model for the DnsResolverDomainOverride capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `DNSResolverDomainOverride` component (already-captured
evidence). No secret material. `domain`/`ip`/`tls_hostname` are not
redacted, matching the already-shipped `DnsResolverHostOverride`'s
established precedent -- the forwarding target address is the whole
point of a domain-override capability, not identifying metadata to
hide.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DnsResolverDomainOverride(BaseModel):
    descr: str
    domain: str
    forward_tls_upstream: bool
    ip: str
    tls_hostname: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DnsResolverDomainOverride":
        return cls(
            descr=data["descr"],
            domain=data["domain"],
            forward_tls_upstream=data["forward_tls_upstream"],
            ip=data["ip"],
            tls_hostname=data["tls_hostname"],
        )
