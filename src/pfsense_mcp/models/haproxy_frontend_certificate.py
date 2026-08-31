"""Model for the HAProxyFrontendCertificate capability endpoint
(`/services/haproxy/frontend/certificates`).

`ssl_certificate` is a `ForeignModelField` pointing at `Certificate.
refid` -- a plain reference ID into pfSense's existing certificate
store, not private key material, PEM content, or a passphrase (that
content lives entirely in the separate, already-audited `Certificate`
model). `id`/`parent_id` are the plain internal array indices pfREST
assigns (`parent_id` identifies which frontend this certificate
association belongs to), not identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyFrontendCertificate(BaseModel):
    id: int
    parent_id: int
    ssl_certificate: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyFrontendCertificate":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            ssl_certificate=data.get("ssl_certificate"),
        )
