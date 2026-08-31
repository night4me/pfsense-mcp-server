"""Model for the HAProxyEmailMailer capability endpoint
(`/services/haproxy/settings/email_mailers`).

All 3 upstream fields retained -- a name plus an IP/FQDN-validated
relay-server address and port. No SMTP-auth username/password fields
exist on this model at all (confirmed via exhaustive field
enumeration) -- this is purely a relay-server address/port, no
authentication configured through this API surface. `id`/`parent_id`
are the plain internal array indices pfREST assigns (`parent_id`
identifies the parent `HAProxySettings` singleton -- always the same
value in practice), not identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyEmailMailer(BaseModel):
    id: int
    parent_id: int
    name: str | None
    mailserver: str | None
    mailserverport: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyEmailMailer":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            name=data.get("name"),
            mailserver=data.get("mailserver"),
            mailserverport=data.get("mailserverport"),
        )
