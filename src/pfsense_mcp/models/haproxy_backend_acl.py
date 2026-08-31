"""Model for the HAProxyBackendACL capability endpoint
(`/services/haproxy/backend/acls`).

All 5 upstream fields retained -- `expression` is a 25-choice enum (24
structured/bounded match types plus a `custom` choice). `value`'s risk
level (not presence) varies with `expression`: a bounded comparison
string for 24 of 25 choices, fully arbitrary HAProxy ACL-condition
syntax only when `expression == 'custom'`. Per
`POST_V1_1_HAPROXY_READ_QUALIFICATION.md` Section 12: classified
`SAFE_READ` with this residual documented rather than excluded --
excluding `value` entirely would eliminate the tool's purpose, and a
single ACL-condition line is categorically narrower than a
raw-config-file fragment.

`id`/`parent_id` are the plain internal array indices pfREST assigns
(`parent_id` identifies which backend this ACL belongs to), not
identifying/sensitive data. `not` is a Python reserved word; modeled
as `not_field` here (upstream key is still `not` on the wire, read via
`data.get("not")`).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyBackendAcl(BaseModel):
    id: int
    parent_id: int
    name: str | None
    expression: str | None
    value: str | None
    casesensitive: bool | None
    not_field: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyBackendAcl":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            name=data.get("name"),
            expression=data.get("expression"),
            value=data.get("value"),
            casesensitive=data.get("casesensitive"),
            not_field=data.get("not"),
        )
