"""Model for the HAProxyFrontendACL capability endpoint
(`/services/haproxy/frontend/acls`).

Identical shape/risk analysis to `HAProxyBackendAcl` -- see that
model's docstring. `value`'s residual `custom`-expression risk is
documented, not excluded (`POST_V1_1_HAPROXY_READ_QUALIFICATION.md`
Section 12). `not` is a Python reserved word; modeled as `not_field`
here (upstream key is still `not` on the wire).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyFrontendAcl(BaseModel):
    id: int
    parent_id: int
    name: str | None
    expression: str | None
    value: str | None
    casesensitive: bool | None
    not_field: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyFrontendAcl":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            name=data.get("name"),
            expression=data.get("expression"),
            value=data.get("value"),
            casesensitive=data.get("casesensitive"),
            not_field=data.get("not"),
        )
