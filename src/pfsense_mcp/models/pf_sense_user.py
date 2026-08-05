"""Model for the PfSenseUser capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture.
Administrative-usefulness policy: only genuinely secret values are
redacted. name/descr/uid/priv/cert are ordinary object metadata
(username, description, reference ID, role, certificate reference)
and are always visible. authorizedkeys (raw SSH key material) and
ipsecpsk (pre-shared key) are the only identifying_fields, redacted
by default, opt-in only.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_PF_SENSE_USER_IDENTIFYING_FIELDS = (
    "authorizedkeys",
    "ipsecpsk",
)


class PfSenseUser(BaseModel):
    cert: list[str] | None
    descr: str
    disabled: bool
    expires: str
    id: int
    name: str
    priv: list[str] | None
    scope: str | None
    uid: int | None
    authorizedkeys: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    ipsecpsk: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "PfSenseUser":
        identifying = {field: data[field] for field in _PF_SENSE_USER_IDENTIFYING_FIELDS}
        return cls(
            cert=data["cert"],
            descr=data["descr"],
            disabled=data["disabled"],
            expires=data["expires"],
            id=data["id"],
            name=data["name"],
            priv=data["priv"],
            scope=data["scope"],
            uid=data["uid"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
