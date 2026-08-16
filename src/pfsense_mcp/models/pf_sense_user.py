"""Model for the PfSenseUser capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture.
Administrative-usefulness policy: genuine secret values are excluded
from the public model entirely. name/descr/uid/priv/cert are ordinary object metadata
(username, description, reference ID, role, certificate reference)
and are always visible. authorizedkeys is public cryptographic material
that remains redacted by default and opt-in only. ipsecpsk is a secret
and is ignored unconditionally.

`expires` is `str | None` (not `str`): a 2026-08-16 live-LAB read against a
real pfSense v2 appliance observed `expires: null` for the built-in `admin`
account (no expiration configured), which the original non-nullable typing
rejected with a schema-validation error -- the approved fixture had only ever
exercised the empty-string ("no expiration") case, never the null one. Both
represent "no expiration" on real hardware.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_PF_SENSE_USER_IDENTIFYING_FIELDS = ("authorizedkeys",)


class PfSenseUser(BaseModel):
    cert: list[str] | None
    descr: str
    disabled: bool
    expires: str | None
    id: int
    name: str
    priv: list[str] | None
    scope: str | None
    uid: int | None
    authorizedkeys: str | None = Field(
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
