"""Model for the AvailableInterface capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `AvailableInterface` component (already-captured evidence,
not a new live call; all four fields are schema-declared nullable).
`mac` is identifying device metadata and is redacted by default,
matching `InterfaceStatus.macaddr`'s established convention. `if_`
(the schema's `if`, renamed since `if` is a Python keyword -- matching
`InterfaceVlan.if_`'s established precedent) and `in_use_by` are
interface identifiers, not personal/device-identifying data, and stay
visible; `dmesg` is a hardware boot-message string, not a secret, and
also stays visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_AVAILABLE_INTERFACE_IDENTIFYING_FIELDS = ("mac",)


class AvailableInterface(BaseModel):
    if_: str | None
    mac: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    dmesg: str | None
    in_use_by: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "AvailableInterface":
        identifying = {field: data[field] for field in _AVAILABLE_INTERFACE_IDENTIFYING_FIELDS}
        return cls(
            if_=data["if"],
            dmesg=data["dmesg"],
            in_use_by=data["in_use_by"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
