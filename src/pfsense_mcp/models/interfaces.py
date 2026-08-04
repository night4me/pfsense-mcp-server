"""Models for the pfSense interface-status endpoint."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_IDENTIFYING_FIELDS = (
    "macaddr",
    "ipaddr",
    "subnet",
    "linklocal",
    "ipaddrv6",
    "subnetv6",
    "gateway",
    "gatewayv6",
)


class InterfaceStatus(BaseModel):
    id: int
    name: str | None
    descr: str | None
    hwif: str | None
    mtu: str | None
    enable: bool
    status: str | None
    dhcplink: str | None
    media: str | None
    inerrs: int
    outerrs: int
    collisions: int
    inbytes: int
    inbytespass: int
    outbytes: int
    outbytespass: int
    inpkts: int
    inpktspass: int
    outpkts: int
    outpktspass: int
    macaddr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    ipaddr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    subnet: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    linklocal: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    ipaddrv6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    subnetv6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    gateway: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    gatewayv6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "InterfaceStatus":
        identifying = {field: data[field] for field in _IDENTIFYING_FIELDS}
        return cls(
            id=data["id"],
            name=data["name"],
            descr=data["descr"],
            hwif=data["hwif"],
            mtu=data["mtu"],
            enable=data["enable"],
            status=data["status"],
            dhcplink=data["dhcplink"],
            media=data["media"],
            inerrs=data["inerrs"],
            outerrs=data["outerrs"],
            collisions=data["collisions"],
            inbytes=data["inbytes"],
            inbytespass=data["inbytespass"],
            outbytes=data["outbytes"],
            outbytespass=data["outbytespass"],
            inpkts=data["inpkts"],
            inpktspass=data["inpktspass"],
            outpkts=data["outpkts"],
            outpktspass=data["outpktspass"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
