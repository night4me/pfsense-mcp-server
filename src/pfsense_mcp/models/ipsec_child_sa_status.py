"""Model for the IPsecChildSaStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `IPsecChildSAStatus` component (already-captured evidence).
Every field in this component is schema-declared `nullable: true`
(unlike several config-object components elsewhere in this project
where the schema's `nullable: false` claim did not match live CE 2.9.0
behavior -- 2026-08-21 finding); modeled as fully optional to match the
schema here, since there is no live-data reason yet to distrust it for
this component. `local_ts`/`remote_ts` (traffic selector subnets) are
address-bearing and redacted by default, matching this project's
established convention. No secret material is present in this
component.

This model is also embedded, unmodified, as `IPsecSAStatus.child_sas`'s
nested item type -- constructing it via `from_api()` there (rather than
passing through a raw dict) is a security requirement, not a style
choice: it keeps this same redaction gate in effect for the nested
case.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_IPSEC_CHILD_SA_STATUS_IDENTIFYING_FIELDS = ("local_ts", "remote_ts")


class IPsecChildSaStatus(BaseModel):
    bytes_in: int | None
    bytes_out: int | None
    dh_group: str | None
    encap: bool | None
    encr_alg: str | None
    encr_keysize: int | None
    install_time: int | None
    integ_alg: str | None
    life_time: int | None
    mode: str | None
    name: str | None
    packets_in: int | None
    packets_out: int | None
    protocol: str | None
    rekey_time: int | None
    reqid: int | None
    spi_in: str | None
    spi_out: str | None
    state: str | None
    uniqueid: int | None
    use_in: int | None
    use_out: int | None
    local_ts: list[Any] | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    remote_ts: list[Any] | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "IPsecChildSaStatus":
        identifying = {field: data[field] for field in _IPSEC_CHILD_SA_STATUS_IDENTIFYING_FIELDS}
        return cls(
            bytes_in=data["bytes_in"],
            bytes_out=data["bytes_out"],
            dh_group=data["dh_group"],
            encap=data["encap"],
            encr_alg=data["encr_alg"],
            encr_keysize=data["encr_keysize"],
            install_time=data["install_time"],
            integ_alg=data["integ_alg"],
            life_time=data["life_time"],
            mode=data["mode"],
            name=data["name"],
            packets_in=data["packets_in"],
            packets_out=data["packets_out"],
            protocol=data["protocol"],
            rekey_time=data["rekey_time"],
            reqid=data["reqid"],
            spi_in=data["spi_in"],
            spi_out=data["spi_out"],
            state=data["state"],
            uniqueid=data["uniqueid"],
            use_in=data["use_in"],
            use_out=data["use_out"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
