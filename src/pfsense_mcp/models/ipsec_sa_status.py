"""Model for the IPsecSaStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `IPsecSAStatus` component (already-captured evidence). Every
field is schema-declared `nullable: true`; modeled as fully optional to
match. `local_host`/`remote_host`/`local_id`/`remote_id` are
address/identity-bearing and redacted by default, matching this
project's established convention.

`child_sas` is schema-confirmed (`$ref`) to embed full
`IPsecChildSAStatus` objects, not opaque data -- it is therefore
constructed through `IPsecChildSaStatus.from_api()` for every item,
never passed through as a raw dict, so that model's own redaction gate
stays in effect for the nested case too. This is a security
requirement of this specific field, not a general pattern choice: a
raw-dict passthrough here would be safe today (no secret material on
`IPsecChildSAStatus`), but the same pattern is unsafe on
`WireGuardTunnelStatus.peers` (see that model), so both are handled
identically and correctly rather than inconsistently.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .ipsec_child_sa_status import IPsecChildSaStatus

_IPSEC_SA_STATUS_IDENTIFYING_FIELDS = ("local_host", "local_id", "remote_host", "remote_id")


class IPsecSaStatus(BaseModel):
    con_id: str | None
    dh_group: str | None
    encr_alg: str | None
    encr_keysize: int | None
    established: int | None
    initiator_spi: str | None
    integ_alg: str | None
    local_port: str | None
    nat_any: bool | None
    nat_remote: bool | None
    prf_alg: str | None
    rekey_time: int | None
    remote_port: str | None
    responder_spi: str | None
    state: str | None
    uniqueid: int | None
    version: int | None
    child_sas: list[IPsecChildSaStatus] | None
    local_host: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    local_id: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    remote_host: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    remote_id: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "IPsecSaStatus":
        identifying = {field: data[field] for field in _IPSEC_SA_STATUS_IDENTIFYING_FIELDS}
        raw_child_sas = data["child_sas"]
        child_sas = (
            [
                IPsecChildSaStatus.from_api(item, include_identifying_metadata=include_identifying_metadata)
                for item in raw_child_sas
            ]
            if raw_child_sas is not None
            else None
        )
        return cls(
            con_id=data["con_id"],
            dh_group=data["dh_group"],
            encr_alg=data["encr_alg"],
            encr_keysize=data["encr_keysize"],
            established=data["established"],
            initiator_spi=data["initiator_spi"],
            integ_alg=data["integ_alg"],
            local_port=data["local_port"],
            nat_any=data["nat_any"],
            nat_remote=data["nat_remote"],
            prf_alg=data["prf_alg"],
            rekey_time=data["rekey_time"],
            remote_port=data["remote_port"],
            responder_spi=data["responder_spi"],
            state=data["state"],
            uniqueid=data["uniqueid"],
            version=data["version"],
            child_sas=child_sas,
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
