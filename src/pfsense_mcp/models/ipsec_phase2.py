"""Model for the IPsecPhase2 capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `IPsecPhase2` component (already-captured evidence, not a
new live call). Re-confirmed the PSK lives only on `IPsecPhase1`,
already REJECTed separately -- no secret material is present on Phase
2 itself. `localid_address`/`natlocalid_address`/`remoteid_address`
(local/NAT/remote endpoint addresses) and `pinghost` (a monitoring
target address) are address-bearing and are redacted by default,
matching `RoutingStaticRoute.gateway`'s established convention;
widened to also accept `None` (this project's standing preference for
address-shaped config fields that can plausibly be unset, matching the
`DhcpServer`/`SystemRestApiVersion.install_version` precedent).
`encryption_algorithm_option` is schema-documented as only available
when `protocol` is `'esp'` and is treated as genuinely possibly-absent
via `.get()`. It is schema-confirmed to embed full
`IPsecPhase2Encryption` objects and is constructed through that
model's own `from_api()` for every item.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .ipsec_phase2_encryption import IPsecPhase2Encryption

_IPSEC_PHASE2_IDENTIFYING_FIELDS = (
    "localid_address",
    "natlocalid_address",
    "remoteid_address",
    "pinghost",
)


class IPsecPhase2(BaseModel):
    uniqid: str | None
    reqid: int | None
    ikeid: int
    descr: str
    disabled: bool
    mode: str
    localid_type: str
    localid_address: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    localid_netbits: int
    natlocalid_type: str | None
    natlocalid_address: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    natlocalid_netbits: int
    remoteid_type: str
    remoteid_address: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    remoteid_netbits: int
    protocol: str
    encryption_algorithm_option: list[IPsecPhase2Encryption]
    hash_algorithm_option: list[str]
    pfsgroup: int
    rekey_time: int
    rand_time: int
    lifetime: int
    pinghost: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    keepalive: bool

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "IPsecPhase2":
        identifying = {field: data[field] for field in _IPSEC_PHASE2_IDENTIFYING_FIELDS}
        return cls(
            uniqid=data["uniqid"],
            reqid=data["reqid"],
            ikeid=data["ikeid"],
            descr=data["descr"],
            disabled=data["disabled"],
            mode=data["mode"],
            localid_type=data["localid_type"],
            localid_netbits=data["localid_netbits"],
            natlocalid_type=data["natlocalid_type"],
            natlocalid_netbits=data["natlocalid_netbits"],
            remoteid_type=data["remoteid_type"],
            remoteid_netbits=data["remoteid_netbits"],
            protocol=data["protocol"],
            encryption_algorithm_option=[
                IPsecPhase2Encryption.from_api(item) for item in data.get("encryption_algorithm_option", [])
            ],
            hash_algorithm_option=data["hash_algorithm_option"],
            pfsgroup=data["pfsgroup"],
            rekey_time=data["rekey_time"],
            rand_time=data["rand_time"],
            lifetime=data["lifetime"],
            keepalive=data["keepalive"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
