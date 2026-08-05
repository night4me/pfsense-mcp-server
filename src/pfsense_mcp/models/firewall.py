"""Models for the pfSense firewall rules, states, states-size, and
apply-status endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_RULE_IDENTIFYING_FIELDS = ("source", "destination", "created_by", "updated_by")
_STATE_IDENTIFYING_FIELDS = ("source", "destination")


class FirewallRule(BaseModel):
    id: int
    type: str | None
    interface: list[str]
    ipprotocol: str | None
    protocol: str | None
    icmptype: list[str] | None
    source_port: str | None
    destination_port: str | None
    descr: str | None
    disabled: bool
    log: bool
    dscp: str | None
    tag: str | None
    statetype: str | None
    tcp_flags_any: bool
    tcp_flags_out_of: list[str] | None
    tcp_flags_set: list[str] | None
    gateway: str | None
    sched: str | None
    dnpipe: str | None
    pdnpipe: str | None
    defaultqueue: str | None
    ackqueue: str | None
    floating: bool
    quick: bool | None
    direction: str | None
    tracker: int
    associated_rule_id: str | None
    created_time: int
    updated_time: int
    source: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    destination: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    created_by: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    updated_by: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "FirewallRule":
        identifying = {field: data[field] for field in _RULE_IDENTIFYING_FIELDS}
        return cls(
            id=data["id"],
            type=data["type"],
            interface=data["interface"],
            ipprotocol=data["ipprotocol"],
            protocol=data["protocol"],
            icmptype=data["icmptype"],
            source_port=data["source_port"],
            destination_port=data["destination_port"],
            descr=data["descr"],
            disabled=data["disabled"],
            log=data["log"],
            dscp=data["dscp"],
            tag=data["tag"],
            statetype=data["statetype"],
            tcp_flags_any=data["tcp_flags_any"],
            tcp_flags_out_of=data["tcp_flags_out_of"],
            tcp_flags_set=data["tcp_flags_set"],
            gateway=data["gateway"],
            sched=data["sched"],
            dnpipe=data["dnpipe"],
            pdnpipe=data["pdnpipe"],
            defaultqueue=data["defaultqueue"],
            ackqueue=data["ackqueue"],
            floating=data["floating"],
            quick=data["quick"],
            direction=data["direction"],
            tracker=data["tracker"],
            associated_rule_id=data["associated_rule_id"],
            created_time=data["created_time"],
            updated_time=data["updated_time"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )


class FirewallState(BaseModel):
    id: int
    interface: str | None
    protocol: str | None
    direction: str | None
    state: str | None
    age: str | None
    expires_in: str | None
    packets_total: int
    packets_in: int
    packets_out: int
    bytes_total: int
    bytes_in: int
    bytes_out: int
    source: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    destination: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "FirewallState":
        identifying = {field: data[field] for field in _STATE_IDENTIFYING_FIELDS}
        return cls(
            id=data["id"],
            interface=data["interface"],
            protocol=data["protocol"],
            direction=data["direction"],
            state=data["state"],
            age=data["age"],
            expires_in=data["expires_in"],
            packets_total=data["packets_total"],
            packets_in=data["packets_in"],
            packets_out=data["packets_out"],
            bytes_total=data["bytes_total"],
            bytes_in=data["bytes_in"],
            bytes_out=data["bytes_out"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )


class FirewallStatesSize(BaseModel):
    maximumstates: int | None
    defaultmaximumstates: int
    currentstates: int

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "FirewallStatesSize":
        return cls(
            maximumstates=data["maximumstates"],
            defaultmaximumstates=data["defaultmaximumstates"],
            currentstates=data["currentstates"],
        )


class FirewallApplyStatus(BaseModel):
    applied: bool
    pending_subsystems: list[str]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "FirewallApplyStatus":
        return cls(
            applied=data["applied"],
            pending_subsystems=data["pending_subsystems"],
        )
