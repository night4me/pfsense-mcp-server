"""Models for the pfSense gateway config and gateway status endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_GATEWAY_IDENTIFYING_FIELDS = ("gateway", "monitor")
_GATEWAY_STATUS_IDENTIFYING_FIELDS = ("srcip", "monitorip")


class GatewayConfig(BaseModel):
    id: int
    name: str | None
    descr: str | None
    disabled: bool
    ipprotocol: str | None
    interface: str | None
    monitor_disable: bool
    action_disable: bool
    force_down: bool
    dpinger_dont_add_static_route: bool
    gw_down_kill_states: str | None
    nonlocalgateway: bool
    weight: int
    data_payload: int
    latencylow: int
    latencyhigh: int
    losslow: int
    losshigh: int
    interval: int
    loss_interval: int
    time_period: int
    alert_interval: int
    gateway: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    monitor: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "GatewayConfig":
        identifying = {field: data[field] for field in _GATEWAY_IDENTIFYING_FIELDS}
        return cls(
            id=data["id"],
            name=data["name"],
            descr=data["descr"],
            disabled=data["disabled"],
            ipprotocol=data["ipprotocol"],
            interface=data["interface"],
            monitor_disable=data["monitor_disable"],
            action_disable=data["action_disable"],
            force_down=data["force_down"],
            dpinger_dont_add_static_route=data["dpinger_dont_add_static_route"],
            gw_down_kill_states=data["gw_down_kill_states"],
            nonlocalgateway=data["nonlocalgateway"],
            weight=data["weight"],
            data_payload=data["data_payload"],
            latencylow=data["latencylow"],
            latencyhigh=data["latencyhigh"],
            losslow=data["losslow"],
            losshigh=data["losshigh"],
            interval=data["interval"],
            loss_interval=data["loss_interval"],
            time_period=data["time_period"],
            alert_interval=data["alert_interval"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )


class GatewayStatus(BaseModel):
    id: int
    name: str | None
    delay: float
    stddev: float
    loss: float
    status: str | None
    substatus: str | None
    srcip: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    monitorip: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "GatewayStatus":
        identifying = {field: data[field] for field in _GATEWAY_STATUS_IDENTIFYING_FIELDS}
        return cls(
            id=data["id"],
            name=data["name"],
            delay=data["delay"],
            stddev=data["stddev"],
            loss=data["loss"],
            status=data["status"],
            substatus=data["substatus"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
