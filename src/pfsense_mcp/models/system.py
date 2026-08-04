"""Models for the pfSense system-status endpoint."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SystemStatus(BaseModel):
    platform: str
    uptime: str
    cpu_model: str
    cpu_count: int
    cpu_usage: float
    mem_usage: int
    swap_usage: int
    disk_usage: int
    temp_c: float | None = None
    temp_f: float | None = None
    netgate_id: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "SystemStatus":
        return cls(
            platform=data["platform"],
            uptime=data["uptime"],
            cpu_model=data["cpu_model"],
            cpu_count=data["cpu_count"],
            cpu_usage=data["cpu_usage"],
            mem_usage=data["mem_usage"],
            swap_usage=data["swap_usage"],
            disk_usage=data["disk_usage"],
            temp_c=data.get("temp_c"),
            temp_f=data.get("temp_f"),
            netgate_id=data.get("netgate_id") if include_identifying_metadata else None,
        )
