"""Model for the WireGuardSettings capability endpoint.

Field types/nullability derived from the pfrest.org v2.10.2 OpenAPI
schema (`WireGuardSettings`), fetched 2026-08-30 and cross-checked
against the `PFREST_SCHEMA_DIFF_ADDENDUM_2026-08-28.md` LAB<->upstream
identity proof. `hide_secrets`/`hide_peers` are UI display-preference
booleans (whether the pfSense WebGUI hides secrets/peers by default),
not secret values themselves -- this endpoint never returns any
private/pre-shared key material.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class WireGuardSettings(BaseModel):
    enable: bool
    keep_conf: bool
    resolve_interval_track: bool
    resolve_interval: int | None
    interface_group: str
    hide_secrets: bool
    hide_peers: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "WireGuardSettings":
        return cls(
            enable=data["enable"],
            keep_conf=data["keep_conf"],
            resolve_interval_track=data["resolve_interval_track"],
            resolve_interval=data.get("resolve_interval"),
            interface_group=data["interface_group"],
            hide_secrets=data["hide_secrets"],
            hide_peers=data["hide_peers"],
        )
