"""Model for the BindSettings capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BindSettings(BaseModel):
    bind_custom_options: str | None
    bind_dnssec_validation: str
    bind_forwarder: bool
    bind_forwarder_ips: list[str] | None
    bind_global_settings: str | None
    bind_hide_version: bool
    bind_ip_version: str | None
    bind_logging: bool
    bind_notify: bool
    bind_ram_limit: str
    controlport: str
    enable_bind: bool
    listenon: list[str]
    listenport: str
    log_only: bool
    log_options: list[str]
    log_severity: str
    rate_enabled: bool
    rate_limit: int | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "BindSettings":
        return cls(
            bind_custom_options=data["bind_custom_options"],
            bind_dnssec_validation=data["bind_dnssec_validation"],
            bind_forwarder=data["bind_forwarder"],
            bind_forwarder_ips=data["bind_forwarder_ips"],
            bind_global_settings=data["bind_global_settings"],
            bind_hide_version=data["bind_hide_version"],
            bind_ip_version=data["bind_ip_version"],
            bind_logging=data["bind_logging"],
            bind_notify=data["bind_notify"],
            bind_ram_limit=data["bind_ram_limit"],
            controlport=data["controlport"],
            enable_bind=data["enable_bind"],
            listenon=data["listenon"],
            listenport=data["listenport"],
            log_only=data["log_only"],
            log_options=data["log_options"],
            log_severity=data["log_severity"],
            rate_enabled=data["rate_enabled"],
            rate_limit=data["rate_limit"],
        )
