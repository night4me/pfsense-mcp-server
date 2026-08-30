"""Model for the BindSettings capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture; identifying_fields
is exactly what the capability manifest declared, never inferred.

`bind_custom_options` and `bind_global_settings` are deliberately
excluded from this model entirely (matching this project's established
`SystemRestApiSettings.ha_sync_password` precedent for structural field
exclusion, and the same rule applied to `BindView.bind_custom_options`
and `BindZone.custom`/`.customzonerecords`). Per direct inspection of
`RESTAPI\\Models\\BINDSettings.inc` (github.com/pfrest/pfSense-pkg-RESTAPI,
`POST_V1_1_BIND_SETTINGS_READ_HARDENING.md`), both fields are typed
`Base64Field` -- an unbounded, unvalidated free-text field with no
`choices`/`validators` constraint -- with help text stating they are
"[c]ustom BIND options to include in the configuration file" /
"[g]lobal BIND settings to include in the configuration file"
respectively: arbitrary operator-supplied text spliced verbatim into
the generated `named.conf`, and thus a potential exfiltration channel
for anything an operator may have pasted there, including secrets,
despite not being formally typed as a credential field. `from_api()`
never reads either key from the raw response. Every other field in
`BINDSettings.inc` is a `BooleanField`/`IntegerField`/`PortField`/
`InterfaceField`, or a `StringField` constrained by an enum `choices`
list or a validator (e.g. `bind_forwarder_ips`'s `IPAddressValidator`)
-- none carries the same unbounded free-text raw-config-injection risk,
so no other field is excluded.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BindSettings(BaseModel):
    bind_dnssec_validation: str
    bind_forwarder: bool
    bind_forwarder_ips: list[str] | None
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
            bind_dnssec_validation=data["bind_dnssec_validation"],
            bind_forwarder=data["bind_forwarder"],
            bind_forwarder_ips=data["bind_forwarder_ips"],
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
