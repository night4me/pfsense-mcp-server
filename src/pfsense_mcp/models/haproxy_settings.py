"""Model for the HAProxySettings capability endpoint (`/services/haproxy/settings`).

Three upstream fields deliberately excluded from this model entirely
(matching this project's established `SystemRestApiSettings.
ha_sync_password`/`BindZone`/`HAProxyBackend` precedent for structural
field exclusion):

- `advanced` -- "custom configuration to pass", a `Base64Field`
  raw-config-injection channel.
- `dns_resolvers`, `email_mailers` -- nested sub-resource arrays
  (`NestedModelField`); excluded here for design uniformity (both are
  individually `SAFE_READ` on their own via the dedicated
  `pfsense_get_haproxy_dns_resolvers`/`_email_mailers` tools, so this
  exclusion is a simplicity/duplication choice, not a security
  necessity).

No credential fields exist anywhere on this model -- confirmed via
exhaustive field enumeration against the live OpenAPI document,
2026-08-30/31. Live-verified response (HAProxy absent from LAB,
2026-08-30 ceremony) matched this field set exactly, including one
schema-drift note: `advanced` is schema-declared `nullable: false` but
was observed `null` live -- consistent with (not proof of) its
exclusion here, and irrelevant since the field is excluded regardless.
Every remaining field is modeled as optional per that same live
evidence and this project's established conservative-conditional-field
handling.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxySettings(BaseModel):
    enable: bool | None
    maxconn: int | None
    nbthread: int | None
    terminate_on_reload: bool | None
    hard_stop_after: str | None
    carpdev: str | None
    localstatsport: str | None
    localstats_refreshtime: int | None
    localstats_sticktable_refreshtime: int | None
    remotesyslog: str | None
    logfacility: str | None
    loglevel: str | None
    log_send_hostname: str | None
    resolver_retries: int | None
    resolver_timeoutretry: str | None
    resolver_holdvalid: str | None
    email_level: str | None
    email_myhostname: str | None
    email_from: str | None
    email_to: str | None
    sslcompatibilitymode: str | None
    ssldefaultdhparam: int | None
    enablesync: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxySettings":
        return cls(
            enable=data.get("enable"),
            maxconn=data.get("maxconn"),
            nbthread=data.get("nbthread"),
            terminate_on_reload=data.get("terminate_on_reload"),
            hard_stop_after=data.get("hard_stop_after"),
            carpdev=data.get("carpdev"),
            localstatsport=data.get("localstatsport"),
            localstats_refreshtime=data.get("localstats_refreshtime"),
            localstats_sticktable_refreshtime=data.get("localstats_sticktable_refreshtime"),
            remotesyslog=data.get("remotesyslog"),
            logfacility=data.get("logfacility"),
            loglevel=data.get("loglevel"),
            log_send_hostname=data.get("log_send_hostname"),
            resolver_retries=data.get("resolver_retries"),
            resolver_timeoutretry=data.get("resolver_timeoutretry"),
            resolver_holdvalid=data.get("resolver_holdvalid"),
            email_level=data.get("email_level"),
            email_myhostname=data.get("email_myhostname"),
            email_from=data.get("email_from"),
            email_to=data.get("email_to"),
            sslcompatibilitymode=data.get("sslcompatibilitymode"),
            ssldefaultdhparam=data.get("ssldefaultdhparam"),
            enablesync=data.get("enablesync"),
        )
