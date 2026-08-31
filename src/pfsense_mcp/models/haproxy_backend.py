"""Model for the HAProxyBackend capability endpoint (`/services/haproxy/backends`).

Field types/nullability derived from the live pfrest.org OpenAPI
document (fetched 2026-08-30 during the LAB read-only qualification
ceremony, `POST_V1_1_HAPROXY_READ_QUALIFICATION.md`). Eight of the
64 upstream fields are deliberately excluded from this model entirely
(matching this project's established `SystemRestApiSettings.ha_sync_password`
/`BindZone` precedent for structural field exclusion):

- `stats_password` -- plaintext HAProxy stats-page password. Marked
  `sensitive: true` in the upstream PHP source but NOT `write_only:
  true` (the flag that actually suppresses a field from API
  representation output) -- a confirmed plaintext-credential-in-GET
  finding if left unexcluded.
- `haproxy_cookie_dynamic_cookie_key` -- "the dynamic cookie secret
  key", no `sensitive`/`write_only` flag at all in upstream source.
- `advanced` -- "per server pass thru to apply to each server line",
  a `StringField` raw-config-injection channel.
- `advanced_backend` -- "backend pass thru to apply to the backend
  section", a `Base64Field` raw-config-injection channel.
- `servers`, `acls`, `actions`, `errorfiles` -- nested sub-resource
  arrays (`NestedModelField`); embedding them would re-expose risks
  already found in the standalone nested models (in particular
  `actions`' arbitrary HTTP-header-manipulation channel, rejected
  outright as `REJECT_HEADER_SECRET_CHANNEL`) via a back door. Use the
  dedicated `pfsense_get_haproxy_backend_acls`/`_servers`/
  `_errorfiles` tools instead; the backend/frontend action endpoints
  are not exposed by any tool.

`id` is the plain internal array index pfREST assigns every list
item, not identifying/sensitive data. Every remaining field is
modeled as optional: the upstream schema declares no field
`required`, and live evidence already showed at least one
schema-declared-non-nullable field (`HAProxySettings.advanced`)
actually return `null` in practice -- matching this project's
established conservative-conditional-field handling elsewhere.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyBackend(BaseModel):
    id: int
    name: str | None
    balance: str | None
    balance_urilen: int | None
    balance_uridepth: int | None
    balance_uriwhole: bool | None
    connection_timeout: int | None
    server_timeout: int | None
    retries: int | None
    check_type: str | None
    checkinter: int | None
    log_health_checks: bool | None
    httpcheck_method: str | None
    monitor_uri: str | None
    monitor_httpversion: str | None
    monitor_username: str | None
    monitor_domain: str | None
    agent_checks: bool | None
    agent_port: str | None
    agent_inter: int | None
    persist_cookie_enabled: bool | None
    persist_cookie_name: str | None
    persist_cookie_mode: str | None
    persist_cookie_cachable: bool | None
    persist_cookie_postonly: bool | None
    persist_cookie_httponly: bool | None
    persist_cookie_secure: bool | None
    haproxy_cookie_maxidle: int | None
    haproxy_cookie_maxlife: int | None
    haproxy_cookie_domains: list[str] | None
    persist_sticky_type: str | None
    persist_stick_expire: str | None
    persist_stick_tablesize: str | None
    persist_stick_cookiename: str | None
    persist_stick_length: int | None
    email_level: str | None
    email_to: str | None
    stats_enabled: bool | None
    stats_uri: str | None
    stats_scope: list[str] | None
    stats_realm: str | None
    stats_username: str | None
    stats_admin: str | None
    stats_node: str | None
    stats_desc: str | None
    stats_refresh: int | None
    strict_transport_security: int | None
    cookie_attribute_secure: bool | None
    transparent_clientip: bool | None
    transparent_interface: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyBackend":
        return cls(
            id=data["id"],
            name=data.get("name"),
            balance=data.get("balance"),
            balance_urilen=data.get("balance_urilen"),
            balance_uridepth=data.get("balance_uridepth"),
            balance_uriwhole=data.get("balance_uriwhole"),
            connection_timeout=data.get("connection_timeout"),
            server_timeout=data.get("server_timeout"),
            retries=data.get("retries"),
            check_type=data.get("check_type"),
            checkinter=data.get("checkinter"),
            log_health_checks=data.get("log_health_checks"),
            httpcheck_method=data.get("httpcheck_method"),
            monitor_uri=data.get("monitor_uri"),
            monitor_httpversion=data.get("monitor_httpversion"),
            monitor_username=data.get("monitor_username"),
            monitor_domain=data.get("monitor_domain"),
            agent_checks=data.get("agent_checks"),
            agent_port=data.get("agent_port"),
            agent_inter=data.get("agent_inter"),
            persist_cookie_enabled=data.get("persist_cookie_enabled"),
            persist_cookie_name=data.get("persist_cookie_name"),
            persist_cookie_mode=data.get("persist_cookie_mode"),
            persist_cookie_cachable=data.get("persist_cookie_cachable"),
            persist_cookie_postonly=data.get("persist_cookie_postonly"),
            persist_cookie_httponly=data.get("persist_cookie_httponly"),
            persist_cookie_secure=data.get("persist_cookie_secure"),
            haproxy_cookie_maxidle=data.get("haproxy_cookie_maxidle"),
            haproxy_cookie_maxlife=data.get("haproxy_cookie_maxlife"),
            haproxy_cookie_domains=data.get("haproxy_cookie_domains"),
            persist_sticky_type=data.get("persist_sticky_type"),
            persist_stick_expire=data.get("persist_stick_expire"),
            persist_stick_tablesize=data.get("persist_stick_tablesize"),
            persist_stick_cookiename=data.get("persist_stick_cookiename"),
            persist_stick_length=data.get("persist_stick_length"),
            email_level=data.get("email_level"),
            email_to=data.get("email_to"),
            stats_enabled=data.get("stats_enabled"),
            stats_uri=data.get("stats_uri"),
            stats_scope=data.get("stats_scope"),
            stats_realm=data.get("stats_realm"),
            stats_username=data.get("stats_username"),
            stats_admin=data.get("stats_admin"),
            stats_node=data.get("stats_node"),
            stats_desc=data.get("stats_desc"),
            stats_refresh=data.get("stats_refresh"),
            strict_transport_security=data.get("strict_transport_security"),
            cookie_attribute_secure=data.get("cookie_attribute_secure"),
            transparent_clientip=data.get("transparent_clientip"),
            transparent_interface=data.get("transparent_interface"),
        )
