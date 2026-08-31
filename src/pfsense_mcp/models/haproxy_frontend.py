"""Model for the HAProxyFrontend capability endpoint (`/services/haproxy/frontends`).

Field types/nullability derived from the live pfrest.org OpenAPI
document (fetched 2026-08-30/31). Seven of the upstream fields are
deliberately excluded from this model entirely (matching this
project's established `SystemRestApiSettings.ha_sync_password`/
`BindZone`/`HAProxyBackend` precedent for structural field exclusion):

- `advanced_bind` -- "custom value to pass behind each bind option",
  a `StringField` raw-config-injection channel.
- `advanced` -- "custom configuration to pass to this frontend", a
  `Base64Field` raw-config-injection channel.
- `a_extaddr`, `ha_acls`, `a_actionitems`, `a_errorfiles`,
  `ha_certificates` -- nested sub-resource arrays (`NestedModelField`);
  embedding them would re-expose risks already found in the standalone
  nested models (in particular `a_actionitems`' arbitrary
  HTTP-header-manipulation channel, rejected outright as
  `REJECT_HEADER_SECRET_CHANNEL`) via a back door. Use the dedicated
  `pfsense_get_haproxy_frontend_acls`/`_addresses`/`_certificates`/
  `_error_files` tools instead. **`ha_certificates` was not
  individually named in `POST_V1_1_HAPROXY_READ_QUALIFICATION.md`'s
  original 4-field exclusion list for this model (it listed
  `a_extaddr`/`ha_acls`/`a_actionitems`/`a_errorfiles` only) -- found
  and corrected during this implementation pass's live schema
  re-check, per the mission's own Phase 2 instruction to fix rather
  than weaken when implementation-time review finds a gap.**

`ssloffloadcert` is retained: a nullable string `ForeignModelField`
reference (a certificate refid, like `HAProxyFrontendCertificate.
ssl_certificate`), not private key material. `id` is the plain
internal array index pfREST assigns every list item, not
identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyFrontend(BaseModel):
    id: int
    name: str | None
    descr: str | None
    status: str | None
    max_connections: int | None
    type: str | None
    backend_serverpool: str | None
    socket_stats: bool | None
    dontlognull: bool | None
    dontlog_normal: bool | None
    log_separate_errors: bool | None
    log_detailed: bool | None
    client_timeout: int | None
    forwardfor: bool | None
    httpclose: str | None
    ssloffloadcert: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyFrontend":
        return cls(
            id=data["id"],
            name=data.get("name"),
            descr=data.get("descr"),
            status=data.get("status"),
            max_connections=data.get("max_connections"),
            type=data.get("type"),
            backend_serverpool=data.get("backend_serverpool"),
            socket_stats=data.get("socket_stats"),
            dontlognull=data.get("dontlognull"),
            dontlog_normal=data.get("dontlog_normal"),
            log_separate_errors=data.get("log_separate_errors"),
            log_detailed=data.get("log_detailed"),
            client_timeout=data.get("client_timeout"),
            forwardfor=data.get("forwardfor"),
            httpclose=data.get("httpclose"),
            ssloffloadcert=data.get("ssloffloadcert"),
        )
