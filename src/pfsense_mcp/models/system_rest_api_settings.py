"""Model for the SystemRestApiSettings capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture.
`ha_sync_password` is declared in the OpenAPI schema but pfSense's own
GET response never includes it (a write-only secret field, same
pattern as certificate private-key material) — it is deliberately
excluded from this model entirely rather than modeled as an
always-missing required field. `ha_sync_username` is identifying: it
is an HA-peer sync auth credential, not a general account username,
so it is redacted to null by default. Everything else here is
ordinary REST API service configuration and stays visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_SYSTEM_REST_API_SETTINGS_IDENTIFYING_FIELDS = ("ha_sync_username",)


class SystemRestApiSettings(BaseModel):
    allow_development_packages: bool
    allow_pre_releases: bool
    allowed_interfaces: list[str]
    auth_methods: list[str]
    enabled: bool
    expose_sensitive_fields: bool
    ha_sync: bool
    ha_sync_hosts: list[str]
    ha_sync_validate_certs: bool
    hateoas: bool
    jwt_exp: int
    keep_backup: bool
    log_level: str
    log_successful_auth: bool
    login_protection: bool
    override_sensitive_fields: list[str]
    read_only: bool
    represent_interfaces_as: str
    ha_sync_username: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "SystemRestApiSettings":
        identifying = {field: data[field] for field in _SYSTEM_REST_API_SETTINGS_IDENTIFYING_FIELDS}
        return cls(
            allow_development_packages=data["allow_development_packages"],
            allow_pre_releases=data["allow_pre_releases"],
            allowed_interfaces=data["allowed_interfaces"],
            auth_methods=data["auth_methods"],
            enabled=data["enabled"],
            expose_sensitive_fields=data["expose_sensitive_fields"],
            ha_sync=data["ha_sync"],
            ha_sync_hosts=data["ha_sync_hosts"],
            ha_sync_validate_certs=data["ha_sync_validate_certs"],
            hateoas=data["hateoas"],
            jwt_exp=data["jwt_exp"],
            keep_backup=data["keep_backup"],
            log_level=data["log_level"],
            log_successful_auth=data["log_successful_auth"],
            login_protection=data["login_protection"],
            override_sensitive_fields=data["override_sensitive_fields"],
            read_only=data["read_only"],
            represent_interfaces_as=data["represent_interfaces_as"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
