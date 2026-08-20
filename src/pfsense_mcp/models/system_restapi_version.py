"""Model for the SystemRestApiVersion capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `RESTAPIVersion` component (already-captured evidence) and
cross-checked against a real LAB response fetched during this READ
Expansion phase's compatibility preflight (2026-08-20,
`https://pfsense-test.lab.invalid`). That live response omitted the
`install_version` key entirely (not merely null) -- confirming the
schema's own lack of any `required` list is accurate here, not just an
OpenAPI-authoring omission. `install_version` is therefore modeled as
genuinely optional (`.get`, not `[...]`); every other field was present
in the same live response and stays required. No secret material and
no address-bearing/identifying fields -- no redaction gate is required
here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SystemRestApiVersion(BaseModel):
    available_versions: list[str]
    current_version: str | None
    install_version: str | None = Field(
        default=None,
        description="Absent entirely in at least one observed live response; not required by the schema.",
    )
    latest_version: str | None
    latest_version_release_date: str | None
    update_available: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemRestApiVersion":
        return cls(
            available_versions=data["available_versions"],
            current_version=data["current_version"],
            install_version=data.get("install_version"),
            latest_version=data["latest_version"],
            latest_version_release_date=data["latest_version_release_date"],
            update_available=data["update_available"],
        )
