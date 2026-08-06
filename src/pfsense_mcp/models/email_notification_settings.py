"""Model for the EmailNotificationSettings capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_EMAIL_NOTIFICATION_SETTINGS_IDENTIFYING_FIELDS = (
    "fromaddress",
    "ipaddress",
    "notifyemailaddress",
    "password",
    "username",
)


class EmailNotificationSettings(BaseModel):
    authentication_mechanism: str
    disable: bool
    port: str
    ssl: bool
    sslvalidate: bool
    timeout: int
    fromaddress: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    ipaddress: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    notifyemailaddress: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    password: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    username: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(
        cls, data: dict[str, Any], *, include_identifying_metadata: bool = False
    ) -> "EmailNotificationSettings":
        identifying = {field: data[field] for field in _EMAIL_NOTIFICATION_SETTINGS_IDENTIFYING_FIELDS}
        return cls(
            authentication_mechanism=data["authentication_mechanism"],
            disable=data["disable"],
            port=data["port"],
            ssl=data["ssl"],
            sslvalidate=data["sslvalidate"],
            timeout=data["timeout"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
