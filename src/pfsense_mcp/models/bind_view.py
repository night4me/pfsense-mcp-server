"""Model for the BINDView capability endpoint.

Field types/nullability derived from the live pfrest.org v2.10.2
OpenAPI document (fetched 2026-08-30,
`POST_V1_1_BIND_READ_QUALIFICATION.md`). `bind_custom_options` is
deliberately excluded from this model entirely (matching this
project's established `SystemRestApiSettings.ha_sync_password`
precedent for structural field exclusion) -- per the qualification
report's source review of the actual pfrest/pfSense-pkg-RESTAPI PHP
implementation, this field is injected verbatim into the generated
BIND configuration and could carry arbitrary operator-pasted text,
including secrets. `id` is the plain internal array index pfREST
assigns every list item, not identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BindView(BaseModel):
    id: int
    name: str
    descr: str
    recursion: bool
    match_clients: list[str]
    allow_recursion: list[str]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "BindView":
        return cls(
            id=data["id"],
            name=data["name"],
            descr=data["descr"],
            recursion=data["recursion"],
            match_clients=data["match_clients"],
            allow_recursion=data["allow_recursion"],
        )
