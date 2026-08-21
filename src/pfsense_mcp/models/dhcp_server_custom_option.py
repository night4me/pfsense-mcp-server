"""Model for the DHCPServerCustomOption capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `DHCPServerCustomOption` component (already-captured
evidence, not a new live call; no secret material present). No field
is redacted: `value` is admin-authored DHCP option data (config, not a
credential), and `number`/`type` are option metadata -- matching this
resource's schema-declared `Parent model` `DHCPServer`'s own
no-redaction convention.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DHCPServerCustomOption(BaseModel):
    number: int
    type: str
    value: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DHCPServerCustomOption":
        return cls(
            number=data["number"],
            type=data["type"],
            value=data["value"],
        )
