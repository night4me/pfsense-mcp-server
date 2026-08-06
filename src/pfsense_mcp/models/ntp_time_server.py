"""Model for the NtpTimeServer capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class NtpTimeServer(BaseModel):
    id: int
    noselect: bool
    prefer: bool
    timeserver: str
    type: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "NtpTimeServer":
        return cls(
            id=data["id"],
            noselect=data["noselect"],
            prefer=data["prefer"],
            timeserver=data["timeserver"],
            type=data["type"],
        )
