"""Model for the AuthKey capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class AuthKey(BaseModel):
    descr: str
    hash_algo: str
    id: int
    length_bytes: int
    username: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "AuthKey":
        return cls(
            descr=data["descr"],
            hash_algo=data["hash_algo"],
            id=data["id"],
            length_bytes=data["length_bytes"],
            username=data["username"],
        )
