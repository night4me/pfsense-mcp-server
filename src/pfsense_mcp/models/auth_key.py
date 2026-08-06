"""Model for the AuthKey capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_AUTH_KEY_IDENTIFYING_FIELDS = ("key",)


class AuthKey(BaseModel):
    descr: str
    hash_algo: str
    id: int
    length_bytes: int
    username: str | None
    key: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "AuthKey":
        identifying = {field: data[field] for field in _AUTH_KEY_IDENTIFYING_FIELDS}
        return cls(
            descr=data["descr"],
            hash_algo=data["hash_algo"],
            id=data["id"],
            length_bytes=data["length_bytes"],
            username=data["username"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
