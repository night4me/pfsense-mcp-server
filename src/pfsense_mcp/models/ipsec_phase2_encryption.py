"""Model for the IPsecPhase2Encryption capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`IPsecPhase2Encryption` component (already-captured evidence, not a
new live call; no secret material present) -- pure algorithm/cipher
capability reference data, no redaction needed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class IPsecPhase2Encryption(BaseModel):
    name: str
    keylen: int

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "IPsecPhase2Encryption":
        return cls(
            name=data["name"],
            keylen=data["keylen"],
        )
