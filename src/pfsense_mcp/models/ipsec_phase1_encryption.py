"""Model for the IPsecPhase1Encryption capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`IPsecPhase1Encryption` component (already-captured evidence, not a
new live call; no secret material present -- the PSK lives only on
IPsecPhase1 itself, already REJECTed separately, re-confirmed absent
here) -- pure algorithm/cipher capability reference data, no
redaction needed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class IPsecPhase1Encryption(BaseModel):
    encryption_algorithm_name: str
    encryption_algorithm_keylen: int
    hash_algorithm: str
    dhgroup: int
    prf_algorithm: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "IPsecPhase1Encryption":
        return cls(
            encryption_algorithm_name=data["encryption_algorithm_name"],
            encryption_algorithm_keylen=data["encryption_algorithm_keylen"],
            hash_algorithm=data["hash_algorithm"],
            dhgroup=data["dhgroup"],
            prf_algorithm=data["prf_algorithm"],
        )
