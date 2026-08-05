"""Model for the SystemCertificate capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture. No
identifying_fields: crt/csr are public PKI artifacts (never the
private key — pfSense's own GET response never includes "prv"), and
descr/refid/caref/type/validity fields are ordinary object metadata,
all visible per administrative-usefulness policy. The committed test
fixture synthesizes descr/refid/caref (this install's real
certificate names/reference IDs) via a stricter capture policy —
runtime behavior is unaffected.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SystemCertificate(BaseModel):
    caref: str | None
    crt: str
    csr: str | None
    descr: str
    id: int
    refid: str | None
    type: str
    valid_days_left: int | None
    valid_from: str | None
    valid_until: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemCertificate":
        return cls(
            caref=data["caref"],
            crt=data["crt"],
            csr=data["csr"],
            descr=data["descr"],
            id=data["id"],
            refid=data["refid"],
            type=data["type"],
            valid_days_left=data["valid_days_left"],
            valid_from=data["valid_from"],
            valid_until=data["valid_until"],
        )
