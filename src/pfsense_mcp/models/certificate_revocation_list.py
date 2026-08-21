"""Model for the CertificateRevocationList capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `CertificateRevocationList` component (already-captured
evidence, not a new live call). No `prv`-equivalent field exists on
this component itself -- `text`/`cert` are the CRL body/entries, a
document inherently public by design (a CRL exists specifically to be
published so relying parties can check it). `cert` is schema-confirmed
to embed full `CertificateRevocationListRevokedCertificate` objects
and is constructed through that model's own `from_api()` for every
item, so that model's own `prv` exclusion holds for the nested case
too.

`text` and `cert` are each schema-documented as "only available when"
a specific `method` value is set (`existing`/`internal` respectively)
-- treated as genuinely possibly-absent keys (`.get()` with an empty
default), the same `InterfaceLAGG`-style precedent already established
for a field that can be legitimately missing from a live response.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .certificate_revocation_list_revoked_certificate import CertificateRevocationListRevokedCertificate


class CertificateRevocationList(BaseModel):
    refid: str | None
    caref: str
    descr: str
    method: str
    lifetime: int
    serial: int
    text: str
    cert: list[CertificateRevocationListRevokedCertificate]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "CertificateRevocationList":
        return cls(
            refid=data["refid"],
            caref=data["caref"],
            descr=data["descr"],
            method=data["method"],
            lifetime=data["lifetime"],
            serial=data["serial"],
            text=data.get("text", ""),
            cert=[CertificateRevocationListRevokedCertificate.from_api(item) for item in data.get("cert", [])],
        )
