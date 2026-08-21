"""Model for the CertificateRevocationListRevokedCertificate nested component.

Field types were derived from the pinned v2.10 OpenAPI schema's
`CertificateRevocationListRevokedCertificate` component
(already-captured evidence, not a new live call). Of the eight
schema-declared fields, five (`crt`, `prv`, `caref`, `descr`, `type`)
are marked `writeOnly: true` -- request-body-construction fields only,
never present in a real GET response -- and are excluded from this
model entirely. `prv` is confirmed to be the X509 **private key**
string for the revoked certificate: never modeled at all, matching the
`CertificateAuthority.prv`/`SystemCertificate.prv` precedent exactly,
proven by construction rather than trusting the schema's `writeOnly`
promise alone. Only `certref`/`serial`/`reason`/`revoke_time` (the
non-`writeOnly` fields, matching the component's own GET-response
`required` set) are modeled.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class CertificateRevocationListRevokedCertificate(BaseModel):
    certref: str
    serial: str | None
    reason: int
    revoke_time: int

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "CertificateRevocationListRevokedCertificate":
        return cls(
            certref=data["certref"],
            serial=data["serial"],
            reason=data["reason"],
            revoke_time=data["revoke_time"],
        )
