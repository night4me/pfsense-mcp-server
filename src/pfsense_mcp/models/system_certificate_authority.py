"""Model for the SystemCertificateAuthority capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `CertificateAuthority` component (already-captured evidence),
then re-checked directly during this READ Expansion phase: `prv` (the
CA's private key) is confirmed present in the schema and is **never
modeled at all** -- not even as a conditionally-redacted field --
mirroring the already-shipped `SystemCertificate` model's own
established treatment of the exact same distinction (it models `crt`
but deliberately excludes `prv`). `crt` is public PKI material (the CA
certificate itself) and stays visible, matching that precedent.
descr/refid/caref/trust/randomserial/serial are ordinary object
metadata, not identifying or secret.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SystemCertificateAuthority(BaseModel):
    caref: str | None
    crt: str
    descr: str
    randomserial: bool
    refid: str | None
    serial: int
    trust: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemCertificateAuthority":
        return cls(
            caref=data["caref"],
            crt=data["crt"],
            descr=data["descr"],
            randomserial=data["randomserial"],
            refid=data["refid"],
            serial=data["serial"],
            trust=data["trust"],
        )
