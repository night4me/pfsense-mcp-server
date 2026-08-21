"""Model for the WebGUISettings capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`WebGUISettings` component (already-captured evidence, not a new live
call). Re-verified secret-free during this batch's own re-check
(`protocol`/`port`/`sslcertref` only -- `sslcertref` is a certificate
reference, not key material). No field is redacted: this is
listener/service posture, not per-device identifying data.

`sslcertref` is widened to also accept `None`: unlike `protocol`/`port`
(both schema-declared with a default, always populated), `sslcertref`
has no declared default and is plausibly unset when the web GUI uses
the appliance's built-in default certificate rather than an
explicitly assigned one -- matching this project's standing preference
to widen a reference-style field ahead of a LAB failure rather than
after one (`SystemRestApiVersion.install_version` precedent).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class WebGUISettings(BaseModel):
    protocol: str
    port: str
    sslcertref: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "WebGUISettings":
        return cls(
            protocol=data["protocol"],
            port=data["port"],
            sslcertref=data["sslcertref"],
        )
