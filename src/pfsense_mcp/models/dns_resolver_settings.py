"""Model for the DnsResolverSettings capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.

`sslcertref`/`tlsport` are widened to also accept `None` (2026-08-21,
LAB CE 2.8.1 -> 2.9.0 platform-upgrade regression check): the pinned
schema still declares these `nullable: false` and the original 2.8.1
LAB capture returned a populated/empty string for both, but a live read
on the upgraded LAB (pfSense CE 2.9.0-RELEASE, FreeBSD 16.0-CURRENT,
reinstalled pfSense-pkg-RESTAPI v2.10) genuinely returns `null` for
both when DNS-over-TLS/SSL is not configured. Live server behavior is
trusted over the schema's stale claim, matching this project's own
established precedent (`SystemRestApiVersion.install_version`).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DnsResolverSettings(BaseModel):
    active_interface: list[str]
    custom_options: str
    dnssec: bool
    enable: bool
    enablessl: bool
    forwarding: bool
    outgoing_interface: list[str]
    port: str
    python: bool
    python_order: str | None
    python_script: str | None
    regdhcp: bool
    regdhcpstatic: bool
    regovpnclients: bool
    sslcertref: str | None
    strictout: bool
    system_domain_local_zone_type: str
    tlsport: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DnsResolverSettings":
        return cls(
            active_interface=data["active_interface"],
            custom_options=data["custom_options"],
            dnssec=data["dnssec"],
            enable=data["enable"],
            enablessl=data["enablessl"],
            forwarding=data["forwarding"],
            outgoing_interface=data["outgoing_interface"],
            port=data["port"],
            python=data["python"],
            python_order=data["python_order"],
            python_script=data["python_script"],
            regdhcp=data["regdhcp"],
            regdhcpstatic=data["regdhcpstatic"],
            regovpnclients=data["regovpnclients"],
            sslcertref=data["sslcertref"],
            strictout=data["strictout"],
            system_domain_local_zone_type=data["system_domain_local_zone_type"],
            tlsport=data["tlsport"],
        )
