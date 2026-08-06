"""Model for the FreeRadiusEap capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class FreeRadiusEap(BaseModel):
    cache_enable: bool
    cache_lifetime: int
    cache_max_entries: int
    cisco_accounting_username_bug: bool
    default_eap_type: str
    disable_weak_eap_types: bool
    ignore_unknown_eap_types: bool
    max_sessions: int
    ocsp_enable: bool
    ocsp_override_cert_url: bool
    ocsp_url: str
    peap_copy_request_to_tunnel: bool
    peap_default_eap_type: str
    peap_soh_enable: str
    peap_use_tunneled_reply: bool
    ssl_ca_cert: str | None
    ssl_ca_crl: str | None
    ssl_server_cert: str | None
    timer_expire: int
    tls_ca_subject: str | None
    tls_check_cert_cn: bool
    tls_check_cert_issuer: bool
    tls_fragment_size: int
    tls_include_length: bool
    tls_min_version: str
    ttls_copy_request_to_tunnel: bool
    ttls_default_eap_type: str
    ttls_include_length: bool
    ttls_use_tunneled_reply: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "FreeRadiusEap":
        return cls(
            cache_enable=data["cache_enable"],
            cache_lifetime=data["cache_lifetime"],
            cache_max_entries=data["cache_max_entries"],
            cisco_accounting_username_bug=data["cisco_accounting_username_bug"],
            default_eap_type=data["default_eap_type"],
            disable_weak_eap_types=data["disable_weak_eap_types"],
            ignore_unknown_eap_types=data["ignore_unknown_eap_types"],
            max_sessions=data["max_sessions"],
            ocsp_enable=data["ocsp_enable"],
            ocsp_override_cert_url=data["ocsp_override_cert_url"],
            ocsp_url=data["ocsp_url"],
            peap_copy_request_to_tunnel=data["peap_copy_request_to_tunnel"],
            peap_default_eap_type=data["peap_default_eap_type"],
            peap_soh_enable=data["peap_soh_enable"],
            peap_use_tunneled_reply=data["peap_use_tunneled_reply"],
            ssl_ca_cert=data["ssl_ca_cert"],
            ssl_ca_crl=data["ssl_ca_crl"],
            ssl_server_cert=data["ssl_server_cert"],
            timer_expire=data["timer_expire"],
            tls_ca_subject=data["tls_ca_subject"],
            tls_check_cert_cn=data["tls_check_cert_cn"],
            tls_check_cert_issuer=data["tls_check_cert_issuer"],
            tls_fragment_size=data["tls_fragment_size"],
            tls_include_length=data["tls_include_length"],
            tls_min_version=data["tls_min_version"],
            ttls_copy_request_to_tunnel=data["ttls_copy_request_to_tunnel"],
            ttls_default_eap_type=data["ttls_default_eap_type"],
            ttls_include_length=data["ttls_include_length"],
            ttls_use_tunneled_reply=data["ttls_use_tunneled_reply"],
        )
