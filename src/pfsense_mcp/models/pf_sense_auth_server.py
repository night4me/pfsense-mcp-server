"""Model for the PfSenseAuthServer capability endpoint (`GET
/user/auth_servers`).

Field types/nullability derived from a freshly-fetched (not cached) live
`pfrest.org` OpenAPI document during
POST_V1_1_AUTH_SERVER_LIVE_QUALIFICATION Phase 0 qualification, and
independently re-confirmed field-by-field during the immediately-following
POST_V1_1_AUTH_SERVER_BOUNDED_READ_PROMOTION implementation. `refid`/`type`/
`name`/`host` are unconditional; the remaining 25 kept fields are each
schema-documented as conditionally available ("only available when" the
account's `type` is `ldap` or `radius`), so every conditional field is read
via `.get()` -- with the schema's own declared default where one exists
(`ldap_protver`=3, `ldap_timeout`=25, `ldap_caref`='global',
`ldap_attr_user`='cn', `ldap_attr_group`='cn', `ldap_attr_member`='member',
`ldap_attr_groupobj`='posixGroup', `ldap_allow_unauthenticated`=True,
`radius_auth_port`='1812', `radius_acct_port`='1813',
`radius_protocol`='MSCHAPv2'), else `None` -- matching the
`OpenVpnServer`/`OpenVPNClient`/`IPsecPhase1` established convention for
such fields.

`ldap_bindpw` and `radius_secret` are **never modeled**, not even as
conditionally-redacted fields -- literal LDAP bind password / RADIUS shared
secret material, the same secret class as
`WireGuardTunnel.privatekey`/`WireGuardPeer.presharedkey`/
`IPsecPhase1.pre_shared_key`. This is the complete required-exclusion set:
all 31 upstream schema fields were individually re-read against an expanded
keyword sweep (password/secret/key/token/bind/radius/ldap/cert/private/
credential/auth/shared/psk) during both the live qualification ceremony and
this implementation -- no additional secret-shaped field exists.
`ldap_caref` is a certificate-authority *reference* (not certificate
material itself), matching this project's established treatment of
reference IDs as non-secret (`OpenVpnServer.caref`/`.certref`,
`IPsecPhase1.certref`/`.caref`).

`host` (the server's real-world IP/hostname), `ldap_binddn`, `ldap_basedn`,
`ldap_authcn`, and `ldap_pam_groupdn` (LDAP directory-structure strings
that name a specific organizational bind identity/search scope) are
identity/address-bearing and redacted by default via
`include_identifying_metadata`, matching `IPsecPhase1.remote_gateway`/
`.myid_data`/`.peerid_data`'s established convention.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_AUTH_SERVER_IDENTIFYING_FIELDS = (
    "host",
    "ldap_binddn",
    "ldap_basedn",
    "ldap_authcn",
    "ldap_pam_groupdn",
)


def _redacted() -> Any:
    return Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )


class PfSenseAuthServer(BaseModel):
    refid: str | None
    type: str
    name: str
    ldap_port: str | None
    ldap_urltype: str | None
    ldap_protver: int | None
    ldap_timeout: int | None
    ldap_caref: str | None
    ldap_scope: str | None
    ldap_extended_enabled: bool | None
    ldap_extended_query: str | None
    ldap_attr_user: str | None
    ldap_attr_group: str | None
    ldap_attr_member: str | None
    ldap_rfc2307: bool | None
    ldap_rfc2307_userdn: bool | None
    ldap_attr_groupobj: str | None
    ldap_utf8: bool | None
    ldap_nostrip_at: bool | None
    ldap_allow_unauthenticated: bool | None
    radius_auth_port: str | None
    radius_acct_port: str | None
    radius_protocol: str | None
    radius_timeout: int | None
    radius_nasip_attribute: str | None

    host: str | None = _redacted()
    ldap_binddn: str | None = _redacted()
    ldap_basedn: str | None = _redacted()
    ldap_authcn: str | None = _redacted()
    ldap_pam_groupdn: str | None = _redacted()

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "PfSenseAuthServer":
        identifying = {field: data.get(field) for field in _AUTH_SERVER_IDENTIFYING_FIELDS}
        return cls(
            refid=data.get("refid"),
            type=data["type"],
            name=data["name"],
            ldap_port=data.get("ldap_port"),
            ldap_urltype=data.get("ldap_urltype"),
            ldap_protver=data.get("ldap_protver", 3),
            ldap_timeout=data.get("ldap_timeout", 25),
            ldap_caref=data.get("ldap_caref", "global"),
            ldap_scope=data.get("ldap_scope"),
            ldap_extended_enabled=data.get("ldap_extended_enabled"),
            ldap_extended_query=data.get("ldap_extended_query"),
            ldap_attr_user=data.get("ldap_attr_user", "cn"),
            ldap_attr_group=data.get("ldap_attr_group", "cn"),
            ldap_attr_member=data.get("ldap_attr_member", "member"),
            ldap_rfc2307=data.get("ldap_rfc2307"),
            ldap_rfc2307_userdn=data.get("ldap_rfc2307_userdn"),
            ldap_attr_groupobj=data.get("ldap_attr_groupobj", "posixGroup"),
            ldap_utf8=data.get("ldap_utf8"),
            ldap_nostrip_at=data.get("ldap_nostrip_at"),
            ldap_allow_unauthenticated=data.get("ldap_allow_unauthenticated", True),
            radius_auth_port=data.get("radius_auth_port", "1812"),
            radius_acct_port=data.get("radius_acct_port", "1813"),
            radius_protocol=data.get("radius_protocol", "MSCHAPv2"),
            radius_timeout=data.get("radius_timeout"),
            radius_nasip_attribute=data.get("radius_nasip_attribute"),
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
