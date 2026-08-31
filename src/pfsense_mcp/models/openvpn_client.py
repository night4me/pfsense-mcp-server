"""Model for the OpenVPNClient capability endpoint (`GET
/vpn/openvpn/clients`) -- the client *configuration* list, distinct
from the already-shipped `status_openvpn_clients` (live runtime
connection state).

Field types/nullability derived from a freshly-fetched (not cached)
live `pfrest.org` OpenAPI document during
POST_V1_1_FINAL_READ_CLOSURE_AND_FULL_HARDENING Phase 3 qualification,
cross-checked directly against `OpenVpnServer`'s twin fields wherever
this component shares a name with it (both are generated from the same
underlying pfSense OpenVPN PHP model family).

Excluded entirely (never modeled, not even conditionally-redacted):
- `auth_pass` / `proxy_passwd` -- literal authentication passwords.
- `tls` -- literal TLS-auth/crypt HMAC key material (same class as
  `WireGuardTunnel.privatekey`; this is also the corrected treatment
  applied retroactively to the sibling `OpenVpnServer.tls` field in
  this same hardening phase -- see that model's docstring).
- `custom_options` -- explicitly free-text ("Additional options to add
  to the OpenVPN client configuration"), a raw-config-injection field
  analogous to HAProxy's already-excluded `advanced`/`customaction`
  fields; its contents are attacker-shaped OpenVPN directives, not
  structured settings.

`caref`/`certref` are certificate *references* (not certificate
material itself), matching this project's established treatment of
reference IDs as non-secret. `tls_type`/`tlsauth_keydir` are enum/
direction-flag values, not key material (`OpenVpnServer` precedent).
`auth_user`/`proxy_user` are plain usernames, not secrets -- usernames
are already exposed elsewhere in this project's public surface (e.g.
`pfsense_get_users`).

`server_addr`/`proxy_addr` (scalar) and `remote_network`/
`remote_networkv6` (list) are address-bearing and redacted by default
via `include_identifying_metadata`, matching
`OpenVpnServer.remote_network`'s established convention exactly.
`tunnel_network`/`tunnel_networkv6` are likewise redacted, matching
`OpenVpnServer.tunnel_network` precisely.

`interface`/`proxy_user`/`tls_type`/`tlsauth_keydir`/`topology`/
`keepalive_interval`/`keepalive_timeout`/`ping_seconds`/`ping_action`/
`ping_action_seconds` are each schema-documented as conditionally
available ("only available when"); each is read via `.get()` with the
schema's own declared default where one exists (mirroring
`OpenVpnServer`'s identical fields byte-for-byte), else `None`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_OPENVPN_CLIENT_IDENTIFYING_SCALAR_FIELDS = (
    "server_addr",
    "proxy_addr",
    "tunnel_network",
    "tunnel_networkv6",
)
_OPENVPN_CLIENT_IDENTIFYING_LIST_FIELDS = (
    "remote_network",
    "remote_networkv6",
)


def _redacted_scalar() -> Any:
    return Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )


def _redacted_list() -> Any:
    return Field(
        default_factory=list,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )


class OpenVPNClient(BaseModel):
    vpnid: int | None
    vpnif: str | None
    description: str
    disable: bool
    mode: str
    dev_mode: str
    protocol: str
    server_port: str
    local_port: str | None
    proxy_port: str | None
    proxy_authtype: str
    auth_user: str | None
    auth_retry_none: bool
    caref: str
    certref: str | None
    data_ciphers: list[str]
    data_ciphers_fallback: str
    digest: str
    remote_cert_tls: bool
    use_shaper: int | None
    allow_compression: str
    passtos: bool
    route_no_pull: bool
    route_no_exec: bool
    dns_add: bool
    inactive_seconds: int
    ping_method: str
    udp_fast_io: bool
    exit_notify: str
    sndrcvbuf: int | None
    create_gw: str
    verbosity_level: int

    interface: str | None
    proxy_user: str | None
    tls_type: str | None
    tlsauth_keydir: str
    topology: str
    keepalive_interval: int
    keepalive_timeout: int
    ping_seconds: int
    ping_action: str
    ping_action_seconds: int

    server_addr: str | None = _redacted_scalar()
    proxy_addr: str | None = _redacted_scalar()
    tunnel_network: str | None = _redacted_scalar()
    tunnel_networkv6: str | None = _redacted_scalar()
    remote_network: list[str] = _redacted_list()
    remote_networkv6: list[str] = _redacted_list()

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "OpenVPNClient":
        identifying_scalars: dict[str, Any] = (
            {field: data.get(field) for field in _OPENVPN_CLIENT_IDENTIFYING_SCALAR_FIELDS}
            if include_identifying_metadata
            else dict.fromkeys(_OPENVPN_CLIENT_IDENTIFYING_SCALAR_FIELDS)
        )
        identifying_lists: dict[str, Any] = (
            {field: data.get(field, []) for field in _OPENVPN_CLIENT_IDENTIFYING_LIST_FIELDS}
            if include_identifying_metadata
            else {field: [] for field in _OPENVPN_CLIENT_IDENTIFYING_LIST_FIELDS}
        )
        return cls(
            vpnid=data["vpnid"],
            vpnif=data["vpnif"],
            description=data["description"],
            disable=data["disable"],
            mode=data["mode"],
            dev_mode=data["dev_mode"],
            protocol=data["protocol"],
            server_port=data["server_port"],
            local_port=data["local_port"],
            proxy_port=data["proxy_port"],
            proxy_authtype=data["proxy_authtype"],
            auth_user=data["auth_user"],
            auth_retry_none=data["auth_retry_none"],
            caref=data["caref"],
            certref=data["certref"],
            data_ciphers=data["data_ciphers"],
            data_ciphers_fallback=data["data_ciphers_fallback"],
            digest=data["digest"],
            remote_cert_tls=data["remote_cert_tls"],
            use_shaper=data["use_shaper"],
            allow_compression=data["allow_compression"],
            passtos=data["passtos"],
            route_no_pull=data["route_no_pull"],
            route_no_exec=data["route_no_exec"],
            dns_add=data["dns_add"],
            inactive_seconds=data["inactive_seconds"],
            ping_method=data["ping_method"],
            udp_fast_io=data["udp_fast_io"],
            exit_notify=data["exit_notify"],
            sndrcvbuf=data["sndrcvbuf"],
            create_gw=data["create_gw"],
            verbosity_level=data["verbosity_level"],
            interface=data.get("interface"),
            proxy_user=data.get("proxy_user"),
            tls_type=data.get("tls_type"),
            tlsauth_keydir=data.get("tlsauth_keydir", "default"),
            topology=data.get("topology", "subnet"),
            keepalive_interval=data.get("keepalive_interval", 10),
            keepalive_timeout=data.get("keepalive_timeout", 60),
            ping_seconds=data.get("ping_seconds", 10),
            ping_action=data.get("ping_action", "ping_restart"),
            ping_action_seconds=data.get("ping_action_seconds", 60),
            **identifying_scalars,
            **identifying_lists,
        )
