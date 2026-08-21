"""Model for the OpenVpnServer capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OpenVPNServer` component (already-captured evidence, not a
new live call; no secret material present -- no field is marked
`writeOnly`, unlike the CRL revoked-certificate case). `caref`/
`certref` are CA/certificate *references* (not the certificate
material itself), matching this project's established treatment of
reference IDs as non-secret. `tlsauth_keydir` is re-confirmed (a
fourth time across sessions) to be a direction-flag enum
(0/1/bidirectional), not key material.

`local_network`/`local_networkv6`/`remote_network`/`remote_networkv6`/
`tunnel_network`/`tunnel_networkv6`/`dns_server1-4`/`ntp_server1-2`/
`wins_server1-2`/`serverbridge_dhcp_start`/`serverbridge_dhcp_end`
(literal network/address data) are redacted by default, matching
`RoutingStaticRoute.gateway`'s established convention. The four
network-list fields redact to an empty list (never `None`, since
their unredacted shape is always a list); the scalar address fields
redact to `None`.

Of this component's 73 fields, 37 are schema-documented as "only
available when" a specific `mode`/`use_tls`/`gwredir`/`ping_action`
condition is met and are treated as genuinely possibly-absent via
`.get()`, falling back to the schema's own declared default where one
exists and `None`/`[]` otherwise -- matching the `InterfaceLAGG`/
`TrafficShaperQueue` precedent. The largest single model in this
project's P1 backlog by field count; this is transcription complexity,
not security complexity (already fully re-verified secret-free).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_OPENVPN_SERVER_IDENTIFYING_LIST_FIELDS = (
    "local_network",
    "local_networkv6",
    "remote_network",
    "remote_networkv6",
)
_OPENVPN_SERVER_IDENTIFYING_SCALAR_FIELDS = (
    "tunnel_network",
    "tunnel_networkv6",
    "dns_server1",
    "dns_server2",
    "dns_server3",
    "dns_server4",
    "ntp_server1",
    "ntp_server2",
    "wins_server1",
    "wins_server2",
    "serverbridge_dhcp_start",
    "serverbridge_dhcp_end",
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


class OpenVpnServer(BaseModel):
    vpnid: int | None
    vpnif: str | None
    description: str
    disable: bool
    mode: str
    dev_mode: str
    protocol: str
    local_port: str
    use_tls: bool
    caref: str
    certref: str
    cert_depth: int | None
    dh_length: str
    ecdh_curve: str
    data_ciphers: list[str]
    data_ciphers_fallback: str
    digest: str
    remote_cert_tls: bool
    tunnel_network: str | None = _redacted_scalar()
    tunnel_networkv6: str | None = _redacted_scalar()
    gwredir: bool
    gwredir6: bool
    remote_network: list[str] = _redacted_list()
    remote_networkv6: list[str] = _redacted_list()
    maxclients: int | None
    allow_compression: str
    passtos: bool
    client2client: bool
    duplicate_cn: bool
    dynamic_ip: bool
    inactive_seconds: int
    ping_method: str
    custom_options: list[str]
    sndrcvbuf: int | None
    create_gw: str
    verbosity_level: int

    authmode: list[str]
    interface: str | None
    tls: str | None
    tls_type: str | None
    tlsauth_keydir: str
    strictusercn: bool | None
    serverbridge_dhcp: bool | None
    serverbridge_interface: str | None
    serverbridge_routegateway: bool | None
    serverbridge_dhcp_start: str | None = _redacted_scalar()
    serverbridge_dhcp_end: str | None = _redacted_scalar()
    local_network: list[str] = _redacted_list()
    local_networkv6: list[str] = _redacted_list()
    connlimit: int | None
    topology: str
    keepalive_interval: int
    keepalive_timeout: int
    ping_seconds: int
    ping_push: bool | None
    ping_action: str
    ping_action_seconds: int
    ping_action_push: bool | None
    dns_domain: str | None
    dns_server1: str | None = _redacted_scalar()
    dns_server2: str | None = _redacted_scalar()
    dns_server3: str | None = _redacted_scalar()
    dns_server4: str | None = _redacted_scalar()
    push_blockoutsidedns: bool | None
    push_register_dns: bool | None
    ntp_server1: str | None = _redacted_scalar()
    ntp_server2: str | None = _redacted_scalar()
    netbios_enable: bool | None
    netbios_ntype: int | None
    netbios_scope: str | None
    wins_server1: str | None = _redacted_scalar()
    wins_server2: str | None = _redacted_scalar()
    username_as_common_name: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "OpenVpnServer":
        identifying_scalars: dict[str, Any] = (
            {field: data.get(field) for field in _OPENVPN_SERVER_IDENTIFYING_SCALAR_FIELDS}
            if include_identifying_metadata
            else dict.fromkeys(_OPENVPN_SERVER_IDENTIFYING_SCALAR_FIELDS)
        )
        identifying_lists: dict[str, Any] = (
            {field: data.get(field, []) for field in _OPENVPN_SERVER_IDENTIFYING_LIST_FIELDS}
            if include_identifying_metadata
            else {field: [] for field in _OPENVPN_SERVER_IDENTIFYING_LIST_FIELDS}
        )
        return cls(
            vpnid=data["vpnid"],
            vpnif=data["vpnif"],
            description=data["description"],
            disable=data["disable"],
            mode=data["mode"],
            dev_mode=data["dev_mode"],
            protocol=data["protocol"],
            local_port=data["local_port"],
            use_tls=data["use_tls"],
            caref=data["caref"],
            certref=data["certref"],
            cert_depth=data["cert_depth"],
            dh_length=data["dh_length"],
            ecdh_curve=data["ecdh_curve"],
            data_ciphers=data["data_ciphers"],
            data_ciphers_fallback=data["data_ciphers_fallback"],
            digest=data["digest"],
            remote_cert_tls=data["remote_cert_tls"],
            gwredir=data["gwredir"],
            gwredir6=data["gwredir6"],
            maxclients=data["maxclients"],
            allow_compression=data["allow_compression"],
            passtos=data["passtos"],
            client2client=data["client2client"],
            duplicate_cn=data["duplicate_cn"],
            dynamic_ip=data["dynamic_ip"],
            inactive_seconds=data["inactive_seconds"],
            ping_method=data["ping_method"],
            custom_options=data["custom_options"],
            sndrcvbuf=data["sndrcvbuf"],
            create_gw=data["create_gw"],
            verbosity_level=data["verbosity_level"],
            authmode=data.get("authmode", ["Local Database"]),
            interface=data.get("interface"),
            tls=data.get("tls"),
            tls_type=data.get("tls_type"),
            tlsauth_keydir=data.get("tlsauth_keydir", "default"),
            strictusercn=data.get("strictusercn"),
            serverbridge_dhcp=data.get("serverbridge_dhcp"),
            serverbridge_interface=data.get("serverbridge_interface"),
            serverbridge_routegateway=data.get("serverbridge_routegateway"),
            connlimit=data.get("connlimit"),
            topology=data.get("topology", "subnet"),
            keepalive_interval=data.get("keepalive_interval", 10),
            keepalive_timeout=data.get("keepalive_timeout", 60),
            ping_seconds=data.get("ping_seconds", 10),
            ping_push=data.get("ping_push"),
            ping_action=data.get("ping_action", "ping_restart"),
            ping_action_seconds=data.get("ping_action_seconds", 60),
            ping_action_push=data.get("ping_action_push"),
            dns_domain=data.get("dns_domain"),
            push_blockoutsidedns=data.get("push_blockoutsidedns"),
            push_register_dns=data.get("push_register_dns"),
            netbios_enable=data.get("netbios_enable"),
            netbios_ntype=data.get("netbios_ntype"),
            netbios_scope=data.get("netbios_scope"),
            username_as_common_name=data.get("username_as_common_name"),
            **identifying_scalars,
            **identifying_lists,
        )
