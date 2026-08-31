"""Model for the IPsecPhase1 capability endpoint (`GET
/vpn/ipsec/phase1s`) -- the phase 1 (IKE) tunnel configuration list.

Field types/nullability derived from a freshly-fetched (not cached)
live `pfrest.org` OpenAPI document during
POST_V1_1_FINAL_READ_CLOSURE_AND_FULL_HARDENING Phase 3 qualification.
`mode`/`myid_data`/`peerid_data`/`certref`/`caref` are each
schema-documented as conditionally available ("only available when"),
each declaring a schema default of `null`; read via `.get()` with no
explicit fallback (falls back to Python's implicit `None`), matching
the `OpenVpnServer` established convention for such fields.
`pre_shared_key` is likewise conditional but is excluded entirely (see
below), so its conditionality is moot.

`pre_shared_key` is **never modeled**, not even as a
conditionally-redacted field -- the PSK value, the same secret class
as `WireGuardTunnel.privatekey`/`WireGuardPeer.presharedkey`.
`certref`/`caref` are certificate *references* (not certificate
material itself), matching this project's established treatment of
reference IDs as non-secret (`OpenVpnServer.caref`/`.certref`).

`encryption` is also excluded, for a different reason: it is
redundant, not sensitive -- this component's own `encryption` array
embeds full `IPsecPhase1Encryption`-shaped objects, and that
sub-resource already has its own dedicated, already-shipped tool
(`pfsense_get_vpn_ipsec_phase1_encryptions`).

`remote_gateway` (the peer's real-world IP/hostname), `myid_data`, and
`peerid_data` (the local/remote tunnel identity values -- themselves
possibly an IP/FQDN/email/key-id depending on the paired `myid_type`/
`peerid_type`) are identity/address-bearing and redacted by default
via `include_identifying_metadata`, matching
`RoutingStaticRoute.gateway`'s established convention.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_IPSEC_PHASE1_IDENTIFYING_FIELDS = ("remote_gateway", "myid_data", "peerid_data")


def _redacted() -> Any:
    return Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )


class IPsecPhase1(BaseModel):
    ikeid: int | None
    descr: str
    disabled: bool
    iketype: str
    mode: str | None
    protocol: str
    interface: str
    authentication_method: str
    myid_type: str
    peerid_type: str
    certref: str | None
    caref: str | None
    rekey_time: int
    reauth_time: int
    rand_time: int
    lifetime: int
    startaction: str
    closeaction: str
    nat_traversal: str
    gw_duplicates: bool
    mobike: bool
    splitconn: bool
    prfselect_enable: bool
    ikeport: str
    nattport: str
    dpd_delay: int | None
    dpd_maxfail: int | None
    remote_gateway: str | None = _redacted()
    myid_data: str | None = _redacted()
    peerid_data: str | None = _redacted()

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "IPsecPhase1":
        identifying = {field: data.get(field) for field in _IPSEC_PHASE1_IDENTIFYING_FIELDS}
        return cls(
            ikeid=data["ikeid"],
            descr=data["descr"],
            disabled=data["disabled"],
            iketype=data["iketype"],
            mode=data.get("mode"),
            protocol=data["protocol"],
            interface=data["interface"],
            authentication_method=data["authentication_method"],
            myid_type=data["myid_type"],
            peerid_type=data["peerid_type"],
            certref=data.get("certref"),
            caref=data.get("caref"),
            rekey_time=data["rekey_time"],
            reauth_time=data["reauth_time"],
            rand_time=data["rand_time"],
            lifetime=data["lifetime"],
            startaction=data["startaction"],
            closeaction=data["closeaction"],
            nat_traversal=data["nat_traversal"],
            gw_duplicates=data["gw_duplicates"],
            mobike=data["mobike"],
            splitconn=data["splitconn"],
            prfselect_enable=data["prfselect_enable"],
            ikeport=data["ikeport"],
            nattport=data["nattport"],
            dpd_delay=data["dpd_delay"],
            dpd_maxfail=data["dpd_maxfail"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
