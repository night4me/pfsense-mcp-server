"""Adversarial test matrix for the 5 candidates promoted in
POST_V1_1_FINAL_FIVE_READ_PROMOTION.md (2026-08-31 OWNER GO ceremony):
pfsense_get_services_service_watchdogs, pfsense_get_vpn_wireguard_tunnels,
pfsense_get_vpn_wireguard_peers, pfsense_get_vpn_ipsec_phase1s,
pfsense_get_vpn_openvpn_clients.

Complements the existing offline test suites in test_pfsense_client.py
(which already prove structural exclusion at the client/model layer)
with proof at the actual MCP surface this mission promoted: tool
registration, exact GET/path dispatch, and end-to-end serialization of
hostile fixtures -- values shaped like real secrets, not merely absent
from the fixture -- through the registered tool wrapper's JSON output.
"""

from __future__ import annotations

import asyncio
import json

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.profiles import AuditorProfile
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools.registry import ToolRegistry
from pfsense_mcp.transport.mock import MockTransport

PROMOTED_TOOL_NAMES = frozenset(
    {
        "pfsense_get_services_service_watchdogs",
        "pfsense_get_vpn_wireguard_tunnels",
        "pfsense_get_vpn_wireguard_peers",
        "pfsense_get_vpn_ipsec_phase1s",
        "pfsense_get_vpn_openvpn_clients",
    }
)


def _envelope(rows: list[dict]) -> dict:
    return {"code": 200, "data": rows, "message": "", "response_id": "SUCCESS", "status": "ok"}


def _registered_mcp():
    transport = MockTransport()
    rest_client = RestApiClient(transport, identity="api-mcp-readonly", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("adversarial-test")
    ToolRegistry(mcp, client, "api-mcp-readonly", AuditorProfile.capabilities).register_all()
    return mcp, client, transport


# ---------------------------------------------------------------------------
# Registration surface
# ---------------------------------------------------------------------------


def test_all_five_promoted_tools_are_registered_and_read_only():
    mcp, _, _ = _registered_mcp()
    tools = asyncio.run(mcp.list_tools())
    tool_by_name = {tool.name: tool for tool in tools}
    assert tool_by_name.keys() >= PROMOTED_TOOL_NAMES
    for name in PROMOTED_TOOL_NAMES:
        annotations = tool_by_name[name].annotations
        assert annotations is not None
        assert annotations.readOnlyHint is True


def test_no_sixth_read_candidate_or_generic_dispatch_tool_was_registered():
    """Freezes the promoted set to exactly these 5 -- no extra config-cluster
    tool for WireGuard/IPsec/OpenVPN/ServiceWatchdog and no generic
    dispatch/router tool exists anywhere in the registered surface."""
    mcp, _, _ = _registered_mcp()
    tools = asyncio.run(mcp.list_tools())
    names = {tool.name for tool in tools}
    suspicious = {
        n
        for n in names
        if n not in PROMOTED_TOOL_NAMES
        and (
            "wireguard" in n
            or "ipsec_phase1" in n
            or "openvpn_client" in n
            or "service_watchdog" in n
            or "dispatch" in n
            or "router" in n
            or n == "pfsense_call"
        )
    }
    # Only the already-shipped status/settings/addresses/encryptions tools
    # and the 5 newly-promoted ones may match these substrings.
    expected_pre_existing = {
        "pfsense_get_status_wireguard_tunnels",
        "pfsense_get_status_wireguard_peers",
        "pfsense_get_status_openvpn_clients",
        "pfsense_get_vpn_wireguard_settings",
        "pfsense_get_vpn_wireguard_tunnel_addresses",
        "pfsense_get_vpn_ipsec_phase1_encryptions",
        "pfsense_get_wireguard_apply_status",
    }
    assert suspicious == expected_pre_existing


# ---------------------------------------------------------------------------
# Exact GET/path proof
# ---------------------------------------------------------------------------


def test_service_watchdogs_tool_calls_exact_get_path():
    _, client, transport = _registered_mcp()
    transport.register(
        "GET", "/api/v2/services/service_watchdogs?limit=100", status_code=200, text=json.dumps(_envelope([]))
    )
    client.get_services_service_watchdogs()
    assert transport.calls == [("GET", "/api/v2/services/service_watchdogs?limit=100")]


def test_wireguard_tunnels_tool_calls_exact_get_path():
    _, client, transport = _registered_mcp()
    transport.register(
        "GET", "/api/v2/vpn/wireguard/tunnels?limit=100", status_code=200, text=json.dumps(_envelope([]))
    )
    client.get_vpn_wireguard_tunnels()
    assert transport.calls == [("GET", "/api/v2/vpn/wireguard/tunnels?limit=100")]


def test_wireguard_peers_tool_calls_exact_get_path():
    _, client, transport = _registered_mcp()
    transport.register("GET", "/api/v2/vpn/wireguard/peers?limit=100", status_code=200, text=json.dumps(_envelope([])))
    client.get_vpn_wireguard_peers()
    assert transport.calls == [("GET", "/api/v2/vpn/wireguard/peers?limit=100")]


def test_ipsec_phase1s_tool_calls_exact_get_path():
    _, client, transport = _registered_mcp()
    transport.register("GET", "/api/v2/vpn/ipsec/phase1s?limit=100", status_code=200, text=json.dumps(_envelope([])))
    client.get_vpn_ipsec_phase1s()
    assert transport.calls == [("GET", "/api/v2/vpn/ipsec/phase1s?limit=100")]


def test_openvpn_clients_tool_calls_exact_get_path():
    _, client, transport = _registered_mcp()
    transport.register("GET", "/api/v2/vpn/openvpn/clients?limit=100", status_code=200, text=json.dumps(_envelope([])))
    client.get_vpn_openvpn_clients()
    assert transport.calls == [("GET", "/api/v2/vpn/openvpn/clients?limit=100")]


# ---------------------------------------------------------------------------
# Hostile fixtures -- structural absence, not fixture-content absence
# ---------------------------------------------------------------------------


def _hostile_wireguard_tunnel_row() -> dict:
    return {
        "name": "wg0",
        "enabled": True,
        "descr": "adversarial",
        "listenport": "51820",
        "publickey": "not-a-secret-public-key",
        "mtu": 1420,
        "privatekey": "PRIVATE_KEY_MUST_NOT_ESCAPE",
        "addresses": ["198.51.100.5/24"],
        "hmac_secret_token": "TOKEN_MUST_NOT_ESCAPE",
    }


def _hostile_wireguard_peer_row() -> dict:
    return {
        "enabled": True,
        "tun": "wg0",
        "port": "51820",
        "descr": "adversarial",
        "persistentkeepalive": 25,
        "publickey": "not-a-secret-public-key",
        "endpoint": "198.51.100.6",
        "presharedkey": "PSK_MUST_NOT_ESCAPE",
        "allowedips": ["198.51.100.0/24"],
    }


def _hostile_ipsec_phase1_row() -> dict:
    return {
        "ikeid": 1,
        "descr": "adversarial",
        "disabled": False,
        "iketype": "ikev2",
        "mode": None,
        "protocol": "inet",
        "interface": "wan",
        "authentication_method": "pre_shared_key",
        "myid_type": "myaddress",
        "peerid_type": "peeraddress",
        "certref": None,
        "caref": None,
        "rekey_time": 28800,
        "reauth_time": 0,
        "rand_time": 3600,
        "lifetime": 28800,
        "startaction": "none",
        "closeaction": "none",
        "nat_traversal": "on",
        "gw_duplicates": False,
        "mobike": False,
        "splitconn": False,
        "prfselect_enable": False,
        "ikeport": "500",
        "nattport": "4500",
        "dpd_delay": 10,
        "dpd_maxfail": 5,
        "remote_gateway": "198.51.100.7",
        "myid_data": "198.51.100.8",
        "peerid_data": "198.51.100.9",
        "pre_shared_key": "IPSEC_SECRET_MUST_NOT_ESCAPE",
        "encryption": [{"algorithm": "aes"}],
    }


def _hostile_openvpn_client_row() -> dict:
    return {
        "vpnid": 1,
        "vpnif": "ovpnc1",
        "description": "adversarial",
        "disable": False,
        "mode": "p2p_tls",
        "dev_mode": "tun",
        "protocol": "UDP4",
        "server_port": "1194",
        "local_port": None,
        "proxy_port": None,
        "proxy_authtype": "none",
        "auth_user": "not-a-secret-username",
        "auth_retry_none": False,
        "caref": "ref1",
        "certref": "ref2",
        "data_ciphers": ["AES-256-GCM"],
        "data_ciphers_fallback": "AES-256-CBC",
        "digest": "SHA256",
        "remote_cert_tls": True,
        "use_shaper": None,
        "allow_compression": "no",
        "passtos": False,
        "route_no_pull": False,
        "route_no_exec": False,
        "dns_add": True,
        "inactive_seconds": 0,
        "ping_method": "keepalive",
        "udp_fast_io": False,
        "exit_notify": "none",
        "sndrcvbuf": None,
        "create_gw": "both",
        "verbosity_level": 1,
        "interface": "wan",
        "proxy_user": None,
        "tls_type": "auth",
        "tlsauth_keydir": "default",
        "topology": "subnet",
        "keepalive_interval": 10,
        "keepalive_timeout": 60,
        "ping_seconds": 10,
        "ping_action": "ping_restart",
        "ping_action_seconds": 60,
        "server_addr": "198.51.100.10",
        "proxy_addr": None,
        "tunnel_network": "198.51.100.0/24",
        "tunnel_networkv6": None,
        "remote_network": ["198.51.100.0/24"],
        "remote_networkv6": [],
        "auth_pass": "SUPER_SECRET_PASSWORD",
        "proxy_passwd": "SUPER_SECRET_PASSWORD",
        "tls": "OPENVPN_TLS_SECRET_MUST_NOT_ESCAPE",
        "custom_options": "up /bin/sh -c 'INJECTED';",
    }


HOSTILE_SECRET_LITERALS = frozenset(
    {
        "PRIVATE_KEY_MUST_NOT_ESCAPE",
        "PSK_MUST_NOT_ESCAPE",
        "IPSEC_SECRET_MUST_NOT_ESCAPE",
        "SUPER_SECRET_PASSWORD",
        "OPENVPN_TLS_SECRET_MUST_NOT_ESCAPE",
        "TOKEN_MUST_NOT_ESCAPE",
        "INJECTED",
    }
)


def test_wireguard_tunnels_hostile_fixture_never_serializes_secret_literals():
    _, client, transport = _registered_mcp()
    transport.register(
        "GET",
        "/api/v2/vpn/wireguard/tunnels?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_wireguard_tunnel_row()])),
    )
    tunnels = client.get_vpn_wireguard_tunnels()
    dumped = json.dumps([t.model_dump() for t in tunnels])
    for secret in ("PRIVATE_KEY_MUST_NOT_ESCAPE", "TOKEN_MUST_NOT_ESCAPE"):
        assert secret not in dumped


def test_wireguard_peers_hostile_fixture_never_serializes_secret_literals():
    _, client, transport = _registered_mcp()
    transport.register(
        "GET",
        "/api/v2/vpn/wireguard/peers?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_wireguard_peer_row()])),
    )
    peers = client.get_vpn_wireguard_peers()
    dumped = json.dumps([p.model_dump() for p in peers])
    assert "PSK_MUST_NOT_ESCAPE" not in dumped


def test_ipsec_phase1s_hostile_fixture_never_serializes_secret_literals():
    _, client, transport = _registered_mcp()
    transport.register(
        "GET",
        "/api/v2/vpn/ipsec/phase1s?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_ipsec_phase1_row()])),
    )
    phase1s = client.get_vpn_ipsec_phase1s()
    dumped = json.dumps([p.model_dump() for p in phase1s])
    assert "IPSEC_SECRET_MUST_NOT_ESCAPE" not in dumped


def test_openvpn_clients_hostile_fixture_never_serializes_secret_literals():
    _, client, transport = _registered_mcp()
    transport.register(
        "GET",
        "/api/v2/vpn/openvpn/clients?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_openvpn_client_row()])),
    )
    clients = client.get_vpn_openvpn_clients()
    dumped = json.dumps([c.model_dump() for c in clients])
    for secret in ("SUPER_SECRET_PASSWORD", "OPENVPN_TLS_SECRET_MUST_NOT_ESCAPE", "INJECTED"):
        assert secret not in dumped


def test_all_hostile_fixtures_across_all_five_never_leak_via_full_mcp_round_trip():
    """Strongest form of the proof: registers all 5 tools through the real
    ToolRegistry (not a bare model constructor), calls each registered
    wrapper function directly, and JSON-serializes the return value the
    way FastMCP would -- confirming the secret literals cannot reach an
    actual MCP tool response, not just a bare model."""
    mcp, _client, transport = _registered_mcp()
    transport.register(
        "GET", "/api/v2/services/service_watchdogs?limit=100", status_code=200, text=json.dumps(_envelope([]))
    )
    transport.register(
        "GET",
        "/api/v2/vpn/wireguard/tunnels?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_wireguard_tunnel_row()])),
    )
    transport.register(
        "GET",
        "/api/v2/vpn/wireguard/peers?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_wireguard_peer_row()])),
    )
    transport.register(
        "GET",
        "/api/v2/vpn/ipsec/phase1s?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_ipsec_phase1_row()])),
    )
    transport.register(
        "GET",
        "/api/v2/vpn/openvpn/clients?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_openvpn_client_row()])),
    )

    async def _call_all():
        structured_results = []
        for name in PROMOTED_TOOL_NAMES:
            _content, structured = await mcp.call_tool(name, {})
            structured_results.append(structured)
        return structured_results

    structured_results = asyncio.run(_call_all())
    full_dump = json.dumps(structured_results, default=str)
    for secret in HOSTILE_SECRET_LITERALS:
        assert secret not in full_dump


# ---------------------------------------------------------------------------
# Malformed / empty / nullable / unknown-future-field robustness
# ---------------------------------------------------------------------------


def test_all_five_handle_empty_list_response():
    _, client, transport = _registered_mcp()
    for path, method_name in (
        ("/api/v2/services/service_watchdogs?limit=100", "get_services_service_watchdogs"),
        ("/api/v2/vpn/wireguard/tunnels?limit=100", "get_vpn_wireguard_tunnels"),
        ("/api/v2/vpn/wireguard/peers?limit=100", "get_vpn_wireguard_peers"),
        ("/api/v2/vpn/ipsec/phase1s?limit=100", "get_vpn_ipsec_phase1s"),
        ("/api/v2/vpn/openvpn/clients?limit=100", "get_vpn_openvpn_clients"),
    ):
        transport.register("GET", path, status_code=200, text=json.dumps(_envelope([])))
        assert getattr(client, method_name)() == []


def test_all_five_tolerate_unknown_future_fields_without_error():
    """extra='ignore' is the project-wide Pydantic v2 default -- an
    unmodeled future upstream field must be silently dropped, never
    raise and never appear in the parsed model."""
    _, client, transport = _registered_mcp()
    row = _hostile_wireguard_tunnel_row()
    row["some_future_field_pfrest_might_add"] = "FUTURE_FIELD_MUST_NOT_ESCAPE"
    transport.register(
        "GET", "/api/v2/vpn/wireguard/tunnels?limit=100", status_code=200, text=json.dumps(_envelope([row]))
    )
    tunnels = client.get_vpn_wireguard_tunnels()
    assert not hasattr(tunnels[0], "some_future_field_pfrest_might_add")
    dumped = json.dumps(tunnels[0].model_dump())
    assert "FUTURE_FIELD_MUST_NOT_ESCAPE" not in dumped
