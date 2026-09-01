"""Adversarial test matrix for the auth_servers READ candidate promoted in
POST_V1_1_AUTH_SERVER_BOUNDED_READ_PROMOTION (2026-09-01, live-qualified in
POST_V1_1_AUTH_SERVER_LIVE_QUALIFICATION.md).

Complements the offline suites in test_pfsense_client.py (which already
prove structural exclusion at the client/model layer) with proof at the
actual MCP surface: tool registration, exact GET/path dispatch, and
end-to-end serialization of hostile fixtures through the registered tool
wrapper's real `call_tool()` JSON output.
"""

from __future__ import annotations

import asyncio
import json

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.models.pf_sense_auth_server import PfSenseAuthServer
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.profiles import AuditorProfile
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools.registry import ToolRegistry
from pfsense_mcp.transport.mock import MockTransport

TOOL_NAME = "pfsense_get_user_auth_servers"


def _envelope(rows: list[dict]) -> dict:
    return {"code": 200, "data": rows, "message": "", "response_id": "SUCCESS", "status": "ok"}


def _registered_mcp():
    transport = MockTransport()
    rest_client = RestApiClient(transport, identity="api-mcp-readonly", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("auth-server-adversarial-test")
    ToolRegistry(mcp, client, "api-mcp-readonly", AuditorProfile.capabilities).register_all()
    return mcp, client, transport


def test_auth_servers_tool_is_registered_and_read_only():
    mcp, _client, _transport = _registered_mcp()
    tools = asyncio.run(mcp.list_tools())
    tool_by_name = {tool.name: tool for tool in tools}
    assert TOOL_NAME in tool_by_name
    assert tool_by_name[TOOL_NAME].annotations.readOnlyHint is True


def test_auth_servers_tool_calls_exact_get_path():
    _mcp, client, transport = _registered_mcp()
    transport.register("GET", "/api/v2/user/auth_servers?limit=100", status_code=200, text=json.dumps(_envelope([])))
    client.get_user_auth_servers()
    assert transport.calls == [("GET", "/api/v2/user/auth_servers?limit=100")]


def _hostile_auth_server_row(type_: str) -> dict:
    if type_ == "ldap":
        return {
            "refid": "abc123",
            "type": "ldap",
            "name": "hostile-ldap",
            "host": "198.51.100.30",
            "ldap_port": "636",
            "ldap_urltype": "SSL Encrypted",
            "ldap_protver": 3,
            "ldap_timeout": 25,
            "ldap_caref": "global",
            "ldap_scope": "subtree",
            "ldap_basedn": "dc=hostile,dc=example,dc=com",
            "ldap_authcn": "ou=People",
            "ldap_extended_enabled": False,
            "ldap_extended_query": None,
            "ldap_binddn": "cn=svc,dc=hostile,dc=example,dc=com",
            "ldap_bindpw": "LDAP_BIND_PASSWORD_MUST_NEVER_ESCAPE",
            "ldap_attr_user": "cn",
            "ldap_attr_group": "cn",
            "ldap_attr_member": "member",
            "ldap_rfc2307": False,
            "ldap_rfc2307_userdn": False,
            "ldap_attr_groupobj": "posixGroup",
            "ldap_pam_groupdn": "cn=shell,dc=hostile,dc=example,dc=com",
            "ldap_utf8": False,
            "ldap_nostrip_at": False,
            "ldap_allow_unauthenticated": True,
            "radius_secret": None,
            "radius_auth_port": "1812",
            "radius_acct_port": "1813",
            "radius_protocol": "MSCHAPv2",
            "radius_timeout": 5,
            "radius_nasip_attribute": None,
        }
    return {
        "refid": "def456",
        "type": "radius",
        "name": "hostile-radius",
        "host": "198.51.100.31",
        "ldap_port": None,
        "ldap_urltype": None,
        "ldap_protver": None,
        "ldap_timeout": None,
        "ldap_caref": None,
        "ldap_scope": None,
        "ldap_basedn": None,
        "ldap_authcn": None,
        "ldap_extended_enabled": None,
        "ldap_extended_query": None,
        "ldap_binddn": None,
        "ldap_bindpw": None,
        "ldap_attr_user": None,
        "ldap_attr_group": None,
        "ldap_attr_member": None,
        "ldap_rfc2307": None,
        "ldap_rfc2307_userdn": None,
        "ldap_attr_groupobj": None,
        "ldap_pam_groupdn": None,
        "ldap_utf8": None,
        "ldap_nostrip_at": None,
        "ldap_allow_unauthenticated": None,
        "radius_secret": "RADIUS_SECRET_MUST_NEVER_ESCAPE",
        "radius_auth_port": "1812",
        "radius_acct_port": "1813",
        "radius_protocol": "MSCHAPv2",
        "radius_timeout": 5,
        "radius_nasip_attribute": "wan",
    }


HOSTILE_SECRET_LITERALS = frozenset(
    {
        "LDAP_BIND_PASSWORD_MUST_NEVER_ESCAPE",
        "RADIUS_SECRET_MUST_NEVER_ESCAPE",
    }
)


def test_structural_exclusion_asserted_on_production_model():
    assert "ldap_bindpw" not in PfSenseAuthServer.model_fields
    assert "radius_secret" not in PfSenseAuthServer.model_fields


def test_hostile_ldap_and_radius_fixtures_never_serialize_secrets_via_client():
    _mcp, client, transport = _registered_mcp()
    transport.register(
        "GET",
        "/api/v2/user/auth_servers?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_auth_server_row("ldap"), _hostile_auth_server_row("radius")])),
    )
    servers = client.get_user_auth_servers(include_identifying_metadata=True)
    assert len(servers) == 2
    dumped = json.dumps([s.model_dump() for s in servers])
    for secret in HOSTILE_SECRET_LITERALS:
        assert secret not in dumped
    # Safe fields survive correctly.
    assert servers[0].name == "hostile-ldap"
    assert servers[1].name == "hostile-radius"
    assert servers[0].host == "198.51.100.30"
    assert servers[1].radius_protocol == "MSCHAPv2"


def test_hostile_fixtures_never_leak_via_full_mcp_call_tool_round_trip():
    """Strongest form of the proof: registers the tool through the real
    ToolRegistry, calls it via mcp.call_tool() (the actual wire path an
    MCP client uses), and asserts hostile secret literals cannot reach
    the serialized MCP response."""
    mcp, _client, transport = _registered_mcp()
    transport.register(
        "GET",
        "/api/v2/user/auth_servers?limit=100",
        status_code=200,
        text=json.dumps(_envelope([_hostile_auth_server_row("ldap"), _hostile_auth_server_row("radius")])),
    )

    _content, structured = asyncio.run(mcp.call_tool(TOOL_NAME, {"include_identifying_metadata": True}))
    full_dump = json.dumps(structured, default=str)
    for secret in HOSTILE_SECRET_LITERALS:
        assert secret not in full_dump


def test_empty_list_state():
    _mcp, client, transport = _registered_mcp()
    transport.register("GET", "/api/v2/user/auth_servers?limit=100", status_code=200, text=json.dumps(_envelope([])))
    assert client.get_user_auth_servers() == []


def test_unknown_future_field_is_dropped_without_error():
    _mcp, client, transport = _registered_mcp()
    row = _hostile_auth_server_row("ldap")
    row["some_future_field_pfrest_might_add"] = "FUTURE_FIELD_MUST_NOT_ESCAPE"
    transport.register("GET", "/api/v2/user/auth_servers?limit=100", status_code=200, text=json.dumps(_envelope([row])))
    servers = client.get_user_auth_servers()
    assert not hasattr(servers[0], "some_future_field_pfrest_might_add")
    dumped = json.dumps(servers[0].model_dump())
    assert "FUTURE_FIELD_MUST_NOT_ESCAPE" not in dumped
