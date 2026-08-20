import asyncio
import json

from mcp.server.fastmcp import FastMCP

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.models.auth_key import AuthKey
from pfsense_mcp.models.email_notification_settings import EmailNotificationSettings
from pfsense_mcp.models.pf_sense_user import PfSenseUser
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.profiles import AuditorProfile
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools.registry import KNOWN_READ_TOOL_NAMES, ToolRegistry
from pfsense_mcp.transport.mock import MockTransport

PROHIBITED_FIELDS = {"ipsecpsk", "password", "key"}


def _property_names(value: object) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            names.update(properties)
        for child in value.values():
            names.update(_property_names(child))
    elif isinstance(value, list):
        for child in value:
            names.update(_property_names(child))
    return names


def test_prohibited_credentials_are_absent_from_public_model_schemas():
    schemas = [
        PfSenseUser.model_json_schema(),
        EmailNotificationSettings.model_json_schema(),
        AuthKey.model_json_schema(),
    ]
    serialized = json.dumps(schemas, sort_keys=True)
    for field in PROHIBITED_FIELDS:
        assert f'"{field}"' not in serialized


def test_prohibited_credentials_are_absent_from_every_mcp_schema():
    mcp = FastMCP("complete-schema-test")
    client = PfSenseClient(RestApiClient(MockTransport(), identity="upstream", api_version=ApiVersion.V2))
    ToolRegistry(mcp, client, "upstream", AuditorProfile.capabilities).register_all()

    for tool in asyncio.run(mcp.list_tools()):
        assert _property_names(tool.inputSchema).isdisjoint(PROHIBITED_FIELDS)
        assert _property_names(tool.outputSchema).isdisjoint(PROHIBITED_FIELDS)


def test_all_read_tools_have_exact_annotations_without_schema_side_effects():
    mcp = FastMCP("annotation-test")
    client = PfSenseClient(RestApiClient(MockTransport(), identity="upstream", api_version=ApiVersion.V2))
    ToolRegistry(mcp, client, "upstream", AuditorProfile.capabilities).register_all()
    tools = asyncio.run(mcp.list_tools())

    assert len(tools) == 46
    assert all(tool.name.startswith("pfsense_get_") or tool.name == "pfsense_mcp_info" for tool in tools)
    assert {tool.name for tool in tools} == KNOWN_READ_TOOL_NAMES
    for tool in tools:
        assert tool.annotations is not None
        expected_open_world_hint = tool.name != "pfsense_mcp_info"
        assert tool.annotations.model_dump(exclude_none=True) == {
            "readOnlyHint": True,
            "openWorldHint": expected_open_world_hint,
        }
        assert "readOnlyHint" not in _property_names(tool.inputSchema)
        assert "openWorldHint" not in _property_names(tool.outputSchema)
        assert _property_names(tool.inputSchema).isdisjoint(PROHIBITED_FIELDS)
        assert _property_names(tool.outputSchema).isdisjoint(PROHIBITED_FIELDS)


def test_auth_keys_tool_input_no_longer_has_disclosure_argument():
    mcp = FastMCP("schema-test")
    client = PfSenseClient(RestApiClient(MockTransport(), identity="upstream", api_version=ApiVersion.V2))
    ToolRegistry(mcp, client, "upstream", AuditorProfile.capabilities).register_all()
    tools = asyncio.run(mcp.list_tools())

    assert len(tools) == 46
    auth_keys = next(tool for tool in tools if tool.name == "pfsense_get_auth_keys")
    assert "include_identifying_metadata" not in auth_keys.inputSchema["properties"]
    for field in PROHIBITED_FIELDS:
        assert f'"{field}"' not in json.dumps(auth_keys.outputSchema, sort_keys=True)


def test_registered_auth_keys_callable_has_no_disclosure_argument():
    mcp = FastMCP("signature-test")
    client = PfSenseClient(RestApiClient(MockTransport(), identity="upstream", api_version=ApiVersion.V2))
    ToolRegistry(mcp, client, "upstream", AuditorProfile.capabilities).register_all()
    tool = next(item for item in asyncio.run(mcp.list_tools()) if item.name == "pfsense_get_auth_keys")
    assert "include_identifying_metadata" not in tool.inputSchema["properties"]
    assert "limit" in tool.inputSchema["properties"]


def test_upstream_secret_values_are_ignored_by_model_factories():
    user = PfSenseUser.from_api(
        {
            "authorizedkeys": "ssh-ed25519 synthetic-public-key",
            "cert": None,
            "descr": "Synthetic user",
            "disabled": False,
            "expires": "",
            "id": 1,
            "ipsecpsk": "SENTINEL-IPSEC-PSK",
            "name": "synthetic",
            "priv": None,
            "scope": "user",
            "uid": 2000,
        },
        include_identifying_metadata=True,
    )
    email = EmailNotificationSettings.from_api(
        {
            "authentication_mechanism": "PLAIN",
            "disable": False,
            "fromaddress": "sender@example.invalid",
            "ipaddress": "198.51.100.20",
            "notifyemailaddress": "notify@example.invalid",
            "password": "SENTINEL-SMTP-PASSWORD",
            "port": "587",
            "ssl": True,
            "sslvalidate": True,
            "timeout": 30,
            "username": "synthetic-user",
        },
        include_identifying_metadata=True,
    )
    auth_key = AuthKey.from_api(
        {
            "descr": "Synthetic key",
            "hash_algo": "sha256",
            "id": 1,
            "key": "SENTINEL-API-KEY",
            "length_bytes": 32,
            "username": "synthetic-user",
        }
    )

    serialized = "\n".join((user.model_dump_json(), email.model_dump_json(), auth_key.model_dump_json()))
    assert "SENTINEL" not in serialized
    all_fields = PfSenseUser.model_fields | EmailNotificationSettings.model_fields | AuthKey.model_fields
    for field in PROHIBITED_FIELDS:
        assert field not in all_fields
