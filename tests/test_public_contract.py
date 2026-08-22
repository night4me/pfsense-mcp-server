from __future__ import annotations

from public_contract import READ_TOOLS, SNAPSHOT, _tool_definitions, build_contract, main


def test_public_contract_matches_approved_snapshot():
    assert main([]) == 0


def test_public_contract_is_complete_and_security_preserving():
    contract = build_contract()
    tools = contract["tools"]

    assert len(tools) == 95
    assert len({tool["name"] for tool in tools}) == 95
    assert all(tool["name"].startswith("pfsense_get_") or tool["name"] == "pfsense_mcp_info" for tool in tools)
    assert all(tool["capability"].endswith("_READ") for tool in tools)

    upstream_tools = [tool for tool in tools if tool["name"] != "pfsense_mcp_info"]
    assert all(tool["endpoint"]["method"] == "GET" for tool in upstream_tools)
    assert all(tool["endpoint"]["verified"] is True for tool in upstream_tools)
    assert all(tool["annotations"] == {"openWorldHint": True, "readOnlyHint": True} for tool in upstream_tools)

    local_only_tool = next(tool for tool in tools if tool["name"] == "pfsense_mcp_info")
    assert local_only_tool["client_method"] is None
    assert local_only_tool["endpoint"] is None
    assert local_only_tool["annotations"] == {"openWorldHint": False, "readOnlyHint": True}

    assert SNAPSHOT.is_file()


def test_contract_descriptions_use_stable_source_docstrings():
    definitions = _tool_definitions()
    acme_source = (READ_TOOLS / "acme_settings.py").read_text(encoding="utf-8")

    description = definitions["pfsense_get_acme_settings"][1]
    assert "        the service is enabled" in description
    assert description in acme_source
