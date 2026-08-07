from __future__ import annotations

from public_contract import SNAPSHOT, build_contract, main


def test_public_contract_matches_approved_snapshot():
    assert main([]) == 0


def test_public_contract_is_complete_and_security_preserving():
    contract = build_contract()
    tools = contract["tools"]

    assert len(tools) == 41
    assert len({tool["name"] for tool in tools}) == 41
    assert all(tool["name"].startswith("pfsense_get_") for tool in tools)
    assert all(tool["capability"].endswith("_READ") for tool in tools)
    assert all(tool["endpoint"]["method"] == "GET" for tool in tools)
    assert all(tool["endpoint"]["verified"] is True for tool in tools)
    assert all(tool["annotations"] == {"openWorldHint": True, "readOnlyHint": True} for tool in tools)
    assert SNAPSHOT.is_file()
