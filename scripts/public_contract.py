#!/usr/bin/env python3
"""Generate or verify the deterministic public MCP contract snapshot."""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
from pathlib import Path
from typing import Any, Sequence

from mcp.server.fastmcp import FastMCP

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
from pfsense_mcp.endpoints import Endpoints
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.profiles import AuditorProfile
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools.registry import ToolRegistry
from pfsense_mcp.transport.mock import MockTransport

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "tests" / "contracts" / "mcp_public_contract_v0.4.1.json"
READ_TOOLS = ROOT / "src" / "pfsense_mcp" / "tools" / "read"
CLIENT_SOURCE = ROOT / "src" / "pfsense_mcp" / "pfsense_client.py"

# Tools with no PfSenseClient dependency at all — they report local
# process state and make no pfSense API call. Currently just the one.
LOCAL_ONLY_TOOL_NAMES: frozenset[str] = frozenset({"pfsense_mcp_info"})


def _client() -> PfSenseClient:
    rest = RestApiClient(MockTransport(), identity="snapshot", api_version=ApiVersion.V2)
    return PfSenseClient(rest)


def _registered_tools(capabilities: frozenset[Capability]) -> list[Any]:
    mcp = FastMCP("public-contract")
    ToolRegistry(mcp, _client(), "snapshot", capabilities).register_all()
    return list(asyncio.run(mcp.list_tools()))


def _single_attribute_calls(tree: ast.AST, owner: str) -> set[str]:
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == owner
    }


def _tool_definitions() -> dict[str, tuple[str | None, str]]:
    """Map each tool name to (client_method, description).

    Every tool has exactly one PfSenseClient method call except
    pfsense_mcp_info, which has none by design (LOCAL_ONLY_TOOL_NAMES) —
    it makes no pfSense API call at all, so client_method is None.
    """
    result: dict[str, tuple[str | None, str]] = {}
    for path in sorted(READ_TOOLS.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        functions = [
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name.startswith("pfsense_")
        ]
        methods = _single_attribute_calls(tree, "client")
        if len(functions) != 1:
            raise RuntimeError(f"Expected exactly one public tool in {path.relative_to(ROOT)}")
        function = functions[0]
        is_local_only = function.name in LOCAL_ONLY_TOOL_NAMES
        expected_methods = 0 if is_local_only else 1
        if len(methods) != expected_methods:
            raise RuntimeError(f"Expected {expected_methods} client method(s) in {path.relative_to(ROOT)}")
        description = ast.get_docstring(function, clean=False)
        if description is None:
            raise RuntimeError(f"Expected a public tool description in {path.relative_to(ROOT)}")
        result[function.name] = (methods.pop() if methods else None, description)
    return result


def _client_endpoints() -> dict[str, str]:
    tree = ast.parse(CLIENT_SOURCE.read_text(encoding="utf-8"), filename=str(CLIENT_SOURCE))
    result: dict[str, str] = {}
    client_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PfSenseClient")
    for node in client_class.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("get_"):
            continue
        endpoint_names = {
            child.attr
            for child in ast.walk(node)
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "Endpoints"
        }
        if len(endpoint_names) != 1:
            raise RuntimeError(f"Expected one declared endpoint in PfSenseClient.{node.name}")
        result[node.name] = endpoint_names.pop()
    return result


def _capability_ownership() -> dict[str, str]:
    ownership: dict[str, str] = {}
    for capability in sorted(SUPPORTED_CAPABILITIES_THIS_BUILD, key=lambda item: item.name):
        for tool in _registered_tools(frozenset({capability})):
            if tool.name in ownership:
                raise RuntimeError(f"Tool has duplicate capability ownership: {tool.name}")
            ownership[tool.name] = capability.name
    return ownership


def build_contract() -> dict[str, Any]:
    tool_definitions = _tool_definitions()
    client_endpoints = _client_endpoints()
    capability_ownership = _capability_ownership()
    tools: list[dict[str, Any]] = []
    for tool in sorted(_registered_tools(AuditorProfile.capabilities), key=lambda item: item.name):
        method, description = tool_definitions[tool.name]
        if method is None:
            endpoint_entry: dict[str, Any] | None = None
        else:
            endpoint_name = client_endpoints[method]
            endpoint = getattr(Endpoints, endpoint_name)
            endpoint_entry = {
                "symbol": endpoint_name,
                "method": "GET",
                "path_suffix": endpoint.path_suffix,
                "minimum_api_version": endpoint.min_api_version.value,
                "verified": endpoint.verified,
            }
        tools.append(
            {
                "name": tool.name,
                # FastMCP description cleanup differs between supported Python
                # versions. Source AST text is stable and is the authoritative
                # tool docstring that FastMCP receives before normalization.
                "description": description,
                "input_schema": tool.inputSchema,
                "output_schema": tool.outputSchema,
                "annotations": tool.annotations.model_dump(exclude_none=True, by_alias=True)
                if tool.annotations is not None
                else None,
                "capability": capability_ownership[tool.name],
                "client_method": method,
                "endpoint": endpoint_entry,
            }
        )
    return {"snapshot_format": 1, "tools": tools}


def _serialized(contract: dict[str, Any]) -> str:
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def _changed_tools(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    expected_tools = {tool["name"]: tool for tool in expected.get("tools", [])}
    actual_tools = {tool["name"]: tool for tool in actual.get("tools", [])}
    return sorted(
        name
        for name in expected_tools.keys() | actual_tools.keys()
        if expected_tools.get(name) != actual_tools.get(name)
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="write the current contract after explicit API approval")
    args = parser.parse_args(argv)
    actual = build_contract()
    if args.update:
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(_serialized(actual), encoding="utf-8")
        print(f"public_contract: updated {SNAPSHOT.relative_to(ROOT)}")
        return 0
    if not SNAPSHOT.exists():
        print(f"public_contract: missing snapshot {SNAPSHOT.relative_to(ROOT)}")
        return 1
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    if expected != actual:
        changed = ", ".join(_changed_tools(expected, actual)) or "snapshot metadata"
        print(f"public_contract: contract drift detected in: {changed}")
        print("Review and approve the API change, then run: python scripts/public_contract.py --update")
        return 1
    print(f"public_contract: OK ({len(actual['tools'])} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
