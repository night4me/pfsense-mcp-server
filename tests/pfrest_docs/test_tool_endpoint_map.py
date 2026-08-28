"""Drift check: TOOL_ENDPOINT_PATHS must exactly match this project's
own authoritative source (scripts/public_contract.py's AST-derived
tool/endpoint mapping) -- a future READ tool cannot silently ship
without this table being updated (pfREST_LIVE_GUIDANCE_ARC Phase 9's
completeness invariant, applied to this table)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from pfsense_mcp.pfrest_docs.tool_endpoint_map import TOOL_ENDPOINT_PATHS, pfrest_path_for

ROOT = Path(__file__).resolve().parents[2]


def _load_public_contract_module():
    scripts_dir = ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    spec = importlib.util.spec_from_file_location("public_contract", scripts_dir / "public_contract.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _derive_expected_mapping() -> dict[str, tuple[str, str]]:
    pc = _load_public_contract_module()
    from pfsense_mcp.endpoints import Endpoints

    tool_defs = pc._tool_definitions()
    client_endpoints = pc._client_endpoints()
    expected: dict[str, tuple[str, str]] = {}
    for name, (method, _description) in tool_defs.items():
        if method is None:
            continue
        endpoint_name = client_endpoints[method]
        endpoint = getattr(Endpoints, endpoint_name)
        expected[name] = (endpoint.path_suffix, "GET")
    return expected


def test_tool_endpoint_paths_matches_authoritative_source_exactly():
    expected = _derive_expected_mapping()
    assert expected == TOOL_ENDPOINT_PATHS


def test_pfrest_path_for_prefixes_api_v2():
    result = pfrest_path_for("pfsense_get_firewall_aliases")
    assert result == ("/api/v2/firewall/aliases", "GET")


def test_pfrest_path_for_unknown_tool_returns_none():
    assert pfrest_path_for("not_a_real_tool") is None


def test_pfrest_path_for_local_only_tool_returns_none():
    assert pfrest_path_for("pfsense_mcp_info") is None


def test_pfrest_path_for_guidance_tools_returns_none():
    assert pfrest_path_for("pfsense_get_official_guidance") is None
    assert pfrest_path_for("pfsense_get_api_guidance") is None
