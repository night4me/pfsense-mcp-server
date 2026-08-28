"""Tests for `pfsense_mcp.guidance.tool_guidance` (post-v0.8.0 guidance
arc, Slice A). Covers: classification completeness against the real
public contract, deterministic/pure behavior, bounded output, closed
schema (no capability/endpoint/token field), and that this module is
never wired into the MCP tool registry yet (deliberate, this arc)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))
import public_contract

from pfsense_mcp.guidance.tool_guidance import (
    PROVENANCE,
    ResultKind,
    ToolGuidance,
    get_tool_guidance,
    known_tool_names,
)

ROOT = Path(__file__).parents[2]


def _real_read_tool_names() -> set[str]:
    contract = public_contract.build_contract()
    return {t["name"] for t in contract["tools"] if t["tool_class"] == "read"}


# --- classification completeness, cross-checked against the real contract ---


def test_every_read_tool_is_classified():
    real = _real_read_tool_names()
    classified = known_tool_names()
    assert real == classified, f"missing={real - classified}, extra={classified - real}"


def test_known_tool_names_matches_public_contract_count():
    assert len(known_tool_names()) == 95


@pytest.mark.parametrize("tool_name", sorted(_real_read_tool_names()))
def test_get_tool_guidance_returns_a_result_for_every_real_tool(tool_name):
    guidance = get_tool_guidance(tool_name)
    assert guidance is not None
    assert guidance.tool_name == tool_name
    assert isinstance(guidance.result_kind, ResultKind)
    assert guidance.provenance == "PROJECT_AUTHORED"
    assert guidance.interpretation


# --- unknown input fails closed, never guesses ---


def test_unknown_tool_name_returns_none():
    assert get_tool_guidance("pfsense_get_totally_made_up_tool") is None
    assert get_tool_guidance("") is None
    assert get_tool_guidance("pfsense_set_firewall_alias_description_v1") is None


# --- purity / determinism (same discipline as registry.lookup_guidance's I5) ---


def test_get_tool_guidance_is_deterministic():
    first = get_tool_guidance("pfsense_get_firewall_aliases")
    second = get_tool_guidance("pfsense_get_firewall_aliases")
    assert first == second


def test_get_tool_guidance_never_raises_for_arbitrary_string_input():
    for candidate in ["", " ", "\x00", "a" * 10000, "pfsense_get_firewall_aliases; DROP TABLE"]:
        assert get_tool_guidance(candidate) is None


# --- bounded output ---


def test_interpretation_is_bounded():
    from pfsense_mcp.guidance.models import MAX_EXCERPT_LENGTH

    for tool_name in known_tool_names():
        guidance = get_tool_guidance(tool_name)
        assert len(guidance.interpretation) <= MAX_EXCERPT_LENGTH


# --- APPLY_STATUS cluster: every one has both a specific override and a named related tool ---


_APPLY_STATUS_TOOLS = (
    "pfsense_get_dhcp_server_apply_status",
    "pfsense_get_dns_forwarder_apply_status",
    "pfsense_get_dns_resolver_apply_status",
    "pfsense_get_firewall_apply_status",
    "pfsense_get_firewall_virtual_ip_apply_status",
    "pfsense_get_interface_apply_status",
    "pfsense_get_ipsec_apply_status",
    "pfsense_get_routing_apply_status",
    "pfsense_get_wireguard_apply_status",
)


def test_apply_status_cluster_is_fully_classified_and_captures_every_flagged_tool():
    assert len(_APPLY_STATUS_TOOLS) == 9
    for tool_name in _APPLY_STATUS_TOOLS:
        guidance = get_tool_guidance(tool_name)
        assert guidance.result_kind is ResultKind.APPLY_STATUS
        assert "Matching configuration tool" in guidance.interpretation
        assert guidance.empty_result_is_meaningful is True


def test_no_other_tool_is_misclassified_as_apply_status():
    for tool_name in known_tool_names() - set(_APPLY_STATUS_TOOLS):
        guidance = get_tool_guidance(tool_name)
        assert guidance.result_kind is not ResultKind.APPLY_STATUS


# --- empty_result_is_meaningful / secrets_intentionally_omitted structural checks ---


def test_secrets_omitted_tools_are_a_narrow_explicit_set():
    secret_tools = {name for name in known_tool_names() if get_tool_guidance(name).secrets_intentionally_omitted}
    assert secret_tools == {
        "pfsense_get_auth_keys",
        "pfsense_get_system_certificates",
        "pfsense_get_system_certificate_authorities",
        "pfsense_get_users",
        "pfsense_get_system_restapi_settings",
    }


def test_identity_kind_tools_never_flag_empty_as_meaningful_by_default():
    for tool_name in known_tool_names():
        guidance = get_tool_guidance(tool_name)
        if guidance.result_kind is ResultKind.IDENTITY:
            assert guidance.empty_result_is_meaningful is False


# --- G1-style closed-schema discipline: no capability/endpoint/token field ---


def test_tool_guidance_dataclass_has_no_authorization_shaped_field():
    field_names = set(ToolGuidance.__dataclass_fields__)
    forbidden_substrings = ("capability", "endpoint", "method", "token", "digest", "signature")
    offenders = [name for name in field_names if any(bad in name.lower() for bad in forbidden_substrings)]
    assert offenders == []


def test_provenance_constant_is_fixed():
    assert PROVENANCE == "PROJECT_AUTHORED"
    for tool_name in known_tool_names():
        assert get_tool_guidance(tool_name).provenance == "PROJECT_AUTHORED"


# --- isolation: this module performs no I/O, imports nothing network-shaped ---


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_tool_guidance_module_imports_no_network_module():
    path = ROOT / "src/pfsense_mcp/guidance/tool_guidance.py"
    imported = _imported_modules(path)
    forbidden = {"socket", "requests", "httpx", "urllib.request"}
    assert not (imported & forbidden)


def test_tool_guidance_module_imports_no_safety_authority_module():
    path = ROOT / "src/pfsense_mcp/guidance/tool_guidance.py"
    imported = _imported_modules(path)
    forbidden_roots = {
        "pfsense_mcp.tier1",
        "pfsense_mcp.write_endpoints",
        "pfsense_mcp.write_api_client",
        "pfsense_mcp.write_types",
        "pfsense_mcp.rest_api_client",
        "pfsense_mcp.transport",
        "pfsense_mcp.tools",
    }
    offenders = {m for m in imported if any(m == root or m.startswith(f"{root}.") for root in forbidden_roots)}
    assert offenders == set()


#: Updated 2026-08-28 (pfREST_LIVE_GUIDANCE_ARC): tool_guidance is now
#: deliberately wired into exactly one reviewed production module,
#: `pfsense_get_api_guidance` -- see that tool's own module docstring
#: for why. A change to this constant is itself the kind of thing that
#: must be a reviewed diff, not a silent expansion (same discipline as
#: `test_isolation.py`'s `ALLOWED_GUIDANCE_IMPORTERS`).
_ALLOWED_TOOL_GUIDANCE_CONSUMER = "src/pfsense_mcp/tools/read/api_guidance.py"


def test_tool_guidance_is_wired_into_exactly_one_reviewed_production_module():
    """Originally (this arc's predecessor): tool_guidance was a tested
    foundation not yet exposed via any MCP tool. Revised 2026-08-28: it
    is now wired into `pfsense_get_api_guidance`'s PROJECT_AUTHORED
    evidence for query_mode="tool" -- deliberately, as part of this
    arc's own Phase 9. This guards against silent, unreviewed scope
    creep in either direction: an additional, undocumented consumer
    fails this test just as loudly as the original "zero consumers"
    version did."""

    production = ROOT / "src/pfsense_mcp"
    offenders = []
    for path in production.rglob("*.py"):
        if path.name == "tool_guidance.py":
            continue
        if "guidance" in path.relative_to(production).parts:
            continue
        imported = _imported_modules(path)
        if any(m == "pfsense_mcp.guidance.tool_guidance" for m in imported):
            relative = path.relative_to(ROOT).as_posix()
            if relative != _ALLOWED_TOOL_GUIDANCE_CONSUMER:
                offenders.append(relative)
    assert offenders == []


def test_allowed_tool_guidance_consumer_actually_imports_tool_guidance():
    """Flip side: confirm the allowed exception is not stale."""
    path = ROOT / _ALLOWED_TOOL_GUIDANCE_CONSUMER
    assert path.is_file(), f"{_ALLOWED_TOOL_GUIDANCE_CONSUMER} no longer exists -- remove the exception"
    imported = _imported_modules(path)
    assert any(m == "pfsense_mcp.guidance.tool_guidance" for m in imported)
