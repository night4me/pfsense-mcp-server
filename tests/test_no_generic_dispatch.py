"""Permanent regression test for ADR-019's no-generic-dispatch invariant
(`docs/API_SURFACE_ARCHITECTURE.md` Part 3): every MCP tool must map to
exactly one `Capability` and call exactly one fixed underlying client
method -- never select among several based on a request parameter,
regardless of whether that parameter is schema-typed as an open string
or a closed enum.

This test enforces the *strengthened* form of the invariant the ADR-019
acceptance-track review specified
(`reports-ai/reviews/ADR_019_ACCEPTANCE_REVIEW.md`, finding A1): a check
that only counts literal `client.<method>()` call sites has its own
loophole -- a `getattr(client, name)(...)` dispatcher can show zero
literal call sites and would not be flagged by a check that only counts
them. This test is therefore two independent rules, not one:

  1. at most one distinct literal `client.<method>(...)` attribute-access
     call site per tool implementation file, and
  2. zero uses of `getattr`/`setattr`/`hasattr` anywhere in a tool file.

Both rules are checked by direct AST inspection of the actual shipped
source, not by trusting that today's tools happen to already satisfy
them -- this is exactly the kind of claim ADR-019's acceptance review
found the design had asserted without a direct check.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
READ_TOOLS_DIR = ROOT / "src/pfsense_mcp/tools/read"

#: mcp_info.py is the one tool with no PfSenseClient dependency at all
#: (it wraps a local snapshot callback instead) -- expected and
#: documented at its own design review, not a violation of this rule.
EXPECTED_ZERO_CLIENT_CALL_TOOLS = {"mcp_info.py"}

_DYNAMIC_ATTRIBUTE_BUILTINS = {"getattr", "setattr", "hasattr"}


def _tool_files() -> list[Path]:
    return sorted(p for p in READ_TOOLS_DIR.glob("*.py") if p.name != "__init__.py")


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _distinct_client_method_call_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "client"
        ):
            names.add(node.func.attr)
    return names


def _dynamic_attribute_call_names(tree: ast.Module) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _DYNAMIC_ATTRIBUTE_BUILTINS
        ):
            found.add(node.func.id)
    return found


def test_every_tool_file_has_at_most_one_distinct_client_method_call() -> None:
    violations: dict[str, set[str]] = {}
    for path in _tool_files():
        calls = _distinct_client_method_call_names(_tree(path))
        if len(calls) > 1:
            violations[path.name] = calls
    assert violations == {}, f"tool file(s) call more than one distinct client method: {violations}"


def test_exactly_one_tool_file_has_zero_client_method_calls_and_it_is_the_expected_one() -> None:
    zero_call_files = {path.name for path in _tool_files() if len(_distinct_client_method_call_names(_tree(path))) == 0}
    assert zero_call_files == EXPECTED_ZERO_CLIENT_CALL_TOOLS


def test_fifty_nine_tool_files_exist_matching_the_public_contract() -> None:
    assert len(_tool_files()) == 95


def test_no_tool_file_uses_getattr_setattr_or_hasattr() -> None:
    """Rule 2 of the strengthened invariant -- catches the smuggled-
    dispatch pattern (`getattr(client, method_name)(...)`) that a
    call-site-counting check alone would miss."""
    violations: dict[str, set[str]] = {}
    for path in _tool_files():
        found = _dynamic_attribute_call_names(_tree(path))
        if found:
            violations[path.name] = found
    assert violations == {}, f"tool file(s) use dynamic attribute access: {violations}"


def test_pfsense_client_itself_uses_no_dynamic_attribute_access_for_dispatch() -> None:
    """The invariant's other half: PfSenseClient's own methods must not
    internally dispatch to REST operations via getattr/setattr/hasattr
    either -- a tool calling exactly one client method is meaningless
    protection if that one method itself dispatches dynamically
    underneath."""
    client_file = ROOT / "src/pfsense_mcp/pfsense_client.py"
    found = _dynamic_attribute_call_names(_tree(client_file))
    assert found == set(), f"pfsense_client.py uses dynamic attribute access: {found}"
