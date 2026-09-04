"""ADR-029: proves `tier1/acceptance.py`'s first-live-acceptance path is
structurally unreachable from any MCP-reachable module -- checked by direct
AST inspection and by dynamic import-graph inspection, the same discipline
`tests/test_signing_tool_isolation.py` already applies to `signing/`.

Unlike `signing/`, `tier1/acceptance.py` lives inside `src/pfsense_mcp/tier1`
(it needs the same trust boundary as `production_runtime.py` to reach
`WriteEndpoints`/`PfSenseConfig`), so "never referenced anywhere" is not the
right invariant -- `executor.py`, `alias_description_execution.py`, and
`production_runtime.py` all reference `AcceptanceExecutionContext` for type
annotations. The invariant that matters is: every one of those references is
`TYPE_CHECKING`-only, so the module's code never actually loads as a side
effect of importing anything MCP-reachable, and no module outside `tier1/`
references it at all (mirroring
`tests/tier1/test_isolation.py::test_tier1_is_not_imported_outside_its_inert_package`,
which already independently proves `write_api_client.py` -- one layer below
`tier1/` -- has zero `tier1` dependency of any kind).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
PRODUCTION_ROOT = ROOT / "src/pfsense_mcp"
TIER1_ROOT = PRODUCTION_ROOT / "tier1"


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _acceptance_import_nodes(tree: ast.Module) -> list[tuple[ast.ImportFrom, bool]]:
    """Returns (node, is_type_checking_guarded) for every ImportFrom whose
    module resolves to `.acceptance` / `tier1.acceptance` /
    `pfsense_mcp.tier1.acceptance`, walking the tree so a node's ancestry
    (whether it sits inside an `if TYPE_CHECKING:` block) can be checked."""

    results: list[tuple[ast.ImportFrom, bool]] = []

    def _is_type_checking_guard(node: ast.If) -> bool:
        test = node.test
        return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )

    def _matches(node: ast.ImportFrom) -> bool:
        module = node.module or ""
        if node.level:  # relative import, e.g. "from .acceptance import ..." or "from ..tier1.acceptance import ..."
            return module == "acceptance" or module.endswith(".acceptance") or module == "tier1.acceptance"
        return module in {"tier1.acceptance", "pfsense_mcp.tier1.acceptance"}

    def _walk(node: ast.AST, guarded: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If) and _is_type_checking_guard(child):
                for inner in child.body:
                    _walk(inner, True)
                for inner in child.orelse:
                    _walk(inner, guarded)
                continue
            if isinstance(child, ast.ImportFrom) and _matches(child):
                results.append((child, guarded))
            _walk(child, guarded)

    _walk(tree, False)
    return results


def test_no_module_outside_tier1_references_acceptance():
    offenders = []
    for path in PRODUCTION_ROOT.rglob("*.py"):
        if TIER1_ROOT in path.parents or path.parent == TIER1_ROOT:
            continue
        if _acceptance_import_nodes(_tree(path)):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_every_reference_inside_tier1_is_type_checking_guarded():
    exempt = {"acceptance.py"}  # the module itself; self-reference not applicable
    unguarded = []
    for path in TIER1_ROOT.glob("*.py"):
        if path.name in exempt:
            continue
        for node, guarded in _acceptance_import_nodes(_tree(path)):
            if not guarded:
                unguarded.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
    assert unguarded == []


def test_importing_mcp_entrypoints_never_loads_acceptance_module():
    """The direct, dynamic proof: actually importing the modules that
    application startup and MCP tool registration import must never cause
    `pfsense_mcp.tier1.acceptance` to appear in sys.modules -- the
    TYPE_CHECKING guards mean this should be true by construction, but this
    test does not trust that reasoning, only the observed result."""

    marker = "pfsense_mcp.tier1.acceptance"
    assert marker not in sys.modules, "acceptance module already loaded before this test ran -- test order issue"

    import pfsense_mcp.application
    import pfsense_mcp.factory
    import pfsense_mcp.server
    import pfsense_mcp.tier1.alias_description_execution
    import pfsense_mcp.tier1.executor
    import pfsense_mcp.tier1.production_runtime
    import pfsense_mcp.tools.registry  # noqa: F401

    assert marker not in sys.modules


def test_acceptance_eligible_is_exactly_the_six_reviewed_endpoints():
    """Was `test_acceptance_eligible_is_exactly_one_endpoint` -- ADR-037
    Batch 1's post-implementation security review (2026-09-04, owner) set
    `acceptance_eligible=True` on all five new Batch 1 entries, each
    opting into the same ADR-029 first-live-acceptance path
    `FIREWALL_ALIAS_DESCRIPTION` already used, never a shortcut around it
    -- see write_endpoints.py's own docstring for the five entries'
    exact reasoning. Six is now the complete, exact, reviewed set."""

    from pfsense_mcp.write_endpoints import WriteEndpoints

    eligible = [
        name
        for name in WriteEndpoints.active_entries()
        if getattr(WriteEndpoints, name).acceptance_eligible  # type: ignore[union-attr]
    ]
    assert sorted(eligible) == sorted(
        [
            "FIREWALL_ALIAS_DESCRIPTION",
            "NTP_TIME_SERVER_PREFER",
            "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
            "LOG_DISPLAY_PREFERENCES",
            "LOG_RETENTION_SETTINGS",
            "SYSTEM_TIMEZONE",
        ]
    )


def test_acceptance_eligible_endpoint_is_now_verified():
    """Was `test_acceptance_eligible_endpoint_is_not_yet_verified` --
    FIREWALL_ALIAS_DESCRIPTION.verified flipped to True on 2026-08-16
    (see write_endpoints.py's module docstring); acceptance_eligible
    remains True but is now permanently inert for this endpoint per
    tier1/acceptance.py's own one-time gate (see test_acceptance.py's
    test_real_endpoint_is_now_verified_and_acceptance_mode_is_permanently_retired)."""
    from pfsense_mcp.write_endpoints import WriteEndpoints

    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified is True
