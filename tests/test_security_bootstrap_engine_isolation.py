"""Structural isolation tests for `security_bootstrap_client.py` and
`security_bootstrap_engine.py` (`ADR-033` implementation Phase C),
proving by direct AST/source inspection of the actual shipped files --
never by importing and trusting runtime behavior -- that:

- neither module is reachable from the MCP tool registry, the
  `pfsense-mcp-security` CLI, `doctor`, or normal application startup
  (requirement 9: "CLI/runtime isolation" -- this phase's review
  boundary before an operator can invoke a mutation);
- neither imports `pfsense_mcp.tier1` in any form;
- `security_bootstrap_client.py` is the sole new addition to
  `get_only_check.py`'s Transport-request allow-list, and the engine
  itself never calls `.request()` directly (all HTTP goes through the
  client);
- each module's public surface is exactly its reviewed API.

Mirrors `tests/test_security_privileges_isolation.py`'s and
`tests/test_security_doctor_isolation.py`'s established structure.

The final section (ADR-033 CLI Integration Slice 3) adds the equivalent
proof for `security_bootstrap_orchestration.py`: it is the *sole*
gateway `security_cli.py` and (as of `setup apply`'s own Slice 3,
`security_setup_apply.py`) may use to reach anything above, and it is
itself unreachable from every other runtime entry point and from
`tools/*`. `security_setup_apply.py` joined
`_RUNTIME_ENTRY_POINTS` when it started composing
`run_bootstrap_from_environment()` for `write_protected` apply -- it
must never reach past that one bridge into the lower-level stack any
more than `security_cli.py` itself may. Slice 4 (inline
`RECOVERY_REQUIRED` delegation) extends the same proof to
`security_recovery_orchestration.py`: `security_setup_apply.py` also
composes `run_recovery_from_environment()` (inspection only) and is
subject to the identical never-reach-past-the-bridge discipline
`security_cli.py`'s own `recover` subcommand already was.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
CLIENT_MODULE_PATH = ROOT / "src/pfsense_mcp/security_bootstrap_client.py"
ENGINE_MODULE_PATH = ROOT / "src/pfsense_mcp/security_bootstrap_engine.py"
RECOVERY_MODULE_PATH = ROOT / "src/pfsense_mcp/security_bootstrap_recovery.py"
TRANSITION_MODULE_PATH = ROOT / "src/pfsense_mcp/security_auth_transition.py"
COMPOSITION_MODULE_PATH = ROOT / "src/pfsense_mcp/security_admin_composition.py"
ORCHESTRATION_MODULE_PATH = ROOT / "src/pfsense_mcp/security_bootstrap_orchestration.py"
CONFIRMATION_MODULE_PATH = ROOT / "src/pfsense_mcp/security_recovery_confirmation.py"
RECOVERY_ORCHESTRATION_MODULE_PATH = ROOT / "src/pfsense_mcp/security_recovery_orchestration.py"
SETUP_APPLY_MODULE_PATH = ROOT / "src/pfsense_mcp/security_setup_apply.py"
#: POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH mission (2026-08-29):
#: the read_only-profile counterparts of COMPOSITION_MODULE_PATH/
#: RECOVERY_MODULE_PATH, subject to the identical isolation discipline
#: -- only ORCHESTRATION_MODULE_PATH may import from them.
READONLY_COMPOSITION_MODULE_PATH = ROOT / "src/pfsense_mcp/security_readonly_admin_composition.py"
READONLY_RECOVERY_MODULE_PATH = ROOT / "src/pfsense_mcp/security_readonly_bootstrap_recovery.py"

# The seven lower-level module names security_cli.py (and every other
# runtime entry point / tool) must never reference directly -- only
# ORCHESTRATION_MODULE_PATH itself may import from them.
_FORBIDDEN_LOWER_LEVEL_MODULE_NAMES = (
    "security_bootstrap_engine",
    "security_bootstrap_client",
    "security_bootstrap_recovery",
    "security_auth_transition",
    "security_admin_composition",
    "security_recovery_confirmation",
    "security_readonly_admin_composition",
    "security_readonly_bootstrap_recovery",
)

_RUNTIME_ENTRY_POINTS = (
    ROOT / "src/pfsense_mcp/server.py",
    ROOT / "src/pfsense_mcp/application.py",
    ROOT / "src/pfsense_mcp/factory.py",
    ROOT / "src/pfsense_mcp/security_cli.py",
    ROOT / "src/pfsense_mcp/security_doctor.py",
    # security_setup_apply.py composes run_bootstrap_from_environment()
    # for write_protected apply (Slice 3) -- it is legitimately wired to
    # the orchestration bridge (see the dedicated tests below), but must
    # never reach past it into the lower-level stack, exactly like
    # security_cli.py itself.
    ROOT / "src/pfsense_mcp/security_setup_apply.py",
)

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "httpx",
    "requests",
    "socket",
}

_CLIENT_EXPECTED_PUBLIC_SURFACE = {
    "ObservedUser",
    "ObservedApiKey",
    "ObservedAuthSettings",
    "ProvisionedApiKey",
    "BootstrapProvisioningClient",
}

_ENGINE_EXPECTED_PUBLIC_SURFACE = {
    "TargetProfile",
    "ProvisioningOutcome",
    "ProvisioningResult",
    "provision_service_account",
    #: Read-only restart-verification primitive (bootstrap-restart
    #: classification improvement) -- reuses the exact same privilege
    #: derivation/drift comparison provision_service_account() itself
    #: uses; never a mutation. See security_bootstrap_orchestration.py's
    #: build_authoritative_restart_observation().
    "AccountProvisioningObservation",
    "observe_account_provisioning_state",
}

_RECOVERY_EXPECTED_PUBLIC_SURFACE = {
    "RECOVERY_USERNAME",
    "RECOVERY_USER_DESCRIPTION",
    "RECOVERY_KEY_DESCRIPTION",
    "RecoveryDeletionEvidence",
    "revoke_failed_bootstrap_api_key",
    "delete_dedicated_recovery_user",
    "identify_orphan_api_key_candidate",
    "identify_dedicated_recovery_user_candidate",
    #: RESOLVE_UNPROVISIONED_INCIDENT's own read-only evidence-gathering
    #: primitive and its sanitized evidence type -- proves absence rather
    #: than a verified deletion; never makes a mutating call. See
    #: security_operation_journal.py's own RecoveryAction docstring.
    "UnprovisionedIncidentEvidence",
    "identify_unprovisioned_incident_evidence",
}

_TRANSITION_EXPECTED_PUBLIC_SURFACE = {
    "FreshTransport",
    "FreshTransportFactory",
    "AuthTransitionState",
    "MutationDelivery",
    "TransitionFinding",
    "ReconnectPolicy",
    "AuthTransitionResult",
    "BasicAuthAvailability",
    "AuthMethodTransitionCoordinator",
}

_READONLY_COMPOSITION_EXPECTED_PUBLIC_SURFACE = {
    "build_readonly_admin_context",
    "load_readonly_admin_composition_config",
}

_READONLY_RECOVERY_EXPECTED_PUBLIC_SURFACE = {
    "READONLY_RECOVERY_USERNAME",
    "READONLY_RECOVERY_USER_DESCRIPTION",
    "READONLY_RECOVERY_KEY_DESCRIPTION",
    "ReadonlyRecoveryDeletionEvidence",
    "revoke_failed_readonly_bootstrap_api_key",
    "delete_dedicated_readonly_recovery_user",
    "identify_orphan_readonly_api_key_candidate",
    "identify_dedicated_readonly_recovery_user_candidate",
    #: See security_bootstrap_recovery.py's own equivalent addition --
    #: mirrored here for the dedicated read_only account's own namespace.
    "ReadonlyUnprovisionedIncidentEvidence",
    "identify_unprovisioned_readonly_incident_evidence",
}

_ORCHESTRATION_EXPECTED_PUBLIC_SURFACE = {
    "BootstrapOrchestrationError",
    "BootstrapOrchestrationOutcome",
    "BootstrapOrchestrationResult",
    "run_bootstrap",
    "run_bootstrap_from_environment",
    "run_readonly_bootstrap_from_environment",
    #: Builds a fresh, live-evidence-only AuthoritativeRestartObservation
    #: -- read-only, never a mutation. run_bootstrap_from_environment()
    #: calls this itself when a local journal already exists and no
    #: explicit `authoritative` override was supplied; exposed publicly
    #: so tests (and any future caller needing the observation on its
    #: own) never have to reach into a private helper.
    "build_authoritative_restart_observation",
}

_CONFIRMATION_EXPECTED_PUBLIC_SURFACE = {
    "RecoveryIncidentBinding",
    "object_fingerprint",
    "derive_confirmation_token",
    "confirmation_token_matches",
}

_RECOVERY_ORCHESTRATION_EXPECTED_PUBLIC_SURFACE = {
    "RecoveryOrchestrationError",
    "RecoveryOrchestrationOutcome",
    "RecoveryOrchestrationResult",
    "run_recovery_from_environment",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> set[str]:
    tree = _tree(path)
    return {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }


def _public_surface(path: Path) -> set[str]:
    tree = _tree(path)
    return {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    } | {
        node.targets[0].id
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and not node.targets[0].id.startswith("_")
    }


def test_both_modules_exist():
    assert CLIENT_MODULE_PATH.is_file()
    assert ENGINE_MODULE_PATH.is_file()
    assert RECOVERY_MODULE_PATH.is_file()
    assert TRANSITION_MODULE_PATH.is_file()
    assert COMPOSITION_MODULE_PATH.is_file()
    assert CONFIRMATION_MODULE_PATH.is_file()
    assert RECOVERY_ORCHESTRATION_MODULE_PATH.is_file()
    assert READONLY_COMPOSITION_MODULE_PATH.is_file()
    assert READONLY_RECOVERY_MODULE_PATH.is_file()


# --- POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH: the read_only-profile
# counterparts of the composition/recovery isolation tests above ---------


def test_readonly_composition_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(READONLY_COMPOSITION_MODULE_PATH) == _READONLY_COMPOSITION_EXPECTED_PUBLIC_SURFACE


def test_readonly_recovery_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(READONLY_RECOVERY_MODULE_PATH) == _READONLY_RECOVERY_EXPECTED_PUBLIC_SURFACE


def test_readonly_composition_does_not_register_commands_or_call_transport_directly():
    source = READONLY_COMPOSITION_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source
    assert "@app.command" not in source
    assert "add_parser(" not in source
    assert "mcp.tool" not in source
    assert "FastMCP" not in source


def test_readonly_recovery_never_calls_transport_request_or_bootstrap_engine():
    source = READONLY_RECOVERY_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source
    assert "security_bootstrap_engine" not in source
    assert "provision_service_account" not in source


def test_neither_readonly_module_is_in_the_tier1_isolation_exemption_list():
    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_readonly_admin_composition.py" not in source
    assert "security_readonly_bootstrap_recovery.py" not in source


def test_readonly_recovery_uses_a_distinct_fixed_username_from_write_protected():
    """The single most important property of the "duplicate rather than
    parametrize" design decision (see security_readonly_admin_
    composition.py's own module docstring): the two ceremonies' fixed
    account identities must never collide, or a bug could let one
    ceremony's orphan-detection/deletion logic match the other's
    account."""

    from pfsense_mcp.security_bootstrap_recovery import RECOVERY_USERNAME
    from pfsense_mcp.security_readonly_bootstrap_recovery import READONLY_RECOVERY_USERNAME

    assert RECOVERY_USERNAME != READONLY_RECOVERY_USERNAME
    assert RECOVERY_USERNAME == "pfsense-mcp"
    assert READONLY_RECOVERY_USERNAME == "pfsense-mcp-readonly"


def test_neither_module_imports_pfsense_mcp_tier1_or_a_raw_http_library():
    for path in (CLIENT_MODULE_PATH, ENGINE_MODULE_PATH, RECOVERY_MODULE_PATH, TRANSITION_MODULE_PATH):
        imported = _imports(path)
        offending = {
            module
            for module in imported
            for root in _FORBIDDEN_IMPORT_ROOTS
            if module == root or module.startswith(f"{root}.")
        }
        assert not offending, f"{path.name} imports forbidden module(s): {offending}"


def test_no_shipped_runtime_entry_point_references_the_bootstrap_engine_or_client():
    """Requirement 9: no CLI subcommand, no application-startup wiring,
    no tool-registry reference. This is the mechanical proof that the
    only way to reach `provision_service_account()` in this build is a
    direct Python import (a test, or a future, separately-authorized
    phase). Iterates `_FORBIDDEN_LOWER_LEVEL_MODULE_NAMES` (rather than
    a hand-repeated list of asserts) so the two read_only-profile
    modules added by the POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH
    mission are covered automatically, with no separate assertion to
    remember to add."""

    for entry_point in _RUNTIME_ENTRY_POINTS:
        source = entry_point.read_text(encoding="utf-8")
        for name in _FORBIDDEN_LOWER_LEVEL_MODULE_NAMES:
            assert name not in source, f"{entry_point.name} references {name}"


def test_no_tool_under_tools_read_references_the_bootstrap_engine_or_client():
    tools_dir = ROOT / "src/pfsense_mcp/tools"
    for path in sorted(tools_dir.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for name in _FORBIDDEN_LOWER_LEVEL_MODULE_NAMES:
            assert name not in source, f"{path} references {name}"


def test_composition_is_absent_from_all_runtime_cli_doctor_and_tool_imports():
    searched = [*_RUNTIME_ENTRY_POINTS, *sorted((ROOT / "src/pfsense_mcp/tools").rglob("*.py"))]
    for path in searched:
        source = path.read_text(encoding="utf-8")
        assert "security_admin_composition" not in source, path
        assert "security_readonly_admin_composition" not in source, path


def test_composition_does_not_register_commands_or_call_transport_directly():
    source = COMPOSITION_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source
    assert "@app.command" not in source
    assert "add_parser(" not in source
    assert "mcp.tool" not in source
    assert "FastMCP" not in source


def test_engine_never_calls_transport_request_directly():
    """All HTTP must funnel through `security_bootstrap_client.py`'s
    four named operations -- the engine itself must never hold or call
    a bare `Transport`."""

    source = ENGINE_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source


def test_client_is_named_in_get_only_checks_allow_list():
    get_only_check_source = (ROOT / "scripts/get_only_check.py").read_text(encoding="utf-8")
    assert "security_bootstrap_client.py" in get_only_check_source


def test_neither_module_is_in_the_tier1_isolation_exemption_list():
    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_bootstrap_client.py" not in source
    assert "security_bootstrap_engine.py" not in source


def test_client_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(CLIENT_MODULE_PATH) == _CLIENT_EXPECTED_PUBLIC_SURFACE


def test_engine_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(ENGINE_MODULE_PATH) == _ENGINE_EXPECTED_PUBLIC_SURFACE


def test_recovery_public_surface_is_exactly_the_two_closed_operations_and_evidence():
    assert _public_surface(RECOVERY_MODULE_PATH) == _RECOVERY_EXPECTED_PUBLIC_SURFACE


def test_transition_public_surface_is_exactly_the_reviewed_closed_coordinator():
    assert _public_surface(TRANSITION_MODULE_PATH) == _TRANSITION_EXPECTED_PUBLIC_SURFACE


def test_recovery_never_calls_transport_request_or_bootstrap_engine():
    source = RECOVERY_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source
    assert "security_bootstrap_engine" not in source
    assert "provision_service_account" not in source


def test_engine_does_not_construct_its_own_http_transport():
    """The engine must never build a `Transport` (or a Basic-Auth
    variant of one) itself -- both are always caller-supplied
    (`provision_service_account()`'s `admin_transport`/
    `self_service_transport_factory` parameters). Confirms no
    `transport.http`/`transport.mock` import exists in the engine."""

    imported = _imports(ENGINE_MODULE_PATH)
    offending = {
        m for m in imported if m == "pfsense_mcp.transport.http" or m.startswith("pfsense_mcp.transport.http.")
    }
    assert not offending


def test_basic_auth_transport_remains_unwired_from_runtime_entry_points():
    for entry_point in _RUNTIME_ENTRY_POINTS:
        source = entry_point.read_text(encoding="utf-8")
        assert "BasicAuthHttpTransport" not in source, f"{entry_point.name} wires BasicAuthHttpTransport"


# --- ADR-033 CLI Integration Slice 3: security_bootstrap_orchestration.py --


def test_orchestration_module_exists():
    assert ORCHESTRATION_MODULE_PATH.is_file()


def test_orchestration_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(ORCHESTRATION_MODULE_PATH) == _ORCHESTRATION_EXPECTED_PUBLIC_SURFACE


def test_orchestration_never_calls_transport_request_directly():
    source = ORCHESTRATION_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source


def test_orchestration_does_not_register_commands_or_expose_mcp_tools():
    source = ORCHESTRATION_MODULE_PATH.read_text(encoding="utf-8")
    assert "@app.command" not in source
    assert "add_parser(" not in source
    assert "mcp.tool" not in source
    assert "FastMCP" not in source


def test_orchestration_module_does_not_import_pfsense_mcp_tier1_or_a_raw_http_library():
    imported = _imports(ORCHESTRATION_MODULE_PATH)
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"security_bootstrap_orchestration.py imports forbidden module(s): {offending}"


def test_orchestration_module_is_not_in_the_tier1_isolation_exemption_list():
    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_bootstrap_orchestration.py" not in source


def test_security_cli_and_setup_apply_are_the_only_entry_points_wired_to_orchestration():
    """security_cli.py (for `bootstrap`) and security_setup_apply.py (for
    `setup apply`'s write_protected branch, Slice 3) must both reference
    the orchestration module -- they are the two intended gateways --
    while every OTHER runtime entry point, and every tool under tools/,
    must not. Proves `run_bootstrap_from_environment()` is reachable
    only through these two reviewed surfaces, both themselves reachable
    only via the `pfsense-mcp-security` CLI's own public subcommands
    (`bootstrap` directly, `setup apply --capability-posture
    write_protected` indirectly)."""

    cli_path = ROOT / "src/pfsense_mcp/security_cli.py"
    assert "security_bootstrap_orchestration" in cli_path.read_text(encoding="utf-8")
    assert "security_bootstrap_orchestration" in SETUP_APPLY_MODULE_PATH.read_text(encoding="utf-8")

    wired = {cli_path, SETUP_APPLY_MODULE_PATH}
    other_entry_points = [path for path in _RUNTIME_ENTRY_POINTS if path not in wired]
    tools_dir = ROOT / "src/pfsense_mcp/tools"
    for path in [*other_entry_points, *sorted(tools_dir.rglob("*.py"))]:
        assert "security_bootstrap_orchestration" not in path.read_text(encoding="utf-8"), (
            f"{path} references security_bootstrap_orchestration"
        )


def test_security_cli_never_references_any_lower_level_bootstrap_module_by_name():
    """Redundant with test_no_shipped_runtime_entry_point_references_the_bootstrap_engine_or_client
    and test_composition_is_absent_from_all_runtime_cli_doctor_and_tool_imports
    above (which already cover security_cli.py as one of _RUNTIME_ENTRY_POINTS)
    -- kept as an explicit, named assertion of the Slice 3 design decision
    (security_cli.py imports only the orchestration module, never any
    module it composes) rather than relying solely on the pre-existing,
    more general sweep."""

    source = (ROOT / "src/pfsense_mcp/security_cli.py").read_text(encoding="utf-8")
    for name in _FORBIDDEN_LOWER_LEVEL_MODULE_NAMES:
        assert name not in source, f"security_cli.py references {name}"


def test_setup_apply_never_references_any_lower_level_bootstrap_module_by_name():
    """The equivalent explicit assertion for security_setup_apply.py
    (its own Slice 3 design decision): it imports only the orchestration
    module for write_protected apply, never any module that module
    itself composes."""

    source = SETUP_APPLY_MODULE_PATH.read_text(encoding="utf-8")
    for name in _FORBIDDEN_LOWER_LEVEL_MODULE_NAMES:
        assert name not in source, f"security_setup_apply.py references {name}"


def test_orchestration_module_itself_reaches_the_lower_level_stack():
    """The inverse of the above: orchestration.py is *expected* to import
    from the lower-level stack (that is its entire purpose) -- confirms
    this isn't accidentally also isolated into uselessness."""

    imported = _imports(ORCHESTRATION_MODULE_PATH)
    assert "security_admin_composition" in imported
    assert "security_bootstrap_engine" in imported
    assert "security_operation_journal" in imported
    assert "security_readonly_admin_composition" in imported


def test_basic_auth_transport_remains_unwired_from_orchestration_module():
    source = ORCHESTRATION_MODULE_PATH.read_text(encoding="utf-8")
    assert "BasicAuthHttpTransport" not in source


# --- ADR-033 recovery CLI: security_recovery_confirmation.py / security_recovery_orchestration.py --


def test_confirmation_module_never_imports_pfsense_mcp_tier1_or_a_raw_http_library():
    imported = _imports(CONFIRMATION_MODULE_PATH)
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"security_recovery_confirmation.py imports forbidden module(s): {offending}"


def test_confirmation_module_never_calls_transport_request_or_bootstrap_engine():
    source = CONFIRMATION_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source
    assert "security_bootstrap_engine" not in source
    assert "provision_service_account" not in source
    # No `Transport` *import* (the module's docstring discusses the
    # concept in prose, which is fine) -- the real property is that it
    # never constructs or holds one.
    imported = _imports(CONFIRMATION_MODULE_PATH)
    assert not any(module.endswith("transport") or ".transport." in module for module in imported)


def test_confirmation_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(CONFIRMATION_MODULE_PATH) == _CONFIRMATION_EXPECTED_PUBLIC_SURFACE


def test_recovery_orchestration_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(RECOVERY_ORCHESTRATION_MODULE_PATH) == _RECOVERY_ORCHESTRATION_EXPECTED_PUBLIC_SURFACE


def test_recovery_orchestration_never_calls_transport_request_directly():
    source = RECOVERY_ORCHESTRATION_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source


def test_recovery_orchestration_does_not_register_commands_or_expose_mcp_tools():
    source = RECOVERY_ORCHESTRATION_MODULE_PATH.read_text(encoding="utf-8")
    assert "@app.command" not in source
    assert "add_parser(" not in source
    assert "mcp.tool" not in source
    assert "FastMCP" not in source


def test_recovery_orchestration_module_does_not_import_pfsense_mcp_tier1_or_a_raw_http_library():
    imported = _imports(RECOVERY_ORCHESTRATION_MODULE_PATH)
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"security_recovery_orchestration.py imports forbidden module(s): {offending}"


def test_recovery_orchestration_module_is_not_in_the_tier1_isolation_exemption_list():
    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_recovery_orchestration.py" not in source


def test_confirmation_module_is_not_in_the_tier1_isolation_exemption_list():
    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_recovery_confirmation.py" not in source


def test_security_cli_and_setup_apply_are_the_only_entry_points_wired_to_recovery_orchestration():
    """Mirrors test_security_cli_and_setup_apply_are_the_only_entry_points_wired_to_orchestration
    for the `recover` subcommand: security_cli.py (for `recover` itself)
    and security_setup_apply.py (for Slice 4's inline RECOVERY_REQUIRED
    delegation) must both reference security_recovery_orchestration --
    the two intended gateways -- while every OTHER runtime entry point,
    and every tool under tools/, must not."""

    cli_path = ROOT / "src/pfsense_mcp/security_cli.py"
    assert "security_recovery_orchestration" in cli_path.read_text(encoding="utf-8")
    assert "security_recovery_orchestration" in SETUP_APPLY_MODULE_PATH.read_text(encoding="utf-8")

    wired = {cli_path, SETUP_APPLY_MODULE_PATH}
    other_entry_points = [path for path in _RUNTIME_ENTRY_POINTS if path not in wired]
    tools_dir = ROOT / "src/pfsense_mcp/tools"
    for path in [*other_entry_points, *sorted(tools_dir.rglob("*.py"))]:
        assert "security_recovery_orchestration" not in path.read_text(encoding="utf-8"), (
            f"{path} references security_recovery_orchestration"
        )


def test_security_cli_never_references_security_recovery_confirmation_directly():
    source = (ROOT / "src/pfsense_mcp/security_cli.py").read_text(encoding="utf-8")
    assert "security_recovery_confirmation" not in source


def test_setup_apply_never_references_security_recovery_confirmation_directly():
    source = SETUP_APPLY_MODULE_PATH.read_text(encoding="utf-8")
    assert "security_recovery_confirmation" not in source


def test_recovery_orchestration_module_itself_reaches_the_lower_level_recovery_stack():
    """The inverse of the isolation checks above: recovery_orchestration.py
    is *expected* to import from security_admin_composition,
    security_bootstrap_recovery, and security_recovery_confirmation (that
    is its entire purpose) -- confirms this isn't accidentally also
    isolated into uselessness."""

    imported = _imports(RECOVERY_ORCHESTRATION_MODULE_PATH)
    assert "security_admin_composition" in imported
    assert "security_bootstrap_recovery" in imported
    assert "security_recovery_confirmation" in imported
    assert "security_operation_journal" in imported


def test_basic_auth_transport_remains_unwired_from_recovery_orchestration_module():
    source = RECOVERY_ORCHESTRATION_MODULE_PATH.read_text(encoding="utf-8")
    assert "BasicAuthHttpTransport" not in source
