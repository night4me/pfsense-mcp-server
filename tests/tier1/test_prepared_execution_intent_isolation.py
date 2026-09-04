from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
MODULE = ROOT / "src/pfsense_mcp/tier1/prepared_execution_intent.py"

_FORBIDDEN_MODULE_FRAGMENTS = {
    "security_authorization",
    "security_plan",
    "security_plan_freshness",
    "authorization_consumption",
    "contract",
    "store",
    "confirmation",
    "execution_coordinator",
    "executor",
    "state_machine",
    "write_api_client",
    "write_endpoints",
    "tools",
    "server",
}
_FORBIDDEN_CALLS = {
    "create",
    "confirm",
    "consume",
    "execute",
    "transition",
    "send_for_tier1",
    "register",
    "tool",
}


def _tree() -> ast.Module:
    return ast.parse(MODULE.read_text(encoding="utf-8"), filename=str(MODULE))


def test_module_exists_and_has_exact_public_surface():
    assert MODULE.is_file()
    tree = _tree()
    public = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    } | {
        target.id
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and not target.id.startswith("_")
    }
    assert public == {
        "PREPARED_EXECUTION_INTENT_SCHEMA_VERSION",
        "PreparedExecutionIntentV1",
        "prepared_execution_intent_payload_of",
        "compute_execution_intent_digest",
    }


def test_module_imports_only_capability_canonical_and_errors_from_project():
    imported = {node.module or "" for node in ast.walk(_tree()) if isinstance(node, ast.ImportFrom)}
    project_imports = {
        module for module in imported if module.startswith("pfsense_mcp") or module in {"canonical", "errors"}
    }
    assert project_imports == {"pfsense_mcp.capabilities", "canonical", "errors"}


def test_module_has_no_forbidden_dependency_or_mutating_call():
    tree = _tree()
    imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} | {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    }
    assert not {module for module in imports if any(fragment in module for fragment in _FORBIDDEN_MODULE_FRAGMENTS)}
    calls = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    } | {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert calls.isdisjoint(_FORBIDDEN_CALLS)


def test_module_reuses_canonical_owner_and_defines_no_hash_or_json_path():
    tree = _tree()
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "") == "canonical"
        for alias in node.names
    }
    assert {"CanonicalValue", "DigestPurpose", "digest_value", "validate_canonical_value"} <= imported_names
    direct_imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert direct_imports.isdisjoint({"hashlib", "json"})
    called = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "dumps" not in called


def test_digest_function_hard_codes_execution_domain_not_caller_input():
    function = next(
        node
        for node in ast.iter_child_nodes(_tree())
        if isinstance(node, ast.FunctionDef) and node.name == "compute_execution_intent_digest"
    )
    assert [argument.arg for argument in function.args.args] == ["intent"]
    attributes = {node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)}
    assert "EXECUTION_INTENT" in attributes
    names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
    assert "_DIGEST_CONTEXT" in names


def test_module_is_not_imported_by_production_construction_sites():
    # W3 Slice 5A: artifact_exchange.py's AuthorizationPreview builder
    # calls the existing compute_execution_intent_digest() on an
    # already-constructed PreparedExecutionIntentV1 it never builds
    # itself -- reuse of the one canonical digest function, not a new
    # construction site or a second implementation (see
    # authorization_preview_from_preparation()'s own docstring and
    # ADR-028's explicit "do not create a second execution-intent
    # canonicalization implementation" instruction).
    #
    # ADR-037 Batch 1 (2026-09-04, owner) adds six further reviewed
    # construction sites: `write_execution_core.py` (the generic execution
    # core the five new capabilities share, mirroring
    # `alias_description_execution.py`'s own reason) and each of the five
    # capability adapter modules themselves (mirroring
    # `alias_description.py`'s own reason -- each constructs
    # `PreparedExecutionIntentV1` inside its own `prepare()`, exactly like
    # `AliasDescriptionPreparerV1.prepare()` already does).
    allowed = {
        "alias_description.py",
        "alias_description_execution.py",
        "artifact_exchange.py",
        "write_execution_core.py",
        "ntp_time_server_prefer.py",
        "ntp_settings_observability.py",
        "log_display_preferences.py",
        "log_retention_settings.py",
        "system_timezone_write.py",
    }
    offenders: list[str] = []
    production = ROOT / "src/pfsense_mcp"
    for path in production.rglob("*.py"):
        if path == MODULE or path.name in allowed or (path.name == "__init__.py" and path.parent.name == "tier1"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} | {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        }
        if any(module.endswith("prepared_execution_intent") for module in imports):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []
