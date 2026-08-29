"""Focused tests for `security_readonly_admin_composition.py` -- the
`read_only`-profile counterpart of `test_security_admin_composition.py`.

Deliberately narrower than the write_protected test file: `provision_
service_account()`/`observe_account_provisioning_state()` (the actual
engine logic) are already exhaustively tested against
`TargetProfile.READ_ONLY` in `tests/test_security_bootstrap_engine.py`
-- this file only proves the *composition* layer this mission adds:
config loading, the distinct env var / fixed account identity, and
(most importantly) that the two ceremonies' namespaces/journals can
never collide."""

from __future__ import annotations

from pathlib import Path

import pytest

from pfsense_mcp.security_admin_composition import AdminCompositionError, build_admin_context
from pfsense_mcp.security_readonly_admin_composition import (
    build_readonly_admin_context,
    load_readonly_admin_composition_config,
)


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


@pytest.fixture
def readonly_admin_env(tmp_path: Path) -> dict[str, str]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    schema = tmp_path / "schema.json"
    fixture = Path(__file__).parent / "fixtures" / "pfsense_openapi_schema_trimmed.json"
    _write_secure(schema, fixture.read_bytes())
    _write_secure(tmp_path / "admin-api-key", b"synthetic-admin-key\n")
    _write_secure(tmp_path / "admin-password", b"synthetic-admin-password\n")
    _write_secure(tmp_path / "journal-key", b"j" * 32)
    _write_secure(tmp_path / "ca.pem", b"synthetic-ca", mode=0o644)
    return {
        "PFSENSE_API_URL": "https://lab.example.invalid",
        "PFSENSE_IDENTITY": "lab-appliance-one",
        "PFSENSE_API_KEY_FILE": str(tmp_path / "admin-api-key"),
        "PFSENSE_TLS_MODE": "auto",
        "PFSENSE_TLS_CA_FILE": str(tmp_path / "ca.pem"),
        "PFSENSE_API_VERSION": "v2",
        "PFSENSE_ADMIN_USERNAME": "admin",
        "PFSENSE_ADMIN_PASSWORD_FILE": str(tmp_path / "admin-password"),
        "PFSENSE_READONLY_SERVICE_API_KEY_FILE": str(custody / "pfsense-mcp-readonly.key"),
        "PFSENSE_ADMIN_STATE_DIR": str(state),
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE": str(tmp_path / "journal-key"),
        "PFSENSE_ADMIN_SCHEMA_FILE": str(schema),
        "PFSENSE_ADMIN_SCHEMA_VERSION": "restapi-v2.10",
        "PFSENSE_RESTAPI_PACKAGE_VERSION": "2.10.0",
    }


@pytest.fixture
def write_protected_admin_env(readonly_admin_env: dict[str, str], tmp_path: Path) -> dict[str, str]:
    """The exact same target/admin config, but with the write_protected
    custody var instead -- used to prove the two ceremonies' namespaces
    never collide even when every other input is identical."""

    env = dict(readonly_admin_env)
    del env["PFSENSE_READONLY_SERVICE_API_KEY_FILE"]
    env["PFSENSE_SERVICE_API_KEY_FILE"] = str(tmp_path / "custody" / "pfsense-mcp.key")
    return env


def test_build_readonly_admin_context_succeeds_with_valid_env(readonly_admin_env):
    context = build_readonly_admin_context(readonly_admin_env)
    assert context.binding.account_identity == "pfsense-mcp-readonly"
    assert context.binding.approved_profile == "read_only"


def test_readonly_context_config_is_readonly_specific(readonly_admin_env):
    config = load_readonly_admin_composition_config(readonly_admin_env)
    assert config.service_api_key_file == Path(readonly_admin_env["PFSENSE_READONLY_SERVICE_API_KEY_FILE"])


def test_missing_readonly_service_key_file_var_is_rejected(readonly_admin_env):
    env = dict(readonly_admin_env)
    del env["PFSENSE_READONLY_SERVICE_API_KEY_FILE"]
    with pytest.raises(AdminCompositionError):
        build_readonly_admin_context(env)


def test_write_protected_service_key_file_var_alone_is_not_sufficient(readonly_admin_env):
    """Reusing write_protected's own env var name must never silently
    satisfy the read_only composition -- the two are deliberately
    distinct names precisely so this cannot happen."""

    env = dict(readonly_admin_env)
    key_file = env.pop("PFSENSE_READONLY_SERVICE_API_KEY_FILE")
    env["PFSENSE_SERVICE_API_KEY_FILE"] = key_file
    with pytest.raises(AdminCompositionError):
        build_readonly_admin_context(env)


def test_forbidden_identity_overrides_are_still_rejected(readonly_admin_env):
    env = dict(readonly_admin_env)
    env["PFSENSE_SERVICE_ACCOUNT_USERNAME"] = "attacker-chosen-name"
    with pytest.raises(AdminCompositionError):
        build_readonly_admin_context(env)


def test_insecure_tls_is_rejected(readonly_admin_env):
    env = dict(readonly_admin_env)
    env["PFSENSE_TLS_MODE"] = "insecure"
    with pytest.raises(AdminCompositionError):
        build_readonly_admin_context(env)


def test_namespace_never_collides_with_write_protected_for_the_identical_target(
    readonly_admin_env, write_protected_admin_env
):
    """The single most important property this module's design exists
    to guarantee: even with byte-identical target/admin configuration,
    the read_only and write_protected ceremonies compute different
    namespaces (and therefore different journal/lock/custody paths),
    because the namespace hash includes the fixed account_identity/
    approved_profile, which differ by construction."""

    readonly_context = build_readonly_admin_context(readonly_admin_env)
    write_protected_context = build_admin_context(write_protected_admin_env)

    assert readonly_context.binding.namespace != write_protected_context.binding.namespace
    assert readonly_context.journal_path != write_protected_context.journal_path
    assert readonly_context.lock_path != write_protected_context.lock_path
    assert readonly_context.binding.account_identity != write_protected_context.binding.account_identity
    assert readonly_context.binding.approved_profile != write_protected_context.binding.approved_profile


def test_readonly_freshness_gate_uses_the_read_only_privilege_set_not_write_protected(
    readonly_admin_env, write_protected_admin_env, tmp_path
):
    """Positive proof that `build_readonly_admin_context()` derives its
    freshness gate from `read_profile_requirements()`, never a stray
    reuse of `write_protected_profile_requirements()`: with the one
    WRITE-only path (`PATCH /api/v2/firewall/alias`) stripped from the
    schema, the read_only composition must still build successfully
    (it never needed that path), while the write_protected composition
    -- built against the identical stripped schema -- must fail closed
    (it does need it)."""

    import json

    fixture_path = Path(readonly_admin_env["PFSENSE_ADMIN_SCHEMA_FILE"])
    schema = json.loads(fixture_path.read_bytes())
    paths = schema.get("paths", {})
    alias_path = paths.get("/api/v2/firewall/alias")
    assert isinstance(alias_path, dict) and "patch" in alias_path, "fixture schema shape changed unexpectedly"
    del alias_path["patch"]
    stripped = json.dumps(schema).encode()

    readonly_stripped_schema = tmp_path / "readonly-stripped-schema.json"
    readonly_stripped_schema.write_bytes(stripped)
    readonly_stripped_schema.chmod(0o600)
    readonly_env = dict(readonly_admin_env)
    readonly_env["PFSENSE_ADMIN_SCHEMA_FILE"] = str(readonly_stripped_schema)
    context = build_readonly_admin_context(readonly_env)
    assert context.binding.approved_profile == "read_only"

    write_protected_stripped_schema = tmp_path / "write-protected-stripped-schema.json"
    write_protected_stripped_schema.write_bytes(stripped)
    write_protected_stripped_schema.chmod(0o600)
    write_protected_env = dict(write_protected_admin_env)
    write_protected_env["PFSENSE_ADMIN_SCHEMA_FILE"] = str(write_protected_stripped_schema)
    with pytest.raises(AdminCompositionError):
        build_admin_context(write_protected_env)
