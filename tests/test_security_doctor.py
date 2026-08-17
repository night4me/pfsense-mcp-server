"""Focused tests for `pfsense_mcp.security_doctor` -- the read-only
Tier 1 ceremony readiness check behind `pfsense-mcp-security doctor`.
Mirrors `tests/test_security_discovery.py`'s established fixture style
(temp store + key material + fake witness anchor via monkeypatch) and
reuses its exact fixtures, since this module's witness check is a thin
wrapper around `discover_anchor_assurance()` and needs no fixtures of
its own for that part.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pfsense_mcp.security_doctor import (
    _ARTIFACT_PATH_CHECKS,
    CheckStatus,
    run_doctor_checks,
)
from pfsense_mcp.tier1 import production_runtime
from tests.test_security_discovery import (
    _WITNESS_ENV,
    _FakeAnchor,
    _patch_witness_anchor,
    _provisioned_store_env,
)

_ARTIFACT_ENV_VARS = tuple(env_var_name for _, _, env_var_name in _ARTIFACT_PATH_CHECKS)


def test_artifact_path_env_var_names_match_production_runtime():
    """Guards against silent drift: security_doctor.py deliberately
    duplicates these four env var name strings (rather than importing
    production_runtime.py, to stay outside tier1's isolation boundary)
    -- if production_runtime.py's own names ever change, this test
    must fail loudly, not the doctor command silently checking the
    wrong variable."""

    assert set(_ARTIFACT_ENV_VARS) == {
        production_runtime._AUTHORIZATION_INBOX_FILE_VAR,
        production_runtime._CONFIRMATION_PENDING_FILE_VAR,
        production_runtime._CONFIRMATION_SIGNED_FILE_VAR,
        production_runtime._AUTHORIZATION_PREVIEW_FILE_VAR,
    }


def _exchange_env(tmp_path: Path) -> dict[str, str]:
    exchange_dir = tmp_path / "exchange"
    exchange_dir.mkdir()
    return {
        production_runtime._AUTHORIZATION_INBOX_FILE_VAR: str(exchange_dir / "authorization-signed.bin"),
        production_runtime._CONFIRMATION_PENDING_FILE_VAR: str(exchange_dir / "confirmation-pending.bin"),
        production_runtime._CONFIRMATION_SIGNED_FILE_VAR: str(exchange_dir / "confirmation-signed.bin"),
        production_runtime._AUTHORIZATION_PREVIEW_FILE_VAR: str(exchange_dir / "authorization-preview.bin"),
    }


def _verified_witness_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, value: int = 2) -> dict[str, str]:
    env = {**_provisioned_store_env(tmp_path, value=value, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(value))
    return env


# ---------------------------------------------------------------------------
# 1. Entirely unconfigured
# ---------------------------------------------------------------------------


def test_entirely_unconfigured_is_not_ready_with_not_configured_status():
    result = run_doctor_checks(env={})

    assert result.ready is False
    assert len(result.checks) == 5
    assert all(check.status is CheckStatus.NOT_CONFIGURED for check in result.checks)


# ---------------------------------------------------------------------------
# 2. Clean, fully configured, witness-verified -> READY
# ---------------------------------------------------------------------------


def test_clean_configuration_with_verified_witness_is_ready(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}

    result = run_doctor_checks(env)

    assert result.ready is True
    assert all(check.status is CheckStatus.PASS for check in result.checks)


def test_ready_result_is_deterministic(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}

    first = run_doctor_checks(env)
    second = run_doctor_checks(env)

    assert first == second


# ---------------------------------------------------------------------------
# 3. Stale artifact detection
# ---------------------------------------------------------------------------


def test_stale_artifact_at_confirmation_signed_path_fails_that_check_only(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}
    stale_path = Path(env[production_runtime._CONFIRMATION_SIGNED_FILE_VAR])
    stale_path.write_bytes(b"leftover from a prior ceremony")

    result = run_doctor_checks(env)

    assert result.ready is False
    by_id = {check.check_id: check for check in result.checks}
    assert by_id["artifact_exchange.confirmation_signed"].status is CheckStatus.FAIL
    assert "already exists" in by_id["artifact_exchange.confirmation_signed"].detail
    # Every other artifact-path check is unaffected.
    assert by_id["artifact_exchange.authorization_inbox"].status is CheckStatus.PASS
    assert by_id["artifact_exchange.confirmation_pending"].status is CheckStatus.PASS
    assert by_id["artifact_exchange.authorization_preview"].status is CheckStatus.PASS


def test_stale_broken_symlink_counts_as_present(monkeypatch, tmp_path):
    """Mirrors production_runtime.py's own _artifact_present() lexists
    semantics exactly -- a broken symlink (target missing) must still
    be reported as a stale artifact, never silently treated as an
    empty handoff location."""

    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}
    inbox_path = Path(env[production_runtime._AUTHORIZATION_INBOX_FILE_VAR])
    inbox_path.symlink_to(inbox_path.parent / "does-not-exist-target")

    result = run_doctor_checks(env)

    by_id = {check.check_id: check for check in result.checks}
    assert by_id["artifact_exchange.authorization_inbox"].status is CheckStatus.FAIL


def test_doctor_never_deletes_a_stale_artifact(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}
    stale_path = Path(env[production_runtime._CONFIRMATION_SIGNED_FILE_VAR])
    stale_path.write_bytes(b"leftover")

    run_doctor_checks(env)

    assert stale_path.exists()
    assert stale_path.read_bytes() == b"leftover"


# ---------------------------------------------------------------------------
# 4. Missing/unwritable exchange directory
# ---------------------------------------------------------------------------


def test_missing_exchange_directory_fails_with_actionable_detail(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}
    missing_dir = tmp_path / "does-not-exist"
    env[production_runtime._CONFIRMATION_PENDING_FILE_VAR] = str(missing_dir / "confirmation-pending.bin")

    result = run_doctor_checks(env)

    by_id = {check.check_id: check for check in result.checks}
    check = by_id["artifact_exchange.confirmation_pending"]
    assert check.status is CheckStatus.FAIL
    assert "does not exist" in check.detail


def test_relative_path_fails_closed(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}
    env[production_runtime._AUTHORIZATION_PREVIEW_FILE_VAR] = "relative/path.bin"

    result = run_doctor_checks(env)

    by_id = {check.check_id: check for check in result.checks}
    check = by_id["artifact_exchange.authorization_preview"]
    assert check.status is CheckStatus.FAIL
    assert "absolute path" in check.detail


# ---------------------------------------------------------------------------
# 5. Partial configuration
# ---------------------------------------------------------------------------


def test_partial_artifact_configuration_is_not_ready(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}
    del env[production_runtime._AUTHORIZATION_PREVIEW_FILE_VAR]

    result = run_doctor_checks(env)

    assert result.ready is False
    by_id = {check.check_id: check for check in result.checks}
    assert by_id["artifact_exchange.authorization_preview"].status is CheckStatus.NOT_CONFIGURED
    assert by_id["artifact_exchange.authorization_inbox"].status is CheckStatus.PASS


# ---------------------------------------------------------------------------
# 6. Witness readiness
# ---------------------------------------------------------------------------


def test_witness_mismatch_is_not_ready(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(value=3))  # live witness disagrees with persisted baseline (2)

    result = run_doctor_checks(env)

    assert result.ready is False
    by_id = {check.check_id: check for check in result.checks}
    assert by_id["witness_readiness"].status is CheckStatus.FAIL
    assert "provisioned_mismatch" in by_id["witness_readiness"].detail


def test_witness_unreachable_is_not_ready(monkeypatch, tmp_path):
    import pfsense_mcp.security_discovery as discovery_module

    env = {**_exchange_env(tmp_path), **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}

    class _UnreachableAnchor:
        def read(self) -> int:
            raise ConnectionError("simulated witness daemon unreachable")

        def advance(self, *, expected_current: int) -> int:
            raise AssertionError("must never be called")

    monkeypatch.setattr(discovery_module, "_build_read_only_witness_client", lambda config: _UnreachableAnchor())

    result = run_doctor_checks(env)

    assert result.ready is False
    by_id = {check.check_id: check for check in result.checks}
    assert by_id["witness_readiness"].status is CheckStatus.FAIL


def test_doctor_never_calls_witness_advance(monkeypatch, tmp_path):
    """_FakeAnchor.advance() raises if ever called -- proof, not just
    an omission, that doctor never mutates witness state, mirroring
    test_security_discovery.py's own established pattern."""

    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}

    result = run_doctor_checks(env)  # would raise via _FakeAnchor.advance() if doctor ever mutated

    assert result.ready is True


def test_ready_requires_both_artifact_paths_and_witness(monkeypatch, tmp_path):
    """Clean artifact paths alone are not sufficient -- an unconfigured
    or broken witness must also make the overall result NOT READY."""

    env = _exchange_env(tmp_path)  # no witness/store config at all

    result = run_doctor_checks(env)

    assert result.ready is False
    by_id = {check.check_id: check for check in result.checks}
    assert by_id["witness_readiness"].status is CheckStatus.NOT_CONFIGURED
    assert all(
        by_id[check_id].status is CheckStatus.PASS
        for check_id in (
            "artifact_exchange.authorization_inbox",
            "artifact_exchange.confirmation_pending",
            "artifact_exchange.confirmation_signed",
            "artifact_exchange.authorization_preview",
        )
    )


# ---------------------------------------------------------------------------
# 7. No secrets in output
# ---------------------------------------------------------------------------


def test_no_check_detail_contains_witness_client_key_material(monkeypatch, tmp_path):
    env = {**_exchange_env(tmp_path), **_verified_witness_env(monkeypatch, tmp_path)}

    result = run_doctor_checks(env)

    for check in result.checks:
        assert "-----BEGIN" not in check.detail
        assert env.get(production_runtime._WITNESS_CLIENT_KEY_VAR, "") not in check.detail
