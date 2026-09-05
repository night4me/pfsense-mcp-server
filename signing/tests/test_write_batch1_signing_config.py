"""Regression tests for the 2026-09-05 `write_batch1_signing.py` config
fix: `_load_config()` used to require all 7 `PFSENSE_SIGNING_SHAPE_A_*`
env vars regardless of which subcommand actually ran, so an operator
running only `sign-authorization` was forced to also export
confirmation-side vars (and vice versa) purely to satisfy the other
subcommand's unrelated fields. Split into `_load_authorization_config()`
(4 vars) and `_load_confirmation_config()` (4 vars), each called only by
its own subcommand -- these tests prove that split actually holds: each
subcommand's config loader succeeds with *only* its own vars exported,
with no placeholder/dummy value required for the other subcommand's
vars."""

from __future__ import annotations

import os

import pytest

from signing.write_batch1_signing import (
    SigningError,
    _AuthorizationSigningConfig,
    _ConfirmationSigningConfig,
    _load_authorization_config,
    _load_confirmation_config,
    sign_authorization_command,
    sign_confirmation_command,
)

_AUTHORIZATION_VARS = {
    "PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY": "/tmp/does-not-matter-artifacts",
    "PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE": "/tmp/does-not-matter-authz-authority.json",
    "PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_PRIVATE_KEY_FILE": "/tmp/does-not-matter-authz-key.json",
    "PFSENSE_SIGNING_SHAPE_A_PREVIEW_INTEGRITY_KEY_FILE": "/tmp/does-not-matter-preview-integrity.json",
}

_CONFIRMATION_VARS = {
    "PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY": "/tmp/does-not-matter-artifacts",
    "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE": "/tmp/does-not-matter-conf-authority.json",
    "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_PRIVATE_KEY_FILE": "/tmp/does-not-matter-conf-key.json",
    "PFSENSE_SIGNING_SHAPE_A_PENDING_INTEGRITY_KEY_FILE": "/tmp/does-not-matter-pending-integrity.json",
}

_ALL_SHAPE_A_SIGNING_VARS = (
    "PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY",
    "PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE",
    "PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_PRIVATE_KEY_FILE",
    "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE",
    "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_PRIVATE_KEY_FILE",
    "PFSENSE_SIGNING_SHAPE_A_PREVIEW_INTEGRITY_KEY_FILE",
    "PFSENSE_SIGNING_SHAPE_A_PENDING_INTEGRITY_KEY_FILE",
)


def _clear_all(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ALL_SHAPE_A_SIGNING_VARS:
        monkeypatch.delenv(name, raising=False)


def test_authorization_config_loads_with_only_authorization_vars_set(monkeypatch):
    _clear_all(monkeypatch)
    for name, value in _AUTHORIZATION_VARS.items():
        monkeypatch.setenv(name, value)

    config = _load_authorization_config()

    assert isinstance(config, _AuthorizationSigningConfig)
    assert str(config.artifact_base_directory) == _AUTHORIZATION_VARS["PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY"]


def test_confirmation_config_loads_with_only_confirmation_vars_set(monkeypatch):
    _clear_all(monkeypatch)
    for name, value in _CONFIRMATION_VARS.items():
        monkeypatch.setenv(name, value)

    config = _load_confirmation_config()

    assert isinstance(config, _ConfirmationSigningConfig)
    assert str(config.artifact_base_directory) == _CONFIRMATION_VARS["PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY"]


def test_authorization_config_never_requires_confirmation_only_vars(monkeypatch):
    """The literal defect: confirmation-only vars must never be read by
    the authorization loader, proven both by success without them and by
    directly checking they are absent from the environment throughout."""

    _clear_all(monkeypatch)
    for name, value in _AUTHORIZATION_VARS.items():
        monkeypatch.setenv(name, value)

    _load_authorization_config()

    for name in (
        "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE",
        "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_PRIVATE_KEY_FILE",
        "PFSENSE_SIGNING_SHAPE_A_PENDING_INTEGRITY_KEY_FILE",
    ):
        assert name not in os.environ


def test_confirmation_config_never_requires_authorization_only_vars(monkeypatch):
    _clear_all(monkeypatch)
    for name, value in _CONFIRMATION_VARS.items():
        monkeypatch.setenv(name, value)

    _load_confirmation_config()

    for name in (
        "PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE",
        "PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_PRIVATE_KEY_FILE",
        "PFSENSE_SIGNING_SHAPE_A_PREVIEW_INTEGRITY_KEY_FILE",
    ):
        assert name not in os.environ


def test_authorization_config_still_fails_closed_on_its_own_missing_var(monkeypatch):
    _clear_all(monkeypatch)
    for name, value in _AUTHORIZATION_VARS.items():
        if name == "PFSENSE_SIGNING_SHAPE_A_PREVIEW_INTEGRITY_KEY_FILE":
            continue
        monkeypatch.setenv(name, value)

    with pytest.raises(SigningError, match="PFSENSE_SIGNING_SHAPE_A_PREVIEW_INTEGRITY_KEY_FILE"):
        _load_authorization_config()


def test_confirmation_config_still_fails_closed_on_its_own_missing_var(monkeypatch):
    _clear_all(monkeypatch)
    for name, value in _CONFIRMATION_VARS.items():
        if name == "PFSENSE_SIGNING_SHAPE_A_PENDING_INTEGRITY_KEY_FILE":
            continue
        monkeypatch.setenv(name, value)

    with pytest.raises(SigningError, match="PFSENSE_SIGNING_SHAPE_A_PENDING_INTEGRITY_KEY_FILE"):
        _load_confirmation_config()


def test_sign_authorization_command_with_no_capabilities_needs_no_confirmation_vars(monkeypatch):
    """End-to-end through the actual subcommand entry point (not just the
    loader) with an empty capability list -- config loading is the only
    thing that runs, and it must succeed without a single confirmation-
    side var exported."""

    _clear_all(monkeypatch)
    for name, value in _AUTHORIZATION_VARS.items():
        monkeypatch.setenv(name, value)

    assert sign_authorization_command([]) == 0


def test_sign_confirmation_command_with_no_capabilities_needs_no_authorization_vars(monkeypatch):
    _clear_all(monkeypatch)
    for name, value in _CONFIRMATION_VARS.items():
        monkeypatch.setenv(name, value)

    assert sign_confirmation_command([]) == 0
