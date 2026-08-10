"""Unit tests for scripts/tier1_store_bootstrap.py.

Everything here runs fully offline against synthetic `tmp_path` stores --
no network, no credentials, and no real production store path is ever
referenced.
"""

from __future__ import annotations

import json
import os

import tier1_store_bootstrap

_MATERIAL_HEX = "ef" * 32


def _write_key_file(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({"key_id": "integrity-cli-0001", "epoch": 0, "material_hex": _MATERIAL_HEX}))
    os.chmod(path, 0o600)


def test_status_reports_unconfigured_and_creates_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PFSENSE_TIER1_STORE_PATH", raising=False)
    monkeypatch.delenv("PFSENSE_TIER1_STORE_KEY_FILE", raising=False)

    exit_code = tier1_store_bootstrap.main([])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "not configured" in captured.out
    assert list(tmp_path.iterdir()) == []


def test_status_reports_configured_but_not_yet_provisioned_and_creates_nothing(tmp_path, monkeypatch, capsys):
    store_path = tmp_path / "store" / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", str(store_path))
    monkeypatch.setenv("PFSENSE_TIER1_STORE_KEY_FILE", str(key_file))

    exit_code = tier1_store_bootstrap.main([])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "not yet provisioned" in captured.out
    assert not store_path.exists()
    assert not store_path.parent.exists()


def test_status_reports_partial_configuration_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", str(tmp_path / "store" / "anchor.sqlite3"))
    monkeypatch.delenv("PFSENSE_TIER1_STORE_KEY_FILE", raising=False)

    exit_code = tier1_store_bootstrap.main([])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error" in captured.err


def test_provision_without_handle_is_refused(tmp_path, monkeypatch, capsys):
    store_path = tmp_path / "store" / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", str(store_path))
    monkeypatch.setenv("PFSENSE_TIER1_STORE_KEY_FILE", str(key_file))

    exit_code = tier1_store_bootstrap.main(["--provision", "5", "--yes-i-understand"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--handle" in captured.err
    assert not store_path.exists()


def test_provision_without_confirmation_is_refused(tmp_path, monkeypatch, capsys):
    store_path = tmp_path / "store" / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", str(store_path))
    monkeypatch.setenv("PFSENSE_TIER1_STORE_KEY_FILE", str(key_file))

    exit_code = tier1_store_bootstrap.main(["--provision", "5", "--handle", "0xTEST"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--yes-i-understand" in captured.err
    assert not store_path.exists()


def test_provision_requires_configuration(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PFSENSE_TIER1_STORE_PATH", raising=False)
    monkeypatch.delenv("PFSENSE_TIER1_STORE_KEY_FILE", raising=False)

    exit_code = tier1_store_bootstrap.main(["--provision", "5", "--handle", "0xTEST", "--yes-i-understand"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "not configured" in captured.err


def test_full_provision_cycle_via_cli(tmp_path, monkeypatch, capsys):
    store_path = tmp_path / "store" / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    store_path.parent.mkdir(mode=0o700, parents=True)
    os.chmod(store_path.parent, 0o700)
    _write_key_file(key_file)
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", str(store_path))
    monkeypatch.setenv("PFSENSE_TIER1_STORE_KEY_FILE", str(key_file))

    exit_code = tier1_store_bootstrap.main(["--provision", "42", "--handle", "0xCLITEST", "--yes-i-understand"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "provisioned baseline=42 handle=0xCLITEST" in captured.out
    assert store_path.exists()

    status_exit = tier1_store_bootstrap.main([])
    status_captured = capsys.readouterr()
    assert status_exit == 0
    assert "seeded:          True" in status_captured.out
    assert "baseline:        42" in status_captured.out
    assert "complete:        True" in status_captured.out
    assert "handle:          0xCLITEST" in status_captured.out

    second_exit = tier1_store_bootstrap.main(["--provision", "99", "--handle", "0xSECOND", "--yes-i-understand"])
    second_captured = capsys.readouterr()
    assert second_exit == 1
    assert "provisioning refused" in second_captured.err
