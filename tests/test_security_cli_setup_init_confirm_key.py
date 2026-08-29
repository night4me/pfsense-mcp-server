"""CLI-level tests for `pfsense-mcp-security setup init-confirm-key` --
argument parsing, human/--json formatting, exit-code mapping, and that
the key value itself is never printed to stdout in any mode. Real
`security_setup_confirm_key.create_confirm_key()` orchestration is
exercised directly (not mocked) since it is pure local filesystem I/O
with no pfSense dependency -- see `tests/test_security_setup_confirm_key.py`
for the isolated unit-level adversarial matrix."""

from __future__ import annotations

import io
import json

import pytest

from pfsense_mcp.security_cli import main


def _run(monkeypatch, argv):
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    exit_code = main(argv)
    return exit_code, out.getvalue()


def test_creates_a_key_at_an_explicit_path(monkeypatch, tmp_path):
    target = tmp_path / "confirm.key"
    exit_code, out = _run(monkeypatch, ["setup", "init-confirm-key", "--path", str(target)])
    assert exit_code == 0
    assert "created" in out
    assert str(target) in out
    assert target.is_file()


def test_second_run_on_same_path_is_idempotent_exit_zero(monkeypatch, tmp_path):
    target = tmp_path / "confirm.key"
    _run(monkeypatch, ["setup", "init-confirm-key", "--path", str(target)])
    original = target.read_bytes()

    exit_code, out = _run(monkeypatch, ["setup", "init-confirm-key", "--path", str(target)])
    assert exit_code == 0
    assert "already_exists" in out
    assert target.read_bytes() == original


def test_symlink_path_is_refused_with_nonzero_exit(monkeypatch, tmp_path):
    real = tmp_path / "real.key"
    real.write_text("x")
    link = tmp_path / "link.key"
    link.symlink_to(real)

    exit_code, out = _run(monkeypatch, ["setup", "init-confirm-key", "--path", str(link)])
    assert exit_code == 1
    assert "blocked_unsafe_path" in out


def test_json_output_contains_outcome_and_path_never_the_key_value(monkeypatch, tmp_path):
    target = tmp_path / "confirm.key"
    exit_code, out = _run(monkeypatch, ["setup", "init-confirm-key", "--path", str(target), "--json"])
    assert exit_code == 0
    payload = json.loads(out)
    assert payload["outcome"] == "created"
    assert payload["path"] == str(target)
    key_value = target.read_text().strip()
    assert key_value not in out


def test_human_output_never_contains_the_key_value(monkeypatch, tmp_path):
    target = tmp_path / "confirm.key"
    _, out = _run(monkeypatch, ["setup", "init-confirm-key", "--path", str(target)])
    key_value = target.read_text().strip()
    assert key_value not in out


def test_human_output_prints_the_exact_export_line_to_use(monkeypatch, tmp_path):
    target = tmp_path / "confirm.key"
    _, out = _run(monkeypatch, ["setup", "init-confirm-key", "--path", str(target)])
    assert f'export PFSENSE_SETUP_CONFIRM_KEY_FILE="{target}"' in out


def test_no_path_flag_uses_the_default_location(monkeypatch, tmp_path):
    # Redirect $HOME so the default path stays inside tmp_path rather
    # than touching the real developer/CI machine's home directory.
    monkeypatch.setenv("HOME", str(tmp_path))
    import pfsense_mcp.security_setup_confirm_key as confirm_key_module

    monkeypatch.setattr(confirm_key_module, "DEFAULT_CONFIRM_KEY_FILE", tmp_path / "state" / "setup-confirm.key")

    exit_code, _out = _run(monkeypatch, ["setup", "init-confirm-key"])
    assert exit_code == 0
    assert (tmp_path / "state" / "setup-confirm.key").is_file()


def test_help_exits_zero():
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "init-confirm-key", "--help"])
    assert excinfo.value.code == 0
