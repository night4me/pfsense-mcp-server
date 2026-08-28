import logging

import pytest

from pfsense_mcp.application import Application


def test_bootstrap_exits_when_required_env_vars_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("PFSENSE_API_URL", raising=False)
    monkeypatch.delenv("PFSENSE_IDENTITY", raising=False)
    monkeypatch.delenv("PFSENSE_API_KEY_FILE", raising=False)
    monkeypatch.setattr("pfsense_mcp.application.LOG_DIR", tmp_path / "state")

    app = Application()
    with pytest.raises(SystemExit) as exc_info:
        app._bootstrap()
    assert exc_info.value.code == 1


def test_configuration_error_points_a_first_time_user_at_the_setup_wizard(monkeypatch, tmp_path, capsys):
    # v1.0 Product/UX arc, front-door fix: a user with no configuration
    # yet should not have to already know the guided wizard exists.
    monkeypatch.delenv("PFSENSE_API_URL", raising=False)
    monkeypatch.delenv("PFSENSE_IDENTITY", raising=False)
    monkeypatch.delenv("PFSENSE_API_KEY_FILE", raising=False)
    monkeypatch.setattr("pfsense_mcp.application.LOG_DIR", tmp_path / "state")

    app = Application()
    with pytest.raises(SystemExit):
        app._bootstrap()

    stderr = capsys.readouterr().err
    assert "configuration error:" in stderr
    assert "pfsense-mcp-security setup" in stderr


def test_bootstrap_exits_when_key_file_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_IDENTITY", "api-mcp-admin")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(tmp_path / "does-not-exist.key"))
    monkeypatch.setenv("PFSENSE_TLS_MODE", "insecure")
    monkeypatch.setattr("pfsense_mcp.application.LOG_DIR", tmp_path / "state")

    app = Application()
    with pytest.raises(SystemExit) as exc_info:
        app._bootstrap()
    assert exc_info.value.code == 1


def test_bootstrap_succeeds_with_valid_config(monkeypatch, tmp_path):
    key_file = tmp_path / "test.key"
    key_file.write_text("fake-key-value\n")
    key_file.chmod(0o600)
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_IDENTITY", "api-mcp-admin")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("PFSENSE_TLS_MODE", "insecure")
    monkeypatch.setattr("pfsense_mcp.application.LOG_DIR", tmp_path / "state")

    app = Application()
    try:
        app._bootstrap()
    finally:
        app.shutdown()


def test_bootstrap_fails_closed_for_unknown_allowed_tool(monkeypatch, tmp_path):
    key_file = tmp_path / "test.key"
    key_file.write_text("fake-key-value\n")
    key_file.chmod(0o600)
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_IDENTITY", "api-mcp-admin")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("PFSENSE_TLS_MODE", "insecure")
    monkeypatch.setenv("PFSENSE_ALLOWED_TOOLS", "pfsense_get_not_a_real_tool")
    monkeypatch.setattr("pfsense_mcp.application.LOG_DIR", tmp_path / "state")

    app = Application()
    with pytest.raises(SystemExit) as exc_info:
        app._bootstrap()
    assert exc_info.value.code == 1


def test_run_cleans_up_logging_when_bootstrap_fails(monkeypatch, tmp_path):
    monkeypatch.delenv("PFSENSE_API_URL", raising=False)
    monkeypatch.setattr("pfsense_mcp.application.LOG_DIR", tmp_path / "state")

    app = Application()
    with pytest.raises(SystemExit):
        app.run()

    assert not [
        handler for handler in logging.getLogger("pfsense_mcp").handlers if hasattr(handler, "_pfsense_mcp_owned")
    ]
