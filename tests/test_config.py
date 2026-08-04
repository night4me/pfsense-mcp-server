import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.config import ConfigurationError, load_api_key, load_config
from pfsense_mcp.tls import TLSMode


def _base_env(key_file) -> dict[str, str]:
    return {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": str(key_file),
    }


def test_missing_key_file_fails_closed(tmp_path):
    with pytest.raises(ConfigurationError, match="not found"):
        load_config(_base_env(tmp_path / "does-not-exist.key"))


def test_unreadable_key_file_fails_closed(tmp_path):
    key_file = tmp_path / "unreadable.key"
    key_file.write_text("fake-key-value\n")
    key_file.chmod(0o000)
    try:
        with pytest.raises(ConfigurationError, match="not readable"):
            load_config(_base_env(key_file))
    finally:
        key_file.chmod(0o600)


def test_empty_key_file_fails_closed(tmp_path):
    key_file = tmp_path / "empty.key"
    key_file.write_text("")
    config = load_config(_base_env(key_file))
    with pytest.raises(ConfigurationError, match="empty"):
        load_api_key(config)


def test_key_file_only_reads_first_line(tmp_path):
    key_file = tmp_path / "multiline.key"
    key_file.write_text("first-line-key\nsecond-line-should-be-ignored\n")
    config = load_config(_base_env(key_file))
    key = load_api_key(config)
    assert key == "first-line-key"


def test_missing_required_env_var_fails_closed(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    del env["PFSENSE_IDENTITY"]
    with pytest.raises(ConfigurationError, match="PFSENSE_IDENTITY"):
        load_config(env)


def test_default_tls_mode_is_strict(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    assert load_config(_base_env(key_file)).tls_mode is TLSMode.STRICT


def test_insecure_tls_requires_explicit_opt_in(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_TLS_MODE"] = "insecure"
    assert load_config(env).tls_mode is TLSMode.INSECURE


def test_invalid_tls_mode_rejected(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_TLS_MODE"] = "nope"
    with pytest.raises(ConfigurationError, match="PFSENSE_TLS_MODE"):
        load_config(env)


def test_auto_tls_requires_ca_file(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_TLS_MODE"] = "auto"
    with pytest.raises(ConfigurationError, match="PFSENSE_TLS_CA_FILE"):
        load_config(env)


def test_default_api_version_is_v2(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    assert load_config(_base_env(key_file)).api_version is ApiVersion.V2
