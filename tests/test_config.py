import os

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.config import ConfigurationError, load_api_key, load_config, load_logging_config
from pfsense_mcp.tls import TLSMode


def _base_env(key_file) -> dict[str, str]:
    if key_file.is_file() and not key_file.is_symlink():
        key_file.chmod(key_file.stat().st_mode & ~0o077)
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


def test_allowed_tools_absent_means_no_additional_restriction(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    assert load_config(_base_env(key_file)).allowed_tools is None


def test_empty_allowed_tools_registers_no_tools(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_ALLOWED_TOOLS"] = "  "
    assert load_config(env).allowed_tools == frozenset()


def test_allowed_tool_duplicates_are_normalized_deterministically(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_ALLOWED_TOOLS"] = "pfsense_get_system_status, pfsense_get_system_status"
    assert load_config(env).allowed_tools == frozenset({"pfsense_get_system_status"})


@pytest.mark.parametrize(
    "value",
    ["pfsense_get_*", "pfsense_get_system_status,", "not-a-tool", "pfsense_get_system_status\nother"],
)
def test_invalid_allowed_tool_syntax_fails_closed(tmp_path, value):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_ALLOWED_TOOLS"] = value
    with pytest.raises(ConfigurationError, match="PFSENSE_ALLOWED_TOOLS"):
        load_config(env)


@pytest.mark.parametrize(
    "url",
    [
        "http://pfsense.example.invalid",
        "pfsense.example.invalid",
        "https://user:pass@pfsense.example.invalid",
        "https://pfsense.example.invalid/api",
        "https://pfsense.example.invalid?x=1",
        "https://pfsense.example.invalid#fragment",
        " https://pfsense.example.invalid",
    ],
)
def test_unsafe_api_urls_are_rejected(tmp_path, url):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_API_URL"] = url
    with pytest.raises(ConfigurationError, match="PFSENSE_API_URL"):
        load_config(env)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://pfsense.example.invalid/", "https://pfsense.example.invalid"),
        ("https://192.0.2.1:8443", "https://192.0.2.1:8443"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_valid_api_urls_are_normalized(tmp_path, url, expected):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_API_URL"] = url
    assert load_config(env).base_url == expected


@pytest.mark.parametrize("identity", [" ", "line\nbreak", "x" * 129])
def test_invalid_identity_is_rejected(tmp_path, identity):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_IDENTITY"] = identity
    with pytest.raises(ConfigurationError, match="PFSENSE_IDENTITY"):
        load_config(env)


def test_key_file_symlink_is_rejected(tmp_path):
    target = tmp_path / "target.key"
    target.write_text("fake-key-value\n")
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with pytest.raises(ConfigurationError, match="symbolic link"):
        load_config(_base_env(link))


def test_key_file_directory_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="regular file"):
        load_config(_base_env(tmp_path))


def test_key_file_size_is_bounded(tmp_path):
    key_file = tmp_path / "large.key"
    key_file.write_text("x" * (16 * 1024 + 1))
    with pytest.raises(ConfigurationError, match="maximum allowed size"):
        load_config(_base_env(key_file))


def test_key_file_with_group_or_other_permissions_is_rejected(tmp_path):
    key_file = tmp_path / "permissive.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    key_file.chmod(0o640)
    with pytest.raises(ConfigurationError, match="group or other"):
        load_config(env)


def test_key_file_owned_by_another_user_is_rejected(tmp_path, monkeypatch):
    key_file = tmp_path / "wrong-owner.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    monkeypatch.setattr(os, "geteuid", lambda: key_file.stat().st_uid + 1)
    with pytest.raises(ConfigurationError, match="current user"):
        load_config(env)


def test_key_file_control_character_is_rejected(tmp_path):
    key_file = tmp_path / "control.key"
    key_file.write_bytes(b"fake\x00key\n")
    config = load_config(_base_env(key_file))
    with pytest.raises(ConfigurationError, match="control characters"):
        load_api_key(config)


def test_auto_tls_requires_existing_regular_readable_ca_file(tmp_path):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    env["PFSENSE_TLS_MODE"] = "auto"
    env["PFSENSE_TLS_CA_FILE"] = str(tmp_path / "missing.pem")
    with pytest.raises(ConfigurationError, match="TLS CA file"):
        load_config(env)

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("synthetic-ca-data")
    env["PFSENSE_TLS_CA_FILE"] = str(ca_file)
    assert load_config(env).tls_ca_file == ca_file


@pytest.mark.parametrize(
    ("name", "value"),
    [("PFSENSE_LOG_MAX_BYTES", "101000000"), ("PFSENSE_LOG_BACKUP_COUNT", "101")],
)
def test_logging_settings_have_upper_bounds(name, value):
    with pytest.raises(ConfigurationError, match=name):
        load_logging_config({name: value})
