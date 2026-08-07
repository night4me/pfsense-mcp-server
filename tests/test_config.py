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
    config = load_config(_base_env(tmp_path / "does-not-exist.key"))
    with pytest.raises(ConfigurationError, match="could not be opened"):
        load_api_key(config)


def test_unreadable_key_file_fails_closed(tmp_path):
    key_file = tmp_path / "unreadable.key"
    key_file.write_text("fake-key-value\n")
    key_file.chmod(0o000)
    try:
        config = load_config(_base_env(key_file))
        if not os.access(key_file, os.R_OK):
            with pytest.raises(ConfigurationError, match="could not be opened"):
                load_api_key(config)
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
    [
        "pfsense_get_*",
        "pfsense_get_system_status,",
        "not-a-tool",
        "pfsense_get_system_status\nother",
        "pfsense_get_system_status\u2028other",
    ],
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
        "https://pfsense%0a.example.invalid",
        "https://pfsense.example.invalid\u2028ignored",
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


@pytest.mark.parametrize("identity", [" ", "line\nbreak", "line\u2028break", "zero\u200bwidth", "x" * 129])
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
    config = load_config(_base_env(link))
    with pytest.raises(ConfigurationError, match="symbolic link"):
        load_api_key(config)


def test_key_file_directory_is_rejected(tmp_path):
    config = load_config(_base_env(tmp_path))
    with pytest.raises(ConfigurationError, match="regular file"):
        load_api_key(config)


def test_key_file_size_is_bounded(tmp_path):
    key_file = tmp_path / "large.key"
    key_file.write_text("x" * (16 * 1024 + 1))
    config = load_config(_base_env(key_file))
    with pytest.raises(ConfigurationError, match="maximum allowed size"):
        load_api_key(config)


@pytest.mark.parametrize("mode", [0o640, 0o604])
def test_key_file_with_group_or_other_permissions_is_rejected(tmp_path, mode):
    key_file = tmp_path / "permissive.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    key_file.chmod(mode)
    config = load_config(env)
    with pytest.raises(ConfigurationError, match="group or other"):
        load_api_key(config)


def test_key_file_owned_by_another_user_is_rejected(tmp_path, monkeypatch):
    key_file = tmp_path / "wrong-owner.key"
    key_file.write_text("fake-key-value\n")
    env = _base_env(key_file)
    monkeypatch.setattr(os, "geteuid", lambda: key_file.stat().st_uid + 1)
    config = load_config(env)
    with pytest.raises(ConfigurationError, match="current user"):
        load_api_key(config)


def test_key_file_control_character_is_rejected(tmp_path):
    key_file = tmp_path / "control.key"
    key_file.write_bytes(b"fake\tkey\n")
    config = load_config(_base_env(key_file))
    with pytest.raises(ConfigurationError, match="control characters"):
        load_api_key(config)


def test_key_file_nul_byte_is_rejected(tmp_path):
    key_file = tmp_path / "nul.key"
    key_file.write_bytes(b"fake\x00key\n")
    config = load_config(_base_env(key_file))
    with pytest.raises(ConfigurationError, match="NUL byte"):
        load_api_key(config)


def test_key_file_first_line_length_is_bounded(tmp_path):
    key_file = tmp_path / "long-line.key"
    key_file.write_bytes(b"x" * 4097 + b"\n")
    config = load_config(_base_env(key_file))
    with pytest.raises(ConfigurationError, match="first line is too long"):
        load_api_key(config)


def test_key_file_invalid_utf8_is_rejected(tmp_path):
    key_file = tmp_path / "invalid-utf8.key"
    key_file.write_bytes(b"fake-\xff-key\n")
    config = load_config(_base_env(key_file))
    with pytest.raises(ConfigurationError, match="valid UTF-8"):
        load_api_key(config)


def test_key_file_loading_requires_nofollow_support(tmp_path, monkeypatch):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    config = load_config(_base_env(key_file))
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(ConfigurationError, match="unsupported on this platform"):
        load_api_key(config)


def test_key_file_descriptor_is_closed_after_success(tmp_path, monkeypatch):
    key_file = tmp_path / "present.key"
    key_file.write_text("fake-key-value\n")
    config = load_config(_base_env(key_file))
    real_open = os.open
    descriptors: list[int] = []

    def capture_open(path, flags):
        descriptor = real_open(path, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", capture_open)
    assert load_api_key(config) == "fake-key-value"
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_key_file_descriptor_is_closed_after_failure(tmp_path, monkeypatch):
    key_file = tmp_path / "permissive.key"
    key_file.write_text("fake-key-value\n")
    config = load_config(_base_env(key_file))
    key_file.chmod(0o640)
    real_open = os.open
    descriptors: list[int] = []

    def capture_open(path, flags):
        descriptor = real_open(path, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", capture_open)
    with pytest.raises(ConfigurationError, match="group or other"):
        load_api_key(config)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_key_file_inode_and_contents_remain_bound_after_path_replacement(tmp_path, monkeypatch):
    key_file = tmp_path / "active.key"
    key_file.write_text("original-key-value\n")
    replacement = tmp_path / "replacement.key"
    replacement.write_text("replacement-key-value\n")
    replacement.chmod(0o600)
    original_inode = key_file.stat().st_ino
    config = load_config(_base_env(key_file))
    displaced = tmp_path / "displaced.key"
    real_fstat = os.fstat
    real_read = os.read
    descriptor_inode: int | None = None

    def replace_path_after_fstat(descriptor):
        nonlocal descriptor_inode
        metadata = real_fstat(descriptor)
        descriptor_inode = metadata.st_ino
        key_file.rename(displaced)
        replacement.rename(key_file)
        return metadata

    def verify_descriptor_before_read(descriptor, size):
        assert real_fstat(descriptor).st_ino == original_inode
        assert key_file.stat().st_ino != original_inode
        return real_read(descriptor, size)

    monkeypatch.setattr(os, "fstat", replace_path_after_fstat)
    monkeypatch.setattr(os, "read", verify_descriptor_before_read)

    assert load_api_key(config) == "original-key-value"
    assert descriptor_inode == original_inode
    assert key_file.read_text() == "replacement-key-value\n"


def test_key_file_errors_and_logs_never_contain_key_contents(tmp_path, caplog):
    sentinel = "SENTINEL_KEY_VALUE_MUST_NOT_LEAK"
    key_file = tmp_path / "invalid.key"
    key_file.write_bytes(sentinel.encode() + b"\x00tail\n")
    config = load_config(_base_env(key_file))
    caplog.set_level("DEBUG")

    with pytest.raises(ConfigurationError) as captured:
        load_api_key(config)

    assert sentinel not in str(captured.value)
    assert sentinel not in caplog.text


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
