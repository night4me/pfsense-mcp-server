from __future__ import annotations

from pathlib import Path

import pytest

from witness_daemon.config import WitnessDaemonConfig, load_witness_daemon_config
from witness_daemon.errors import WitnessConfigurationError

_FINGERPRINT_A = "a" * 64
_FINGERPRINT_B = "b" * 64

_VALID_ENV = {
    "WITNESS_TPM_NV_HANDLE": "0x01500000",
    "WITNESS_TPM_AUTH_CREDENTIAL_FILE": "/run/credentials/witness/nv-index-auth",
    "WITNESS_BIND_HOST": "203.0.113.5",
    "WITNESS_BIND_PORT": "8443",
    "WITNESS_SERVER_CERT_FILE": "/etc/witness/server.crt",
    "WITNESS_SERVER_KEY_FILE": "/run/credentials/witness/witness-server-key",
    "WITNESS_CLIENT_CA_FILE": "/etc/witness/client-ca.crt",
    "WITNESS_ADVANCE_CLIENT_FINGERPRINTS": f"{_FINGERPRINT_A},{_FINGERPRINT_B}",
}


def test_valid_configuration_is_accepted():
    config = load_witness_daemon_config(dict(_VALID_ENV))

    assert config == WitnessDaemonConfig(
        nv_handle="0x01500000",
        auth_credential_path=Path("/run/credentials/witness/nv-index-auth"),
        bind_host="203.0.113.5",
        bind_port=8443,
        server_cert_path=Path("/etc/witness/server.crt"),
        server_key_path=Path("/run/credentials/witness/witness-server-key"),
        client_ca_path=Path("/etc/witness/client-ca.crt"),
        advance_client_fingerprints=frozenset({_FINGERPRINT_A, _FINGERPRINT_B}),
    )


@pytest.mark.parametrize(
    "bad_value",
    [
        "",
        "not-hex",
        "a" * 63,
        "a" * 65,
        "A" * 64,  # uppercase refused -- must already be lowercase, never normalized silently
        f"{_FINGERPRINT_A},",
        f"{_FINGERPRINT_A},{_FINGERPRINT_A}",  # duplicate
    ],
)
def test_invalid_advance_fingerprints_are_refused(bad_value):
    env = dict(_VALID_ENV)
    env["WITNESS_ADVANCE_CLIENT_FINGERPRINTS"] = bad_value
    with pytest.raises(WitnessConfigurationError):
        load_witness_daemon_config(env)


def test_single_advance_fingerprint_is_accepted():
    env = dict(_VALID_ENV)
    env["WITNESS_ADVANCE_CLIENT_FINGERPRINTS"] = _FINGERPRINT_A
    config = load_witness_daemon_config(env)
    assert config.advance_client_fingerprints == frozenset({_FINGERPRINT_A})


@pytest.mark.parametrize("missing", list(_VALID_ENV))
def test_missing_any_required_variable_is_refused(missing):
    env = dict(_VALID_ENV)
    del env[missing]
    with pytest.raises(WitnessConfigurationError, match="Missing required"):
        load_witness_daemon_config(env)


@pytest.mark.parametrize(
    "bad_handle",
    ["0x00500000", "not-a-handle", "0x01500000extra", "0x1500000", "0x01c00000", "0x01ffffff", "0x00ffffff"],
)
def test_invalid_or_out_of_range_handle_is_refused(bad_handle):
    env = dict(_VALID_ENV)
    env["WITNESS_TPM_NV_HANDLE"] = bad_handle
    with pytest.raises(WitnessConfigurationError):
        load_witness_daemon_config(env)


def test_handle_at_range_boundaries_is_accepted():
    for handle in ("0x01000000", "0x01bfffff"):
        env = dict(_VALID_ENV)
        env["WITNESS_TPM_NV_HANDLE"] = handle
        config = load_witness_daemon_config(env)
        assert config.nv_handle == handle


@pytest.mark.parametrize(
    "var",
    [
        "WITNESS_TPM_AUTH_CREDENTIAL_FILE",
        "WITNESS_SERVER_CERT_FILE",
        "WITNESS_SERVER_KEY_FILE",
        "WITNESS_CLIENT_CA_FILE",
    ],
)
def test_relative_path_variables_are_refused(var):
    env = dict(_VALID_ENV)
    env[var] = "relative/path"
    with pytest.raises(WitnessConfigurationError, match="absolute"):
        load_witness_daemon_config(env)


@pytest.mark.parametrize("bad_port", ["0", "-1", "65536", "not-a-port", ""])
def test_invalid_port_is_refused(bad_port):
    env = dict(_VALID_ENV)
    env["WITNESS_BIND_PORT"] = bad_port
    with pytest.raises(WitnessConfigurationError):
        load_witness_daemon_config(env)


def test_load_witness_daemon_config_touches_no_filesystem_state(tmp_path):
    env = dict(_VALID_ENV)
    env["WITNESS_TPM_AUTH_CREDENTIAL_FILE"] = str(tmp_path / "does-not-exist" / "nv-index-auth")
    env["WITNESS_SERVER_CERT_FILE"] = str(tmp_path / "also-does-not-exist" / "server.crt")

    config = load_witness_daemon_config(env)

    assert not config.auth_credential_path.parent.exists()
    assert not config.server_cert_path.parent.exists()
