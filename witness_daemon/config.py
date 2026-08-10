"""Fail-closed, environment-driven configuration for the witness daemon.

Mirrors `pfsense_mcp.config`'s own discipline exactly: every setting is
explicit, nothing falls back to a discovered file or guessed default,
and missing/invalid configuration refuses to start rather than guessing
a value that happens to work today. This module never reads the
contents of the credential/certificate files it points at -- only their
paths are validated here; opening them is `main.py`'s/`tpm_cli.py`'s job,
at daemon startup, not configuration-load time.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import WitnessConfigurationError

_HANDLE_VAR = "WITNESS_TPM_NV_HANDLE"
_AUTH_CREDENTIAL_VAR = "WITNESS_TPM_AUTH_CREDENTIAL_FILE"
_BIND_HOST_VAR = "WITNESS_BIND_HOST"
_BIND_PORT_VAR = "WITNESS_BIND_PORT"
_SERVER_CERT_VAR = "WITNESS_SERVER_CERT_FILE"
_SERVER_KEY_VAR = "WITNESS_SERVER_KEY_FILE"
_CLIENT_CA_VAR = "WITNESS_CLIENT_CA_FILE"

_REQUIRED_VARS = (
    _HANDLE_VAR,
    _AUTH_CREDENTIAL_VAR,
    _BIND_HOST_VAR,
    _BIND_PORT_VAR,
    _SERVER_CERT_VAR,
    _SERVER_KEY_VAR,
    _CLIENT_CA_VAR,
)

# TPM2 NV handle syntax: "0x01" + 6 hex digits. The conventional
# owner/application-usable sub-range this project's own accepted design
# (anti_rollback_tpm_host_witness.md's "Provisioning strategy") uses is
# 0x01000000-0x01bfffff, explicitly avoiding the TCG-reserved
# platform-certificate range 0x01c00000-0x01ffffff. This is defense in
# depth, not the sole protection: the deeper guarantee is structural --
# every TPM invocation in tpm_cli.py always uses this one configured
# handle, never a caller-supplied value (see tpm_cli.py's own docstring).
_HANDLE_PATTERN = re.compile(r"0x01[0-9a-fA-F]{6}")
_HANDLE_RANGE = (0x01000000, 0x01BFFFFF)


@dataclass(frozen=True)
class WitnessDaemonConfig:
    nv_handle: str
    auth_credential_path: Path
    bind_host: str
    bind_port: int
    server_cert_path: Path
    server_key_path: Path
    client_ca_path: Path


def _validate_handle(raw: str) -> str:
    if not _HANDLE_PATTERN.fullmatch(raw):
        raise WitnessConfigurationError(f"{_HANDLE_VAR} must be a TPM2 NV handle of the form 0x01XXXXXX (got {raw!r}).")
    numeric = int(raw, 16)
    low, high = _HANDLE_RANGE
    if not low <= numeric <= high:
        raise WitnessConfigurationError(
            f"{_HANDLE_VAR} must be within the owner/application-usable range "
            f"0x{low:08x}-0x{high:08x}, avoiding the TCG-reserved range (got {raw!r})."
        )
    return raw


def _require_absolute_path(raw: str, var_name: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise WitnessConfigurationError(f"{var_name} must be an absolute path (got {raw!r}).")
    return path


def _validate_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError:
        raise WitnessConfigurationError(f"{_BIND_PORT_VAR} must be an integer (got {raw!r}).") from None
    if not 1 <= port <= 65535:
        raise WitnessConfigurationError(f"{_BIND_PORT_VAR} must be between 1 and 65535 (got {port}).")
    return port


def load_witness_daemon_config(env: dict[str, str] | None = None) -> WitnessDaemonConfig:
    """All seven variables are required together -- no partial
    configuration, no default that would let the daemon silently bind to
    an unintended interface or accept an unvalidated handle. Raises
    `WitnessConfigurationError` on any problem; touches no filesystem
    state (does not open the credential/certificate files)."""

    source = env if env is not None else os.environ
    missing = [name for name in _REQUIRED_VARS if not source.get(name)]
    if missing:
        raise WitnessConfigurationError(f"Missing required environment variable(s): {', '.join(missing)}")

    nv_handle = _validate_handle(source[_HANDLE_VAR])
    auth_credential_path = _require_absolute_path(source[_AUTH_CREDENTIAL_VAR], _AUTH_CREDENTIAL_VAR)
    bind_host = source[_BIND_HOST_VAR].strip()
    if not bind_host:
        raise WitnessConfigurationError(f"{_BIND_HOST_VAR} must not be empty.")
    bind_port = _validate_port(source[_BIND_PORT_VAR])
    server_cert_path = _require_absolute_path(source[_SERVER_CERT_VAR], _SERVER_CERT_VAR)
    server_key_path = _require_absolute_path(source[_SERVER_KEY_VAR], _SERVER_KEY_VAR)
    client_ca_path = _require_absolute_path(source[_CLIENT_CA_VAR], _CLIENT_CA_VAR)

    return WitnessDaemonConfig(
        nv_handle=nv_handle,
        auth_credential_path=auth_credential_path,
        bind_host=bind_host,
        bind_port=bind_port,
        server_cert_path=server_cert_path,
        server_key_path=server_key_path,
        client_ca_path=client_ca_path,
    )
