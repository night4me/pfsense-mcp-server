"""Configuration loading for the pfSense MCP server.

All configuration is environment-driven. Nothing is inferred, nothing
falls back to a discovered file, and no key file is silently selected.
Missing or invalid configuration fails closed via ConfigurationError.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .api_version import ApiVersion
from .errors import ConfigurationError
from .profiles import Profile, get_profile
from .tls import TLSMode, validate_tls_settings

_REQUIRED_VARS = ("PFSENSE_API_URL", "PFSENSE_IDENTITY", "PFSENSE_API_KEY_FILE")


@dataclass(frozen=True)
class PfSenseConfig:
    base_url: str
    identity: str
    key_file: Path
    tls_mode: TLSMode
    tls_ca_file: Path | None
    api_version: ApiVersion
    profile: Profile
    log_max_bytes: int
    log_backup_count: int


def _validate_key_file(key_file: Path) -> None:
    if not key_file.is_file():
        raise ConfigurationError(f"Key file not found: {key_file}")
    if not os.access(key_file, os.R_OK):
        raise ConfigurationError(f"Key file is not readable: {key_file}")


def _parse_positive_int(raw: str, var_name: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError(f"{var_name} must be an integer (got {raw!r})") from None
    if value <= 0:
        raise ConfigurationError(f"{var_name} must be positive (got {value})")
    return value


def load_logging_config(env: dict[str, str] | None = None) -> tuple[int, int]:
    """Parse just the logging size/rotation settings. Kept separate
    from load_config() so logging can be configured correctly even if
    some other part of configuration fails to validate."""
    source = env if env is not None else os.environ
    max_bytes = _parse_positive_int(source.get("PFSENSE_LOG_MAX_BYTES", "5000000"), "PFSENSE_LOG_MAX_BYTES")
    backup_count = _parse_positive_int(source.get("PFSENSE_LOG_BACKUP_COUNT", "5"), "PFSENSE_LOG_BACKUP_COUNT")
    return max_bytes, backup_count


def load_config(env: dict[str, str] | None = None) -> PfSenseConfig:
    source = env if env is not None else os.environ

    missing = [name for name in _REQUIRED_VARS if not source.get(name)]
    if missing:
        raise ConfigurationError(f"Missing required environment variable(s): {', '.join(missing)}")

    base_url = source["PFSENSE_API_URL"].rstrip("/")
    identity = source["PFSENSE_IDENTITY"]
    key_file = Path(source["PFSENSE_API_KEY_FILE"]).expanduser()

    tls_mode_raw = source.get("PFSENSE_TLS_MODE", "strict").strip().lower()
    try:
        tls_mode = TLSMode(tls_mode_raw)
    except ValueError:
        valid = ", ".join(m.value for m in TLSMode)
        raise ConfigurationError(f"PFSENSE_TLS_MODE must be one of: {valid} (got {tls_mode_raw!r})") from None

    tls_ca_file_raw = source.get("PFSENSE_TLS_CA_FILE")
    tls_ca_file = Path(tls_ca_file_raw).expanduser() if tls_ca_file_raw else None
    validate_tls_settings(tls_mode, tls_ca_file)

    api_version_raw = source.get("PFSENSE_API_VERSION", "v2").strip().lower()
    try:
        api_version = ApiVersion(api_version_raw)
    except ValueError:
        valid = ", ".join(v.value for v in ApiVersion)
        raise ConfigurationError(f"PFSENSE_API_VERSION must be one of: {valid} (got {api_version_raw!r})") from None

    profile_raw = source.get("PFSENSE_PROFILE", "auditor").strip().lower()
    profile = get_profile(profile_raw)

    log_max_bytes, log_backup_count = load_logging_config(env)

    _validate_key_file(key_file)

    return PfSenseConfig(
        base_url=base_url,
        identity=identity,
        key_file=key_file,
        tls_mode=tls_mode,
        tls_ca_file=tls_ca_file,
        api_version=api_version,
        profile=profile,
        log_max_bytes=log_max_bytes,
        log_backup_count=log_backup_count,
    )


def load_api_key(config: PfSenseConfig) -> str:
    """Read only the first line of the key file. The returned value
    must never be logged, printed, or included in any exception
    message by any caller of this function."""
    try:
        with config.key_file.open("r", encoding="utf-8") as fh:
            first_line = fh.readline()
    except OSError:
        raise ConfigurationError(f"Key file could not be read: {config.key_file}") from None
    key = first_line.strip()
    if not key:
        raise ConfigurationError(f"Key file is empty: {config.key_file}")
    return key
