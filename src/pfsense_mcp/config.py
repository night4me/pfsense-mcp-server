"""Configuration loading for the pfSense MCP server.

All configuration is environment-driven. Nothing is inferred, nothing
falls back to a discovered file, and no key file is silently selected.
Missing or invalid configuration fails closed via ConfigurationError.
"""

from __future__ import annotations

import os
import stat
import unicodedata
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from hmac import compare_digest
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .api_version import ApiVersion
from .errors import ConfigurationError
from .profiles import Profile, get_profile
from .secure_file import open_nofollow, validate_descriptor
from .tls import TLSMode, validate_tls_ca_file, validate_tls_settings

_REQUIRED_VARS = ("PFSENSE_API_URL", "PFSENSE_IDENTITY", "PFSENSE_API_KEY_FILE")
_IDENTITY_MAX_LENGTH = 128
_KEY_FILE_MAX_BYTES = 16 * 1024
_KEY_LINE_MAX_LENGTH = 4096
_LOG_MAX_BYTES_MIN = 1024
_LOG_MAX_BYTES_MAX = 100_000_000
_LOG_BACKUP_COUNT_MIN = 1
_LOG_BACKUP_COUNT_MAX = 100


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
    allowed_tools: frozenset[str] | None = None


def _open_key_file(key_file: Path) -> int:
    return open_nofollow(key_file, on_error=ConfigurationError)


def _validate_key_file_descriptor(key_file: Path, descriptor: int) -> None:
    validate_descriptor(key_file, descriptor, max_bytes=_KEY_FILE_MAX_BYTES, on_error=ConfigurationError)


def _contains_control_characters(value: str) -> bool:
    return any(
        ord(character) < 32 or ord(character) == 127 or unicodedata.category(character) in {"Cf", "Zl", "Zp"}
        for character in value
    )


def _validate_base_url(raw: str) -> str:
    if raw != raw.strip() or _contains_control_characters(raw) or _contains_control_characters(unquote(raw)):
        raise ConfigurationError("PFSENSE_API_URL must not contain surrounding whitespace or control characters")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise ConfigurationError("PFSENSE_API_URL is not a valid URL") from None
    if parsed.scheme.lower() != "https":
        raise ConfigurationError("PFSENSE_API_URL must use https")
    if not parsed.hostname:
        raise ConfigurationError("PFSENSE_API_URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("PFSENSE_API_URL must not include user information")
    if parsed.query or parsed.fragment:
        raise ConfigurationError("PFSENSE_API_URL must not include a query string or fragment")
    if parsed.path not in ("", "/"):
        raise ConfigurationError("PFSENSE_API_URL must not include a path")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"https://{host}{f':{port}' if port is not None else ''}"


def _validate_identity(raw: str) -> str:
    identity = raw.strip()
    if not identity:
        raise ConfigurationError("PFSENSE_IDENTITY must not be empty or whitespace")
    if len(identity) > _IDENTITY_MAX_LENGTH:
        raise ConfigurationError(f"PFSENSE_IDENTITY must be at most {_IDENTITY_MAX_LENGTH} characters")
    if _contains_control_characters(identity):
        raise ConfigurationError("PFSENSE_IDENTITY must not contain control characters")
    return identity


def _parse_positive_int(raw: str, var_name: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError(f"{var_name} must be an integer (got {raw!r})") from None
    if value <= 0:
        raise ConfigurationError(f"{var_name} must be positive (got {value})")
    return value


def _parse_bounded_int(raw: str, var_name: str, *, minimum: int, maximum: int) -> int:
    value = _parse_positive_int(raw, var_name)
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{var_name} must be between {minimum} and {maximum} (got {value})")
    return value


def _parse_allowed_tools(source: Mapping[str, str]) -> frozenset[str] | None:
    if "PFSENSE_ALLOWED_TOOLS" not in source:
        return None

    raw = source["PFSENSE_ALLOWED_TOOLS"]
    if _contains_control_characters(raw):
        raise ConfigurationError("PFSENSE_ALLOWED_TOOLS must not contain control characters")
    if not raw.strip():
        return frozenset()

    names = [part.strip() for part in raw.split(",")]
    if any(not name for name in names):
        raise ConfigurationError("PFSENSE_ALLOWED_TOOLS must be a comma-separated list without empty entries")
    if any("*" in name or "?" in name or "[" in name or "]" in name for name in names):
        raise ConfigurationError("PFSENSE_ALLOWED_TOOLS accepts exact tool names only; wildcards are not allowed")
    if any(not name.startswith("pfsense_") or not name.replace("_", "").isalnum() for name in names):
        raise ConfigurationError("PFSENSE_ALLOWED_TOOLS contains an invalid tool name")
    return frozenset(names)


def load_logging_config(env: dict[str, str] | None = None) -> tuple[int, int]:
    """Parse just the logging size/rotation settings. Kept separate
    from load_config() so logging can be configured correctly even if
    some other part of configuration fails to validate."""
    source = env if env is not None else os.environ
    max_bytes = _parse_bounded_int(
        source.get("PFSENSE_LOG_MAX_BYTES", "5000000"),
        "PFSENSE_LOG_MAX_BYTES",
        minimum=_LOG_MAX_BYTES_MIN,
        maximum=_LOG_MAX_BYTES_MAX,
    )
    backup_count = _parse_bounded_int(
        source.get("PFSENSE_LOG_BACKUP_COUNT", "5"),
        "PFSENSE_LOG_BACKUP_COUNT",
        minimum=_LOG_BACKUP_COUNT_MIN,
        maximum=_LOG_BACKUP_COUNT_MAX,
    )
    return max_bytes, backup_count


def load_config(env: dict[str, str] | None = None) -> PfSenseConfig:
    source = env if env is not None else os.environ

    missing = [name for name in _REQUIRED_VARS if not source.get(name)]
    if missing:
        raise ConfigurationError(f"Missing required environment variable(s): {', '.join(missing)}")

    base_url = _validate_base_url(source["PFSENSE_API_URL"])
    identity = _validate_identity(source["PFSENSE_IDENTITY"])
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
    validate_tls_ca_file(tls_mode, tls_ca_file)

    api_version_raw = source.get("PFSENSE_API_VERSION", "v2").strip().lower()
    try:
        api_version = ApiVersion(api_version_raw)
    except ValueError:
        valid = ", ".join(v.value for v in ApiVersion)
        raise ConfigurationError(f"PFSENSE_API_VERSION must be one of: {valid} (got {api_version_raw!r})") from None

    profile_raw = source.get("PFSENSE_PROFILE", "auditor").strip().lower()
    profile = get_profile(profile_raw)
    allowed_tools = _parse_allowed_tools(source)

    log_max_bytes, log_backup_count = load_logging_config(env)

    return PfSenseConfig(
        base_url=base_url,
        identity=identity,
        key_file=key_file,
        tls_mode=tls_mode,
        tls_ca_file=tls_ca_file,
        api_version=api_version,
        profile=profile,
        allowed_tools=allowed_tools,
        log_max_bytes=log_max_bytes,
        log_backup_count=log_backup_count,
    )


def load_api_key(config: PfSenseConfig) -> str:
    """Validate and read the key through one non-following descriptor.

    The returned value must never be logged, printed, or included in any
    exception message by any caller of this function.
    """
    descriptor = _open_key_file(config.key_file)
    try:
        _validate_key_file_descriptor(config.key_file, descriptor)
        try:
            first_line = os.read(descriptor, _KEY_LINE_MAX_LENGTH + 1).split(b"\n", maxsplit=1)[0]
        except OSError:
            raise ConfigurationError(f"Key file could not be read: {config.key_file}") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise ConfigurationError(f"Key file descriptor could not be closed: {config.key_file}") from None

    if len(first_line) > _KEY_LINE_MAX_LENGTH:
        raise ConfigurationError(f"Key file first line is too long: {config.key_file}")
    if b"\x00" in first_line:
        raise ConfigurationError(f"Key file first line contains a NUL byte: {config.key_file}")
    if any(byte < 32 or byte == 127 for byte in first_line):
        raise ConfigurationError(f"Key file first line contains control characters: {config.key_file}")
    try:
        key = first_line.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ConfigurationError(f"Key file first line is not valid UTF-8: {config.key_file}") from None
    if not key:
        raise ConfigurationError(f"Key file is empty: {config.key_file}")
    return key


def store_api_key(config: PfSenseConfig, api_key: str) -> None:
    """Write a newly provisioned API key to ``PFSENSE_API_KEY_FILE``.

    Creation is exclusive and non-following: an existing path is never
    replaced.  A write/fsync/close/verification failure removes only the
    newly created artifact, so a partial key cannot be mistaken for a
    usable credential.  Error messages contain the configured path but
    never the key value.

    This helper performs no network operation and is deliberately not
    called by application startup or the ADR-033 bootstrap engine.  A
    future, separately authorized provisioning ceremony must invoke it
    explicitly after receiving a successful ``ProvisionedApiKey``.
    """

    if (
        not isinstance(api_key, str)
        or not api_key
        or api_key != api_key.strip()
        or _contains_control_characters(api_key)
    ):
        raise ConfigurationError("Provisioned API key is invalid")
    try:
        encoded = api_key.encode("utf-8")
    except UnicodeEncodeError:
        raise ConfigurationError("Provisioned API key is invalid") from None
    if len(encoded) > _KEY_LINE_MAX_LENGTH:
        raise ConfigurationError("Provisioned API key exceeds the maximum supported length")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ConfigurationError("Secure key-file creation is unsupported on this platform")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | nofollow | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    parent_descriptor: int | None = None
    descriptor: int | None = None
    created = False
    created_identity: tuple[int, int] | None = None
    complete = False
    try:
        try:
            parent_descriptor = os.open(config.key_file.parent, directory_flags)
            descriptor = os.open(config.key_file.name, flags, 0o600, dir_fd=parent_descriptor)
            created = True
        except OSError:
            raise ConfigurationError(f"Key file could not be created exclusively: {config.key_file}") from None

        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ConfigurationError(f"Key file creation produced an unsafe artifact: {config.key_file}")
        created_identity = (metadata.st_dev, metadata.st_ino)
        value = encoded + b"\n"
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise ConfigurationError(f"Key file could not be written: {config.key_file}")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        if not compare_digest(load_api_key(config), api_key):
            raise ConfigurationError(f"Key file verification failed: {config.key_file}")
        os.fsync(parent_descriptor)
        complete = True
    except ConfigurationError:
        raise
    except OSError:
        raise ConfigurationError(f"Key file could not be stored safely: {config.key_file}") from None
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if created and not complete and created_identity is not None:
            # Never unlink a path that another process substituted after
            # creation.  That may leave our inaccessible orphan elsewhere,
            # but cannot delete an unrelated replacement artifact.
            with suppress(OSError):
                if parent_descriptor is not None:
                    current = os.stat(config.key_file.name, dir_fd=parent_descriptor, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == created_identity:
                        os.unlink(config.key_file.name, dir_fd=parent_descriptor)
                        os.fsync(parent_descriptor)
        if parent_descriptor is not None:
            with suppress(OSError):
                os.close(parent_descriptor)
