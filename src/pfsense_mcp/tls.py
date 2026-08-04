"""TLS mode configuration.

STRICT verifies against the system default CA trust store. AUTO
verifies against an explicitly configured CA file. INSECURE disables
verification entirely and must be explicitly requested — it is a
temporary mode, intended to be replaced by AUTO once this instance's
internal CA certificate is available to configure.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from .errors import ConfigurationError


class TLSMode(str, Enum):
    STRICT = "strict"
    AUTO = "auto"
    INSECURE = "insecure"


def validate_tls_settings(mode: TLSMode, ca_file: Path | None) -> None:
    if mode is TLSMode.STRICT and ca_file is not None:
        raise ConfigurationError("PFSENSE_TLS_CA_FILE must not be set when PFSENSE_TLS_MODE=strict")
    if mode is TLSMode.AUTO and ca_file is None:
        raise ConfigurationError("PFSENSE_TLS_MODE=auto requires PFSENSE_TLS_CA_FILE")
    if mode is TLSMode.INSECURE and ca_file is not None:
        raise ConfigurationError("PFSENSE_TLS_CA_FILE must not be set when PFSENSE_TLS_MODE=insecure")


def resolve_verify(mode: TLSMode, ca_file: Path | None) -> bool | str:
    """Convert a validated TLSMode into the value httpx's `verify=`
    expects. Call validate_tls_settings first."""
    if mode is TLSMode.STRICT:
        return True
    if mode is TLSMode.AUTO:
        assert ca_file is not None
        return str(ca_file)
    if mode is TLSMode.INSECURE:
        return False
    raise AssertionError(f"unhandled TLSMode {mode!r}")
