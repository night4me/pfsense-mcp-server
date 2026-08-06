"""TLS mode configuration.

STRICT verifies against the system default CA trust store. AUTO
verifies against an explicitly configured CA file. INSECURE disables
verification entirely and must be explicitly requested — it is a
temporary mode, intended to be replaced by AUTO once this instance's
internal CA certificate is available to configure.
"""

from __future__ import annotations

import os
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


def validate_tls_ca_file(mode: TLSMode, ca_file: Path | None) -> None:
    if mode is not TLSMode.AUTO:
        return
    assert ca_file is not None
    if not ca_file.is_file():
        raise ConfigurationError(f"TLS CA file not found or not a regular file: {ca_file}")
    if not os.access(ca_file, os.R_OK):
        raise ConfigurationError(f"TLS CA file is not readable: {ca_file}")


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
