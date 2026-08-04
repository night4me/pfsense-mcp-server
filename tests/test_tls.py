from pathlib import Path

import pytest

from pfsense_mcp.errors import ConfigurationError
from pfsense_mcp.tls import TLSMode, resolve_verify, validate_tls_settings


def test_strict_requires_no_ca_file():
    validate_tls_settings(TLSMode.STRICT, None)
    with pytest.raises(ConfigurationError):
        validate_tls_settings(TLSMode.STRICT, Path("/tmp/ca.pem"))


def test_auto_requires_ca_file():
    with pytest.raises(ConfigurationError):
        validate_tls_settings(TLSMode.AUTO, None)
    validate_tls_settings(TLSMode.AUTO, Path("/tmp/ca.pem"))


def test_insecure_requires_no_ca_file():
    validate_tls_settings(TLSMode.INSECURE, None)
    with pytest.raises(ConfigurationError):
        validate_tls_settings(TLSMode.INSECURE, Path("/tmp/ca.pem"))


def test_resolve_verify_strict_is_true():
    assert resolve_verify(TLSMode.STRICT, None) is True


def test_resolve_verify_insecure_is_false():
    assert resolve_verify(TLSMode.INSECURE, None) is False


def test_resolve_verify_auto_returns_ca_path_string():
    ca_file = Path("/tmp/ca.pem")
    assert resolve_verify(TLSMode.AUTO, ca_file) == str(ca_file)
