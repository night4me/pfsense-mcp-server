"""Comprehensive regression tests for
`pfsense_mcp.tier1_anchor_check.run_anchor_startup_check` -- the read-
only, opt-in, log-only production wiring of the Tier 1 anti-rollback
anchor. Every test asserts the function never raises (matching its own
contract) and inspects the resulting log records, since that is its
only observable effect.
"""

from __future__ import annotations

import json
import logging
import os

from pfsense_mcp.tier1_anchor_check import run_anchor_startup_check

_MATERIAL_HEX = "ab" * 32


def _write_key_file(path, *, key_id="integrity-anchor-check"):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({"key_id": key_id, "epoch": 0, "material_hex": _MATERIAL_HEX}))
    os.chmod(path, 0o600)


def _store_env(tmp_path, *, store_dir_mode=0o700):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=store_dir_mode)
    store_path = store_dir / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    return {
        "PFSENSE_TIER1_STORE_PATH": str(store_path),
        "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file),
    }


def _clear_tier1_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_TIER1_"):
            monkeypatch.delenv(name, raising=False)


def _apply_env(monkeypatch, env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_unconfigured_is_a_complete_noop(monkeypatch, caplog):
    _clear_tier1_env(monkeypatch)
    logger = logging.getLogger("test.tier1_anchor_check.unconfigured")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert caplog.records == []


def test_invalid_store_config_logs_error_and_does_not_raise(monkeypatch, caplog):
    _clear_tier1_env(monkeypatch)
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", "/some/absolute/path")
    # PFSENSE_TIER1_STORE_KEY_FILE deliberately left unset -- partial config.
    logger = logging.getLogger("test.tier1_anchor_check.invalid_store_config")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(r.levelno == logging.ERROR and "store configuration is invalid" in r.message for r in caplog.records)


def test_malformed_store_logs_error(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed = store_dir / "anchor.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    os.chmod(malformed, 0o600)
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    _apply_env(
        monkeypatch,
        {"PFSENSE_TIER1_STORE_PATH": str(malformed), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)},
    )
    logger = logging.getLogger("test.tier1_anchor_check.malformed_store")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(
        r.levelno == logging.ERROR and "could not be opened or failed integrity" in r.message for r in caplog.records
    )


def test_unseeded_store_logs_warning_and_skips_comparison(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _store_env(tmp_path))
    logger = logging.getLogger("test.tier1_anchor_check.unseeded")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(
        r.levelno == logging.WARNING and "not fully provisioned" in r.message and "seeded=False" in r.message
        for r in caplog.records
    )


def _provisioned_store_env(tmp_path, *, value=2, handle="0x01500000"):
    env = _store_env(tmp_path)
    from pathlib import Path

    from pfsense_mcp.tier1.production_store import ProductionStoreConfig, provision_production_anchor_baseline

    config = ProductionStoreConfig(
        store_path=Path(env["PFSENSE_TIER1_STORE_PATH"]), key_file=Path(env["PFSENSE_TIER1_STORE_KEY_FILE"])
    )
    provision_production_anchor_baseline(config, value=value, handle=handle)
    return env


def test_configured_handle_mismatch_logs_error(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path, value=2, handle="0x01500000"))
    monkeypatch.setenv("PFSENSE_TIER1_EXPECTED_HANDLE", "0x01999999")
    logger = logging.getLogger("test.tier1_anchor_check.handle_mismatch")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(r.levelno == logging.ERROR and "configured handle mismatch" in r.message for r in caplog.records)


def test_configured_handle_match_does_not_error_on_handle_check(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path, value=2, handle="0x01500000"))
    monkeypatch.setenv("PFSENSE_TIER1_EXPECTED_HANDLE", "0x01500000")
    logger = logging.getLogger("test.tier1_anchor_check.handle_match")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert not any("configured handle mismatch" in r.message for r in caplog.records)
    # No witness client configured -- comparison skipped, not an error.
    assert any("witness client not configured" in r.message for r in caplog.records)


def test_provisioned_store_without_witness_config_skips_comparison(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path))
    logger = logging.getLogger("test.tier1_anchor_check.no_witness")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert not any(r.levelno >= logging.ERROR for r in caplog.records)
    assert any("witness client not configured" in r.message for r in caplog.records)


def test_partial_witness_config_logs_error(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path))
    monkeypatch.setenv("PFSENSE_TIER1_WITNESS_BASE_URL", "https://192.0.2.39:8443")
    # The other three witness vars deliberately left unset.
    logger = logging.getLogger("test.tier1_anchor_check.partial_witness")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(
        r.levelno == logging.ERROR and "witness client configuration is invalid" in r.message for r in caplog.records
    )


def test_witness_tls_client_failure_logs_error(monkeypatch, tmp_path, caplog):
    """Cert/key paths are well-formed absolute paths but do not exist --
    ssl.SSLContext.load_cert_chain()/load_verify_locations() raise a
    real OSError, exercising the client-side TLS configuration failure
    path distinct from AnchorUnavailableError (network unreachability)."""

    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path))
    _apply_env(
        monkeypatch,
        {
            "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
            "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(tmp_path / "does-not-exist-client.crt"),
            "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(tmp_path / "does-not-exist-client.key"),
            "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "does-not-exist-server.crt"),
        },
    )
    logger = logging.getLogger("test.tier1_anchor_check.tls_failure")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(
        r.levelno == logging.ERROR and "witness client TLS configuration failed" in r.message for r in caplog.records
    )


def test_witness_unavailable_logs_warning(monkeypatch, tmp_path, caplog):
    """A syntactically valid but unreachable base_url (nothing listening)
    exercises AnchorUnavailableError from a real (failing) connection
    attempt -- no mock needed, this is a real localhost connection
    refusal."""

    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path))

    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    _apply_env(
        monkeypatch,
        {
            # Port 1 is reserved/unused -- connection refused, not a hang.
            "PFSENSE_TIER1_WITNESS_BASE_URL": "https://127.0.0.1:1",
            "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(cert_path),
            "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(key_path),
            "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(cert_path),
        },
    )
    logger = logging.getLogger("test.tier1_anchor_check.witness_unavailable")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(r.levelno == logging.WARNING and "witness anchor unavailable" in r.message for r in caplog.records)


def test_healthy_matching_state_logs_info_only(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path, value=2, handle="0x01500000"))
    logger = logging.getLogger("test.tier1_anchor_check.healthy")

    class _FakeAnchor:
        def read(self) -> int:
            return 2

    import pfsense_mcp.tier1_anchor_check as module

    monkeypatch.setattr(module, "_build_witness_anchor", lambda config: _FakeAnchor())
    _apply_env(
        monkeypatch,
        {
            "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
            "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(tmp_path / "client.crt"),
            "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(tmp_path / "client.key"),
            "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "server.crt"),
        },
    )

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert any(
        r.levelno == logging.INFO and "witness value matches persisted high-water mark (2 == 2)" in r.message
        for r in caplog.records
    )


def test_mismatch_logs_error_without_mutating_anything(monkeypatch, tmp_path, caplog):
    _clear_tier1_env(monkeypatch)
    _apply_env(monkeypatch, _provisioned_store_env(tmp_path, value=2, handle="0x01500000"))
    logger = logging.getLogger("test.tier1_anchor_check.mismatch")

    class _FakeAnchor:
        def read(self) -> int:
            return 7  # deliberately different from the persisted baseline (2)

    import pfsense_mcp.tier1_anchor_check as module

    monkeypatch.setattr(module, "_build_witness_anchor", lambda config: _FakeAnchor())
    _apply_env(
        monkeypatch,
        {
            "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
            "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(tmp_path / "client.crt"),
            "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(tmp_path / "client.key"),
            "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "server.crt"),
        },
    )

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)

    assert any(
        r.levelno == logging.ERROR and "witness value (7) does not match persisted high-water mark (2)" in r.message
        for r in caplog.records
    )

    # Confirm truly read-only: re-reading the store afterward shows the
    # baseline is still exactly what it was before this check ran.
    from pathlib import Path

    from pfsense_mcp.tier1.production_store import ProductionStoreConfig, open_production_store

    config = ProductionStoreConfig(
        store_path=Path(os.environ["PFSENSE_TIER1_STORE_PATH"]),
        key_file=Path(os.environ["PFSENSE_TIER1_STORE_KEY_FILE"]),
    )
    status = open_production_store(config).anchor_provisioning_status()
    assert status.baseline == 2
    assert status.complete is True


def test_never_raises_even_on_completely_unexpected_internal_error(monkeypatch, caplog):
    """Exercises run_anchor_startup_check()'s own outer catch-all --
    simulates an error type no inner except clause anticipates."""

    _clear_tier1_env(monkeypatch)
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", "/tmp/does-not-matter")
    monkeypatch.setenv("PFSENSE_TIER1_STORE_KEY_FILE", "/tmp/also-does-not-matter")

    import pfsense_mcp.tier1_anchor_check as module

    def _boom(env=None):
        raise RuntimeError("completely unexpected failure type")

    monkeypatch.setattr(module, "load_production_store_config", _boom)
    logger = logging.getLogger("test.tier1_anchor_check.unexpected")

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        run_anchor_startup_check(logger)  # must not raise

    assert any(r.levelno == logging.ERROR and "tier1_anchor_check_failed" in r.message for r in caplog.records)
