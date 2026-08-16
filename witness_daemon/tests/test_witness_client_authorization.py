"""Owner decision 2026-08-16 (Slice 6 signer read-only witness identity):
the client-certificate bundle may now trust more than one identity, but
only an explicit, fail-closed allow-list of fingerprints may call
`/anchor/advance` -- mTLS authentication alone no longer implies mutation
authority. Exercises this over a real TLS socket with real, distinct
self-signed certificates (never a real TPM), mirroring
`test_mtls_integration.py`'s own established recipe exactly.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from witness_daemon.http_server import WitnessHTTPServer
from witness_daemon.service import AdvanceOutcome


def _generate_self_signed(*, common_name: str, ip_address: str | None = None) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if ip_address is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip_address))]),
            critical=False,
        )
    certificate = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


def _fingerprint(cert_pem: bytes) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_pem.decode("ascii"))
    return hashlib.sha256(der).hexdigest()


class _FakeService:
    """read() always returns 2; advance() records whether it was ever
    called at all -- a rejected caller must never reach this object,
    proven by asserting `advance_calls == []` after every negative test."""

    def __init__(self) -> None:
        self.advance_calls: list[int] = []

    def read(self) -> int:
        return 2

    def advance(self, expected_current: int) -> AdvanceOutcome:
        self.advance_calls.append(expected_current)
        return AdvanceOutcome(conflict=False, value=expected_current + 1)


@pytest.fixture
def two_client_identities(tmp_path) -> dict[str, tuple[Path, Path, str]]:
    """Two distinct, independently generated identities -- 'production'
    (stands in for VM106's real witness client) and 'signer' (stands in
    for the off-host signer's new, separate identity). Both are bundled
    into one client-CA file (concatenated PEM), matching how the real
    Proxmox-host daemon will trust both without a real CA hierarchy."""

    identities: dict[str, tuple[Path, Path, str]] = {}
    bundle = b""
    for name in ("production", "signer"):
        cert_pem, key_pem = _generate_self_signed(common_name=f"{name}-test")
        cert_path = tmp_path / f"{name}.crt"
        key_path = tmp_path / f"{name}.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        identities[name] = (cert_path, key_path, _fingerprint(cert_pem))
        bundle += cert_pem
    bundle_path = tmp_path / "client-ca-bundle.crt"
    bundle_path.write_bytes(bundle)
    identities["__bundle__"] = (bundle_path, bundle_path, "")  # type: ignore[assignment]
    return identities


@pytest.fixture
def running_server_with_two_identities(
    tmp_path, two_client_identities
) -> Iterator[tuple[int, Path, _FakeService, str, str]]:
    server_cert, server_key = _generate_self_signed(common_name="witness-test", ip_address="127.0.0.1")
    server_cert_path = tmp_path / "server.crt"
    server_key_path = tmp_path / "server.key"
    server_cert_path.write_bytes(server_cert)
    server_key_path.write_bytes(server_key)

    bundle_path, _, _ = two_client_identities["__bundle__"]
    _, _, production_fingerprint = two_client_identities["production"]

    service = _FakeService()
    server = WitnessHTTPServer(
        ("127.0.0.1", 0), service, advance_allowed_fingerprints=frozenset({production_fingerprint})
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(server_cert_path), keyfile=str(server_key_path))
    context.load_verify_locations(cafile=str(bundle_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], server_cert_path, service, "production", "signer"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _client(port: int, server_cert_path: Path, cert_path: Path, key_path: Path) -> httpx.Client:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=str(server_cert_path))
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return httpx.Client(verify=ssl_context, trust_env=False, timeout=5.0, base_url=f"https://127.0.0.1:{port}")


def test_signer_identity_can_read(running_server_with_two_identities, two_client_identities):
    port, server_cert_path, _service, _prod, _signer = running_server_with_two_identities
    cert_path, key_path, _fp = two_client_identities["signer"]

    with _client(port, server_cert_path, cert_path, key_path) as client:
        response = client.get("/anchor/read")

    assert response.status_code == 200
    assert response.json() == {"value": 2}


def test_signer_identity_cannot_advance(running_server_with_two_identities, two_client_identities):
    port, server_cert_path, service, _prod, _signer = running_server_with_two_identities
    cert_path, key_path, _fp = two_client_identities["signer"]

    with _client(port, server_cert_path, cert_path, key_path) as client:
        response = client.post("/anchor/advance", json={"expected_current": 2})

    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    # The decisive proof: the rejected caller never reached the TPM-facing
    # service at all -- zero mutation attempted, not merely zero mutation
    # applied.
    assert service.advance_calls == []


def test_production_identity_can_read(running_server_with_two_identities, two_client_identities):
    port, server_cert_path, _service, _prod, _signer = running_server_with_two_identities
    cert_path, key_path, _fp = two_client_identities["production"]

    with _client(port, server_cert_path, cert_path, key_path) as client:
        response = client.get("/anchor/read")

    assert response.status_code == 200
    assert response.json() == {"value": 2}


def test_production_identity_can_advance_unchanged(running_server_with_two_identities, two_client_identities):
    """VM106's own production credential behavior is unaffected by this
    change -- it remains full-power (read + advance), exactly as before
    this owner decision."""

    port, server_cert_path, service, _prod, _signer = running_server_with_two_identities
    cert_path, key_path, _fp = two_client_identities["production"]

    with _client(port, server_cert_path, cert_path, key_path) as client:
        response = client.post("/anchor/advance", json={"expected_current": 2})

    assert response.status_code == 200
    assert response.json() == {"value": 3}
    assert service.advance_calls == [2]


def test_no_client_certificate_is_rejected_for_advance(running_server_with_two_identities):
    port, server_cert_path, service, _prod, _signer = running_server_with_two_identities

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=str(server_cert_path))
    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=5.0, base_url=f"https://127.0.0.1:{port}")

    with client, pytest.raises(httpx.TransportError):
        client.post("/anchor/advance", json={"expected_current": 2})

    assert service.advance_calls == []


def test_untrusted_certificate_is_rejected_for_advance(running_server_with_two_identities, tmp_path):
    port, server_cert_path, service, _prod, _signer = running_server_with_two_identities
    untrusted_cert, untrusted_key = _generate_self_signed(common_name="untrusted-outsider")
    cert_path = tmp_path / "untrusted.crt"
    key_path = tmp_path / "untrusted.key"
    cert_path.write_bytes(untrusted_cert)
    key_path.write_bytes(untrusted_key)

    with pytest.raises(httpx.TransportError), _client(port, server_cert_path, cert_path, key_path) as client:
        client.post("/anchor/advance", json={"expected_current": 2})

    assert service.advance_calls == []


def test_default_advance_allow_list_is_empty_fail_closed():
    """Constructing a WitnessHTTPServer without an explicit allow-list
    (e.g. legacy test/tooling code written before this parameter
    existed) permits no one to advance -- never silently permits every
    authenticated client the way the daemon behaved before this change."""

    service = _FakeService()
    server = WitnessHTTPServer(("127.0.0.1", 0), service)
    try:
        assert server.advance_allowed_fingerprints == frozenset()
    finally:
        server.server_close()
