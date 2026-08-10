"""Integration-style regression test for the real-hardware finding that
`httpx.Client(cert=(...), verify=<path>)` was unreliable for mTLS
client-certificate configuration on `httpx>=0.28` (2026-08-10
real-Proxmox verification). Exercises the exact confirmed-working
recipe documented in `witness_daemon/README.md`'s "Connecting from the
guest" section -- explicit `ssl.SSLContext` + `load_cert_chain()` +
`load_verify_locations()` + `trust_env=False` -- end to end over a real
TLS socket on localhost, using throwaway self-signed certificates
generated with this project's own already-declared `cryptography`
dependency. No real TPM, network, or Proxmox host involved -- fully
offline, deterministic, and automatically re-run on every CI push, so a
future httpx regression of this exact kind would be caught here instead
of only by manual real-hardware testing again.

This test is explicitly permitted to import `pfsense_mcp` --
`witness_daemon/tests/test_isolation.py` deliberately excludes `tests/`
from its "witness_daemon never imports pfsense_mcp" check for exactly
this purpose: production `witness_daemon/*.py` stays fully isolated,
while its own test suite may still exercise the real guest-side class
this daemon is built to serve.
"""

from __future__ import annotations

import datetime
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

from pfsense_mcp.tier1.anti_rollback_tpm_witness import TpmHostWitnessAnchor
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


class _FakeService:
    """Synthetic service -- never touches a real TPM. read() always
    returns 2, mirroring the real hardware's already-verified value,
    purely so this test's assertion reads naturally; the actual value
    is irrelevant to what this test proves (that the transport works)."""

    def read(self) -> int:
        return 2

    def advance(self, expected_current: int) -> AdvanceOutcome:
        raise AssertionError("not exercised by this test")


@pytest.fixture
def running_tls_server(tmp_path) -> Iterator[tuple[int, Path, Path, Path]]:
    server_cert, server_key = _generate_self_signed(common_name="witness-test", ip_address="127.0.0.1")
    client_cert, client_key = _generate_self_signed(common_name="guest-test")

    server_cert_path = tmp_path / "server.crt"
    server_key_path = tmp_path / "server.key"
    client_cert_path = tmp_path / "client.crt"
    client_key_path = tmp_path / "client.key"
    server_cert_path.write_bytes(server_cert)
    server_key_path.write_bytes(server_key)
    client_cert_path.write_bytes(client_cert)
    client_key_path.write_bytes(client_key)

    server = WitnessHTTPServer(("127.0.0.1", 0), _FakeService())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(server_cert_path), keyfile=str(server_key_path))
    context.load_verify_locations(cafile=str(client_cert_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], server_cert_path, client_cert_path, client_key_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_confirmed_client_recipe_completes_a_real_mtls_round_trip(running_tls_server):
    port, server_cert_path, client_cert_path, client_key_path = running_tls_server

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=str(server_cert_path))
    ssl_context.load_cert_chain(certfile=str(client_cert_path), keyfile=str(client_key_path))

    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=5.0)
    anchor = TpmHostWitnessAnchor(client=client, base_url=f"https://127.0.0.1:{port}")

    assert anchor.read() == 2


def test_no_client_certificate_is_rejected(running_tls_server):
    port, server_cert_path, _client_cert_path, _client_key_path = running_tls_server

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=str(server_cert_path))

    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=5.0)
    anchor = TpmHostWitnessAnchor(client=client, base_url=f"https://127.0.0.1:{port}")

    from pfsense_mcp.tier1.errors import AnchorUnavailableError

    with pytest.raises(AnchorUnavailableError):
        anchor.read()


def test_wrong_client_certificate_is_rejected(running_tls_server):
    port, server_cert_path, _client_cert_path, _client_key_path = running_tls_server
    wrong_cert, wrong_key = _generate_self_signed(common_name="not-the-real-client")
    wrong_cert_path = server_cert_path.parent / "wrong.crt"
    wrong_key_path = server_cert_path.parent / "wrong.key"
    wrong_cert_path.write_bytes(wrong_cert)
    wrong_key_path.write_bytes(wrong_key)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=str(server_cert_path))
    ssl_context.load_cert_chain(certfile=str(wrong_cert_path), keyfile=str(wrong_key_path))

    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=5.0)
    anchor = TpmHostWitnessAnchor(client=client, base_url=f"https://127.0.0.1:{port}")

    from pfsense_mcp.tier1.errors import AnchorUnavailableError

    with pytest.raises(AnchorUnavailableError):
        anchor.read()
