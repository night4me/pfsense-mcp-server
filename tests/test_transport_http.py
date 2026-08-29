import base64
import ssl

import httpx
import pytest
import respx

from pfsense_mcp.transport.base import (
    TransportConfigurationError,
    TransportConnectionError,
    TransportRequestNotSentError,
    TransportTimeoutError,
)
from pfsense_mcp.transport.http import BasicAuthHttpTransport, HttpTransport


def _connect_error_with_cause(cause: BaseException) -> httpx.ConnectError:
    """Build an httpx.ConnectError with a given __cause__, matching the
    real shape httpcore produces (its own ConnectError message text is
    what carries the DNS/refused/TLS distinction -- see
    _classify_connect_failure's own docstring comment)."""

    exc = httpx.ConnectError(str(cause))
    exc.__cause__ = cause
    return exc


@respx.mock
def test_request_sends_api_key_header_and_returns_response():
    route = respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        response = transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()

    assert route.called
    sent_request = route.calls.last.request
    assert sent_request.headers["X-API-Key"] == "fake-key"
    assert response.status_code == 200
    assert response.text == '{"status": "ok"}'


@respx.mock
def test_request_sends_body_and_content_type_when_provided():
    route = respx.patch("https://pfsense.example.invalid/api/v2/firewall/alias").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        response = transport.request("PATCH", "/api/v2/firewall/alias", body=b'{"descr":"updated"}')
    finally:
        transport.close()

    assert route.called
    sent_request = route.calls.last.request
    assert sent_request.headers["X-API-Key"] == "fake-key"
    assert sent_request.headers["Content-Type"] == "application/json"
    assert sent_request.content == b'{"descr":"updated"}'
    assert response.status_code == 200


@respx.mock
def test_request_without_body_sends_no_content_type_and_no_content():
    route = respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()

    sent_request = route.calls.last.request
    assert "Content-Type" not in sent_request.headers
    assert sent_request.content == b""


@respx.mock
def test_connect_error_raises_transport_connection_error():
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=httpx.ConnectError("boom"))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError):
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()


@respx.mock
def test_connect_error_message_classifies_a_tls_certificate_failure():
    # v1.0.0 Product/UX arc (UX-D): httpx/httpcore collapse DNS
    # failure, connection-refused, and a TLS certificate-verification
    # failure into the same exception class -- this asserts the
    # message text itself now distinguishes them, using the exact
    # wording httpcore produces for a real cert-verify failure
    # (confirmed live against self-signed.badssl.com during this
    # arc's UX-D investigation).
    cause = ConnectionError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=_connect_error_with_cause(cause))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError) as excinfo:
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()
    assert "TLS certificate verification failed" in str(excinfo.value)


@respx.mock
def test_connect_error_message_classifies_dns_failure():
    cause = ConnectionError("[Errno -2] Name or service not known")
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=_connect_error_with_cause(cause))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError) as excinfo:
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()
    assert "hostname could not be resolved" in str(excinfo.value)


@respx.mock
def test_connect_error_message_classifies_connection_refused():
    cause = ConnectionError("[Errno 111] Connection refused")
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=_connect_error_with_cause(cause))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError) as excinfo:
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()
    assert "refused the connection" in str(excinfo.value)


@respx.mock
def test_connect_error_message_falls_back_to_generic_wording_for_unrecognized_cause():
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=httpx.ConnectError("boom"))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError) as excinfo:
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()
    assert "could not be reached" in str(excinfo.value)


# --- structured TLS verify_code classification (v1.0.0 clean-room finding, 2026-08-29) ---
#
# Real human clean-room acceptance testing against a real LAB target with a
# correctly-trusted private CA connected to by IP address (instead of the
# certificate's own DNS name) got only "TLS certificate verification failed
# -- the server's certificate could not be verified" -- concealing that the
# trust chain was actually fine and only the hostname/IP identity check
# failed. `_classify_ssl_verification_error()` walks `__context__` (not
# `__cause__`, which httpcore/httpx never populate with the real
# ssl.SSLCertVerificationError -- see the module's own top-level comment)
# for the genuine exception with its structured `.verify_code`/
# `.verify_message`. These tests build the exact real exception chain shape
# (httpx.ConnectError -> __context__ -> httpcore-shaped wrapper ->
# __context__ -> a real ssl.SSLCertVerificationError with genuine verify_code
# set) to prove the classification without needing a real socket/certificate.


def _exception_with_ssl_context_chain(verify_code: int, verify_message: str) -> httpx.ConnectError:
    """Mirrors the real shape confirmed live: httpx.ConnectError's own
    __context__ is an httpcore-style ConnectError, whose own __context__
    is the real ssl.SSLCertVerificationError with populated verify_code/
    verify_message -- reachable even though raise ... from None (used by
    real httpcore) clears __cause__/traceback display, never __context__
    itself (PEP 3134). NOTE: this exact chain only survives if the
    returned exception is inspected directly (as the tests below do,
    calling `_classify_connect_failure()`/`_classify_ssl_verification_error()`
    straight from `pfsense_mcp.transport.http`) -- routing it back through
    `respx`'s own `side_effect` raises it fresh from a different call
    frame, which (per Python's raise semantics) resets `__context__` to
    whatever respx itself happens to be handling, discarding this
    constructed chain. That is a property of the test double, not of
    real httpx/httpcore (confirmed against a real local TLS server in
    `test_ip_address_mismatch_end_to_end_against_a_real_server` below)."""

    ssl_error = ssl.SSLCertVerificationError()
    ssl_error.verify_code = verify_code
    ssl_error.verify_message = verify_message
    ssl_error.args = (1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {verify_message}")

    try:
        raise ssl_error
    except ssl.SSLCertVerificationError:
        try:
            raise ConnectionError(str(ssl_error)) from None  # httpcore-shaped inner wrapper
        except ConnectionError as httpcore_shaped:
            try:
                raise httpx.ConnectError(str(httpcore_shaped)) from None
            except httpx.ConnectError as outer:
                return outer


def test_hostname_mismatch_is_distinguished_from_generic_tls_failure():
    from pfsense_mcp.transport.http import _classify_connect_failure

    exc = _exception_with_ssl_context_chain(62, "Hostname mismatch, certificate is not valid for 'wrong.invalid'.")
    message = _classify_connect_failure(exc)
    assert "certificate authority is trusted" in message
    assert "not valid for the address you connected to" in message
    assert "Hostname mismatch" in message


def test_ip_address_mismatch_is_distinguished_from_generic_tls_failure():
    """The exact real-LAB scenario: connecting by IP to a certificate
    whose SAN is DNS-only. verify_code=64 is OpenSSL's own stable
    X509_V_ERR_IP_ADDRESS_MISMATCH constant, independently confirmed via
    `openssl s_client -verify_ip ... -verify_return_error` during this
    arc's own investigation."""
    from pfsense_mcp.transport.http import _classify_connect_failure

    exc = _exception_with_ssl_context_chain(64, "IP address mismatch, certificate is not valid for '192.168.250.1'.")
    message = _classify_connect_failure(exc)
    assert "certificate authority is trusted" in message
    assert "connect using the exact hostname" in message
    assert "IP address mismatch" in message


def test_untrusted_ca_is_distinguished_from_hostname_mismatch():
    from pfsense_mcp.transport.http import _classify_connect_failure

    exc = _exception_with_ssl_context_chain(20, "unable to get local issuer certificate")
    message = _classify_connect_failure(exc)
    assert "certificate authority that signed the server's certificate is not trusted" in message
    assert "PFSENSE_TLS_CA_FILE" in message
    assert "not valid for the address" not in message  # never conflated with an identity mismatch


def test_self_signed_certificate_is_classified_as_untrusted_ca():
    from pfsense_mcp.transport.http import _classify_connect_failure

    exc = _exception_with_ssl_context_chain(18, "self-signed certificate")
    assert "not trusted" in _classify_connect_failure(exc)


def test_expired_certificate_is_distinguished():
    from pfsense_mcp.transport.http import _classify_connect_failure

    exc = _exception_with_ssl_context_chain(10, "certificate has expired")
    assert "has expired" in _classify_connect_failure(exc)


def test_not_yet_valid_certificate_is_distinguished():
    from pfsense_mcp.transport.http import _classify_connect_failure

    exc = _exception_with_ssl_context_chain(9, "certificate is not yet valid")
    assert "not yet valid" in _classify_connect_failure(exc)


def test_unrecognized_verify_code_falls_back_to_generic_message_never_guesses():
    """A verify_code this classifier does not specifically recognize
    must fall back to the pre-existing marker-based classification --
    never a fabricated specific-sounding message for an unrecognized code."""
    from pfsense_mcp.transport.http import _classify_connect_failure

    exc = _exception_with_ssl_context_chain(99, "some future OpenSSL verify failure this code does not know")
    assert "TLS certificate verification failed" in _classify_connect_failure(exc)


def test_no_ssl_error_in_context_chain_falls_back_to_marker_classification():
    """No ssl.SSLCertVerificationError anywhere in __context__ (e.g. a
    future httpx/httpcore that stops setting it, or a non-CPython ssl
    implementation) must never crash and must fall back to the
    pre-existing, already-tested marker-based classification."""
    from pfsense_mcp.transport.http import _classify_connect_failure

    cause = ConnectionError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")
    exc = _connect_error_with_cause(cause)
    assert "TLS certificate verification failed" in _classify_connect_failure(exc)


def test_never_suggests_insecure_bypass_for_any_tls_classification():
    from pfsense_mcp.transport.http import _classify_connect_failure

    for code, message in ((62, "hostname mismatch"), (64, "IP mismatch"), (20, "untrusted"), (18, "self-signed")):
        exc = _exception_with_ssl_context_chain(code, message)
        lowered = _classify_connect_failure(exc).lower()
        for forbidden in ("verify=false", "-k ", "insecure mode", "skip verification", "disable verification"):
            assert forbidden not in lowered


def test_ip_address_mismatch_end_to_end_against_a_real_server():
    """No mocking anywhere: a real local self-signed-CA HTTPS server
    whose certificate SAN is DNS-only, connected to by IP address --
    proves the full real httpx/httpcore/ssl exception chain (not a
    hand-built stand-in) actually reaches the same specific
    classification through the real `HttpTransport.request()` path."""
    import ssl as ssl_module
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    key_pem, cert_pem = _generate_self_signed_dns_only_cert()
    ca_path = tmp_dir = None
    try:
        import tempfile
        from pathlib import Path

        tmp_dir = tempfile.mkdtemp()
        key_path = Path(tmp_dir) / "server.key"
        cert_path = Path(tmp_dir) / "server.crt"
        key_path.write_bytes(key_pem)
        cert_path.write_bytes(cert_pem)
        ca_path = cert_path  # self-signed: the cert is its own CA

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_args):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        port = httpd.server_address[1]
        ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            transport = HttpTransport(f"https://127.0.0.1:{port}", "fake-key", verify=str(ca_path))
            try:
                with pytest.raises(TransportConnectionError) as excinfo:
                    transport.request("GET", "/")
            finally:
                transport.close()
            message = str(excinfo.value)
            assert "certificate authority is trusted" in message
            assert "connect using the exact hostname" in message
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
    finally:
        if tmp_dir is not None:
            import shutil

            shutil.rmtree(tmp_dir, ignore_errors=True)


def _generate_self_signed_dns_only_cert() -> tuple[bytes, bytes]:
    """Generates a fresh, throwaway self-signed key/cert pair (DNS-only
    SAN, no IP SAN) purely in-process via the `cryptography` package
    (already a transitive dependency of this project's own `httpx`/TLS
    stack) -- no external `openssl` CLI dependency for this test."""

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pfsense-test.lab.invalid")])
    import datetime

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("pfsense-test.lab.invalid")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


@respx.mock
def test_connect_timeout_is_proven_not_sent_for_transition_accounting():
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=httpx.ConnectTimeout("hidden"))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportRequestNotSentError):
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()


@respx.mock
def test_timeout_raises_transport_timeout_error():
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=httpx.TimeoutException("boom"))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportTimeoutError):
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()


@respx.mock
def test_other_httpx_transport_error_is_sanitized():
    secret = "SYNTHETIC-SECRET-MUST-NOT-ESCAPE"
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(
        side_effect=httpx.RemoteProtocolError(secret)
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError) as excinfo:
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()

    assert secret not in str(excinfo.value)


@respx.mock
def test_basic_auth_transport_sends_only_basic_auth_and_json_headers():
    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = BasicAuthHttpTransport(
        "https://pfsense.example.invalid", "synthetic-service-user", "synthetic:password", True
    )

    response = transport.request("POST", "/api/v2/auth/key", body=b'{"descr":"bootstrap"}')

    sent_request = route.calls.last.request
    expected = base64.b64encode(b"synthetic-service-user:synthetic:password").decode("ascii")
    assert sent_request.headers["Authorization"] == f"Basic {expected}"
    assert "X-API-Key" not in sent_request.headers
    assert sent_request.headers["Accept"] == "application/json"
    assert sent_request.headers["Content-Type"] == "application/json"
    assert sent_request.content == b'{"descr":"bootstrap"}'
    assert response.status_code == 200


@pytest.mark.parametrize(
    ("base_url", "username", "password", "verify"),
    [
        ("http://pfsense.example.invalid", "svc", "password", True),
        ("https://user@pfsense.example.invalid", "svc", "password", True),
        ("https://pfsense.example.invalid/api", "svc", "password", True),
        ("https://pfsense.example.invalid", "", "password", True),
        ("https://pfsense.example.invalid", " svc", "password", True),
        ("https://pfsense.example.invalid", "svc:other", "password", True),
        ("https://pfsense.example.invalid", "svc\nother", "password", True),
        ("https://pfsense.example.invalid", "svc", "", True),
        ("https://pfsense.example.invalid", "svc", " password", True),
        ("https://pfsense.example.invalid", "svc", "pass\rword", True),
        ("https://pfsense.example.invalid", "svc", "password", False),
        ("https://pfsense.example.invalid", "svc", "password", ""),
    ],
)
def test_basic_auth_transport_rejects_unsafe_or_ambiguous_configuration(base_url, username, password, verify):
    with pytest.raises(TransportConfigurationError):
        BasicAuthHttpTransport(base_url, username, password, verify)


def test_basic_auth_invalid_credential_value_is_not_exposed_by_error():
    canary = "SYNTHETIC-CREDENTIAL-CANARY"

    with pytest.raises(TransportConfigurationError) as excinfo:
        BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", f"{canary}\n", True)
    assert canary not in str(excinfo.value)


def test_basic_auth_transport_repr_never_contains_credentials():
    username = "synthetic-service-user"
    password = "SYNTHETIC-CREDENTIAL-CANARY"
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", username, password, True)
    try:
        rendered = repr(transport)
    finally:
        transport.close()

    assert username not in rendered
    assert password not in rendered
    assert rendered == "BasicAuthHttpTransport(single_use=True)"


@respx.mock
def test_basic_auth_transport_is_single_use_and_never_retries():
    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        side_effect=httpx.ReadTimeout("SYNTHETIC-CREDENTIAL-CANARY")
    )
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    with pytest.raises(TransportTimeoutError) as excinfo:
        transport.request("POST", "/api/v2/auth/key", body=b"{}")
    with pytest.raises(TransportConfigurationError):
        transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert len(route.calls) == 1
    assert "SYNTHETIC-CREDENTIAL-CANARY" not in str(excinfo.value)


@respx.mock
def test_basic_auth_transport_does_not_follow_redirects():
    first = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        return_value=httpx.Response(307, headers={"Location": "https://other.example.invalid/collect"})
    )
    redirected = respx.post("https://other.example.invalid/collect").mock(
        return_value=httpx.Response(200, text="unexpected")
    )
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    response = transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert response.status_code == 307
    assert len(first.calls) == 1
    assert len(redirected.calls) == 0


@respx.mock
def test_closing_unused_basic_auth_transport_sends_nothing_and_consumes_it():
    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        return_value=httpx.Response(200, text='{"status":"unexpected"}')
    )
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    transport.close()

    with pytest.raises(TransportConfigurationError):
        transport.request("POST", "/api/v2/auth/key", body=b"{}")
    assert len(route.calls) == 0


def test_basic_auth_close_failure_is_sanitized(monkeypatch):
    canary = "SYNTHETIC-CREDENTIAL-CANARY"

    class CloseFailingClient:
        def request(self, method, path, *, content, headers):
            return httpx.Response(200, text='{"status":"ok"}')

        def close(self):
            raise RuntimeError(canary)

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: CloseFailingClient())
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", canary, True)

    with pytest.raises(TransportConnectionError) as excinfo:
        transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert canary not in str(excinfo.value)


def test_basic_auth_request_error_remains_sanitized_when_close_also_fails(monkeypatch):
    canary = "SYNTHETIC-CREDENTIAL-CANARY"

    class RequestAndCloseFailingClient:
        def request(self, method, path, *, content, headers):
            raise httpx.ReadTimeout(canary)

        def close(self):
            raise RuntimeError(canary)

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: RequestAndCloseFailingClient())
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", canary, True)

    with pytest.raises(TransportTimeoutError) as excinfo:
        transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert canary not in str(excinfo.value)


@respx.mock
def test_basic_auth_transport_error_does_not_echo_method_or_path():
    canary = "SYNTHETIC-CREDENTIAL-CANARY"
    respx.route().mock(side_effect=httpx.ConnectError("synthetic failure"))
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    with pytest.raises(TransportConnectionError) as excinfo:
        transport.request(f"POST-{canary}", f"/api/v2/auth/key?value={canary}", body=b"{}")

    assert canary not in str(excinfo.value)
