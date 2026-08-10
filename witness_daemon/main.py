"""Entrypoint: `python -m witness_daemon`. Wires configuration -> TPM
client -> witness service -> mTLS-wrapped HTTP server, then serves
forever. Not invoked by anything in this repository automatically --
this is the process a deployer starts on the Proxmox host (by hand for
now, or via the shipped-but-not-enabled systemd unit under
`witness_daemon/systemd/`), never something `pfsense-mcp-server` itself
spawns.

Deliberately the only module in this package that touches `ssl`
directly: certificate/key loading and mutual-TLS enforcement are
security-critical setup performed exactly once at process start, kept
out of `http_server.py` so that module's own review surface stays
limited to request routing.
"""

from __future__ import annotations

import ssl
import sys

from .config import WitnessDaemonConfig, load_witness_daemon_config
from .errors import WitnessError
from .http_server import WitnessHTTPServer
from .service import WitnessService
from .tpm_cli import Tpm2ToolsClient


def build_ssl_context(config: WitnessDaemonConfig) -> ssl.SSLContext:
    """Mutual TLS, matching this project's own established
    `TLSMode.STRICT`-only trust discipline applied to this new boundary:
    the daemon requires and verifies a client certificate signed by the
    pinned client CA on every connection -- never optional, never
    downgraded."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(config.server_cert_path), keyfile=str(config.server_key_path))
    context.load_verify_locations(cafile=str(config.client_ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def build_server(config: WitnessDaemonConfig) -> WitnessHTTPServer:
    tpm_client = Tpm2ToolsClient(nv_handle=config.nv_handle, auth_credential_path=config.auth_credential_path)
    service = WitnessService(tpm_client)
    server = WitnessHTTPServer((config.bind_host, config.bind_port), service)
    context = build_ssl_context(config)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> int:
    try:
        config = load_witness_daemon_config()
    except WitnessError as exc:
        print(f"witness_daemon: configuration error: {exc}", file=sys.stderr)
        return 1

    server = build_server(config)
    print(f"witness_daemon: listening on {config.bind_host}:{config.bind_port}, handle {config.nv_handle}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
