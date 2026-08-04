"""Dependency factory: constructs Transport, RestApiClient, and
PfSenseClient from a validated PfSenseConfig + loaded API key.

Kept separate from Application so construction logic can be tested
independently of MCP server startup/lifecycle.
"""

from __future__ import annotations

from .config import PfSenseConfig
from .pfsense_client import PfSenseClient
from .rest_api_client import RestApiClient
from .tls import resolve_verify
from .transport.http import HttpTransport


def build_pfsense_client(config: PfSenseConfig, api_key: str) -> tuple[HttpTransport, PfSenseClient]:
    """Returns (transport, client). The caller owns the transport's
    lifecycle (close() must be called on shutdown)."""
    verify = resolve_verify(config.tls_mode, config.tls_ca_file)
    transport = HttpTransport(config.base_url, api_key, verify)
    rest_client = RestApiClient(transport, identity=config.identity, api_version=config.api_version)
    client = PfSenseClient(rest_client)
    return transport, client
