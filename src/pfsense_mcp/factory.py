"""Dependency factory: constructs Transport, RestApiClient, PfSenseClient,
and WriteApiClient from a validated PfSenseConfig + loaded API key.

Kept separate from Application so construction logic can be tested
independently of MCP server startup/lifecycle. This is also the one
reviewed place outside `pfsense_mcp.tier1` that constructs a
`WriteApiClient` -- `tier1/production_runtime.py` (W2) calls
`build_write_client()` below rather than importing
`pfsense_mcp.write_api_client` itself, since every `tier1/*.py` module
except `executor.py` is forbidden from importing it directly
(`tests/tier1/test_isolation.py::test_tier1_domain_has_no_transport_or_tool_registration_dependency`).
`factory.py` living outside `pfsense_mcp.tier1` is not subject to that
restriction, exactly like `build_pfsense_client()` already was for the
read client -- this is the same, already-established pattern, extended,
not a new one.
"""

from __future__ import annotations

from .config import PfSenseConfig
from .pfsense_client import PfSenseClient
from .rest_api_client import RestApiClient
from .tls import resolve_verify
from .transport.http import HttpTransport
from .write_api_client import WriteApiClient


def build_pfsense_client(config: PfSenseConfig, api_key: str) -> tuple[HttpTransport, PfSenseClient]:
    """Returns (transport, client). The caller owns the transport's
    lifecycle (close() must be called on shutdown)."""
    verify = resolve_verify(config.tls_mode, config.tls_ca_file)
    transport = HttpTransport(config.base_url, api_key, verify)
    rest_client = RestApiClient(transport, identity=config.identity, api_version=config.api_version)
    client = PfSenseClient(rest_client)
    return transport, client


def build_write_client(config: PfSenseConfig, transport: HttpTransport) -> WriteApiClient:
    """Builds a `WriteApiClient` bound to an already-constructed
    transport (reuse the same transport `build_pfsense_client()`
    returned -- never a second, independent one). Refuses nothing by
    itself: `WriteApiClient` remains a thin, allow-list-checked
    chokepoint, and `WriteEndpoints` ships empty in this build regardless
    of who holds a reference to this client."""

    return WriteApiClient(transport, identity=config.identity, api_version=config.api_version)
