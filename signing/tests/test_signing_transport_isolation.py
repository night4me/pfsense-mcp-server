"""ADR-028's "Signing-side CLI trust boundary" requirement, checked
directly rather than trusted by convention: "Contains zero pfSense
mutation capability: no import of, or path to, any pfSense-reaching
transport; never contacts pfSense and never invokes any MCP WRITE path,
directly or indirectly."

Discovered violated 2026-08-16 while provisioning an off-host signer for
W3 Slice 6 live acceptance: `signing/alias_description_signing.py`
imports `pfsense_mcp.tier1.artifact_exchange` -> `pfsense_mcp.tier1.
alias_description`, which (before the fix accompanying this test)
imported `ResolvedTransportTarget` from `pfsense_mcp.tier1.executor` for
a type hint alone -- and `executor.py` itself imports the real
`WriteApiClient`/`PfSenseClient`. Fixed by moving `ResolvedTransportTarget`
to the dependency-free `pfsense_mcp.tier1.transport_target` (see that
module's docstring). This test proves the fix and guards against
regression: any future change that reintroduces a transitive dependency
on a pfSense-reaching transport module must fail this test, not be
discovered by accident during a live provisioning session again.
"""

from __future__ import annotations

import sys

_FORBIDDEN_MODULES = (
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.transport.base",
    "pfsense_mcp.transport.http",
    "pfsense_mcp.transport.mock",
    "pfsense_mcp.tier1.executor",
    "pfsense_mcp.tier1.production_runtime",
    "pfsense_mcp.factory",
    "pfsense_mcp.application",
    "pfsense_mcp.server",
)


def test_importing_signing_module_never_loads_a_pfsense_reaching_transport():
    for name in list(sys.modules):
        if name in _FORBIDDEN_MODULES or (name.startswith("pfsense_mcp.tools")):
            del sys.modules[name]
    if "signing.alias_description_signing" in sys.modules:
        del sys.modules["signing.alias_description_signing"]

    import signing.alias_description_signing  # noqa: F401

    loaded = {name for name in sys.modules if name.startswith("pfsense_mcp")}
    offenders = sorted(name for name in loaded if name in _FORBIDDEN_MODULES or name.startswith("pfsense_mcp.tools"))
    assert offenders == []
