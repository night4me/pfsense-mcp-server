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

**Found violated a second time, 2026-09-04**, this time for the
generalized Shape-A signer (`signing/write_batch1_signing.py`), while
deriving its dependency closure for the same VMID 100 isolated signer:
`pfsense_mcp.tier1.shape_a_registry` imported `WriteExecutionCoreV1` from
`write_execution_core.py` (itself importing `.executor` ->
`write_api_client.py`) for one method's return-type annotation alone --
the exact same shape of bug, in a different file, that this test's
original case already existed to prevent, just not extended to cover the
newer module. Fixed the same way (deferred to `TYPE_CHECKING`); this
file now parametrizes over both signer entrypoints so neither can
regress silently again.
"""

from __future__ import annotations

import sys

import pytest

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
    "pfsense_mcp.tier1.write_execution_core",
    "pfsense_mcp.tier1.write_batch1_production_runtime",
    "pfsense_mcp.factory",
    "pfsense_mcp.application",
    "pfsense_mcp.server",
)


@pytest.mark.parametrize("signing_module", ["signing.alias_description_signing", "signing.write_batch1_signing"])
def test_importing_signing_module_never_loads_a_pfsense_reaching_transport(signing_module):
    for name in list(sys.modules):
        if name in _FORBIDDEN_MODULES or name.startswith("pfsense_mcp.tools") or name == signing_module:
            del sys.modules[name]

    __import__(signing_module)

    loaded = {name for name in sys.modules if name.startswith("pfsense_mcp")}
    offenders = sorted(name for name in loaded if name in _FORBIDDEN_MODULES or name.startswith("pfsense_mcp.tools"))
    assert offenders == []
