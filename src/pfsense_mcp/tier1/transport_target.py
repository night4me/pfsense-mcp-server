"""`ResolvedTransportTarget` -- factored out of `executor.py` so capability
adapters (`tier1/alias_description.py`, and any future adapter) can type
their `build_request()`/`build_rollback_request()` signatures against it
without transitively importing `executor.py` -- which itself imports
`WriteApiClient`/`PfSenseClient`, a real pfSense-reaching transport chain.

This split exists for ADR-028's own "Signing-side CLI trust boundary"
requirement ("no import of, or path to, any pfSense-reaching transport"):
`signing/alias_description_signing.py` imports `tier1/artifact_exchange.py`
-> `tier1/alias_description.py` for the shared request model and semantic
unit constant, and before this split that chain transitively pulled in
`write_api_client.py`/`pfsense_client.py`/`transport/` purely because of
this one type hint -- discovered 2026-08-16 while provisioning an off-host
signer for W3 Slice 6 live acceptance. `executor.py` re-exports this class
unchanged (`from .transport_target import ResolvedTransportTarget`), so
every existing `from .executor import ResolvedTransportTarget` /
`from pfsense_mcp.tier1.executor import ResolvedTransportTarget` caller is
unaffected."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import ContractValidationError

_HEX_64 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ResolvedTransportTarget:
    """Fresh executor-owned transport projection for one exact semantic target."""

    numeric_locator: int
    target_identity_digest: str

    def __post_init__(self) -> None:
        if type(self.numeric_locator) is not int or not 0 <= self.numeric_locator <= 2_147_483_647:
            raise ContractValidationError("Resolved transport locator is invalid.")
        if not isinstance(self.target_identity_digest, str) or not _HEX_64.fullmatch(self.target_identity_digest):
            raise ContractValidationError("Resolved transport target identity is invalid.")
