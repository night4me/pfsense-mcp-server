"""Concrete Nexus READ adapters (Phase D, ADR-030/ADR-031).

Deliberately narrow scope: this package contains pure, deterministic
normalization logic that turns an already-fetched, already-parsed
Nexus JSON response into an existing domain model -- never the HTTP
transport, JWT login/refresh flow, or the
`{controller}/api/device/{device_type}/{device_id}/api...` device
base-path construction confirmed in Phase B
(docs/NEXUS_COMPATIBILITY_MATRIX.md). Building an actual Nexus HTTP
client is separate, materially larger infrastructure work, not
specific to any one capability, and out of scope for "the smallest
isolated adapter" this phase's own authorization calls for -- doing so
now would be exactly the "unrelated refactoring" the owner's Phase D
message explicitly forbade. Each reader here takes the raw response
dict directly (or a caller-supplied fetch function returning one),
mirroring how `pfsense_client.py`'s own `_parse_object_response()` /
`_parse_list_response()` separate "get the raw dict from wherever"
from "validate and construct the typed model."

Not imported by, and never reachable from, `factory.py`,
`tools/registry.py`, `application.py`, or `tier1/` -- same isolation
guarantee as the rest of `pfsense_mcp.backends`
(`tests/backends/test_isolation.py`).
"""
