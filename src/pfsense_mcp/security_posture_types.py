"""Pure, dependency-free data shapes for `ADR-021`'s two-axis security
posture model.

Extracted from `security_discovery.py` (2026-09-05, ADR-021/022
amendment for the AnchorEvidenceExport signer-verification path) for
the exact same reason `ResolvedTransportTarget` was extracted from
`tier1/executor.py` into `tier1/transport_target.py` under ADR-028: a
type definition that itself has no dependency on a heavier module was
sitting inside one, so anything needing only the type paid for the
whole module's import graph. Here, `AnchorAssuranceDiscovery` (and its
siblings) previously lived in `security_discovery.py`, which
unconditionally imports `pfsense_mcp.tier1.production_store` (and
therefore `sqlite3`) for its *other* function, `discover_anchor_
assurance()`. The new signer-side `discover_anchor_assurance_from_
export()` (`security_discovery_export.py`) needs these exact types but
must never import `sqlite3`/`production_store.py` merely to get them.

Zero project-internal imports. `security_discovery.py` re-exports every
name here unchanged (`from .security_posture_types import X as X`) so
every existing caller (`security_plan.py`, `security_cli.py`,
`tests/test_security_discovery*.py`) continues to import them from
`security_discovery` exactly as before -- this file is an
implementation detail of where the type now *lives*, not a change to
where callers import it *from*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CapabilityPosture(str, Enum):
    """The accepted `ADR-021` capability-posture axis. Deliberately only
    these two values -- never collapsed with anchor assurance into a
    three-level ladder (`ADR-021`'s own rejected Model A)."""

    READ_ONLY = "read_only"
    WRITE_PROTECTED = "write_protected"


class AnchorAssurance(str, Enum):
    """The accepted `ADR-021` anchor-assurance axis. `SOFTWARE` is a
    real value in the model but is never resolved by either discovery
    path today -- `docs/SECURITY_POSTURE_PROVISIONING.md` records that
    no remote-witness backend exists anywhere in this repository yet
    (Phase G, unimplemented); reporting it would assert a capability
    that cannot currently be verified."""

    NONE = "none"
    SOFTWARE = "software"
    HARDWARE_WITNESS = "hardware_witness"
    UNKNOWN = "unknown"


class AnchorEvidenceState(str, Enum):
    """Finer-grained evidence trail behind `AnchorAssurance`'s coarse
    value -- required so discovery can distinguish "nothing configured"
    from "configured but not provisioned" from "provisioned but the
    live witness could not be verified", per `ADR-021` Phase B's own
    "do not infer ACTIVE merely because files or configuration exist"
    requirement. Shared, unchanged, by both the store-backed and
    export-backed anchor-assurance discovery paths."""

    UNCONFIGURED = "unconfigured"
    CONFIGURATION_INVALID = "configuration_invalid"
    CONFIGURED_NOT_CREATED = "configured_not_created"
    STORE_ERROR = "store_error"
    CONFIGURED_UNPROVISIONED = "configured_unprovisioned"
    PROVISIONED_UNVERIFIED = "provisioned_unverified"
    PROVISIONED_UNREACHABLE = "provisioned_unreachable"
    PROVISIONED_VERIFIED = "provisioned_verified"
    PROVISIONED_MISMATCH = "provisioned_mismatch"


@dataclass(frozen=True)
class CapabilityPostureDiscovery:
    value: CapabilityPosture
    configured_profile_name: str
    configured_profile_valid: bool
    write_capabilities_active: int
    write_capabilities_total: int
    allow_list_entries: tuple[str, ...]
    evidence: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class AnchorAssuranceDiscovery:
    value: AnchorAssurance
    evidence_state: AnchorEvidenceState
    store_configured: bool
    store_exists: bool | None
    seeded: bool | None
    complete: bool | None
    handle: str | None
    baseline: int | None
    provisioned_at: str | None
    witness_configured: bool
    witness_reachable: bool | None
    witness_value: int | None
    witness_matches_baseline: bool | None
    evidence: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecurityPostureDiscovery:
    capability_posture: CapabilityPostureDiscovery
    anchor_assurance: AnchorAssuranceDiscovery


__all__ = [
    "AnchorAssurance",
    "AnchorAssuranceDiscovery",
    "AnchorEvidenceState",
    "CapabilityPosture",
    "CapabilityPostureDiscovery",
    "SecurityPostureDiscovery",
]
