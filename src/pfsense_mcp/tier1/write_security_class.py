"""Two-tier WRITE security model (2026-09-06, owner-authorized Phase 1).

`WriteSecurityClass` is the trusted, closed classification every WRITE
capability carries: `HIGH_ASSURANCE_TIER1` (the existing, unchanged,
off-host-signed / TPM-witnessed ceremony every capability has used since
ADR-014/ADR-028/ADR-037) or `STANDARD_SEALED_WRITE` (a new, narrower,
lower-ceremony tier for a small, explicitly-reviewed set of low-consequence
mutations -- NTP_TIME_SERVER_PREFER only, this phase).

This module is a deliberate leaf: it imports nothing from elsewhere in
`tier1/` and nothing pfSense-reaching, so every signing module and every
capability/adapter registration can depend on it with zero risk of ever
pulling in transport-capable code. Never import `.executor`, `.store`,
`.shape_a_registry`, or any pfSense client from here.

The classification itself is NEVER attached here -- this module only
defines the *type* and the two execution-time behaviors it selects
between. The trusted per-capability assignment lives on the static
capability/adapter registration (`shape_a_registry.ShapeARegistration.
security_class`, plus one hardcoded literal for the alias-description
capability) -- never caller-, request-, CLI-, environment-, or
contract-selectable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Protocol


class WriteSecurityClass(str, Enum):
    #: The new, narrower tier: no off-host authorization/confirmation
    #: signature, no AnchorEvidenceExport, no TPM witness participation.
    #: A dedicated, locally-approved SealedWriteApproval (a separate
    #: Ed25519 authority/domain, never the HIGH_ASSURANCE authorities)
    #: replaces that ceremony. See docs/adr for the accepted threat-model
    #: delta -- this tier does NOT claim runtime-host-compromise
    #: resistance or off-host authorization separation.
    STANDARD_SEALED_WRITE = "standard_sealed_write"

    #: The original, unchanged, fully off-host-signed / TPM-witnessed
    #: ceremony every WRITE capability used exclusively before this
    #: phase. The default for every capability unless explicitly,
    #: reviewably opted into STANDARD_SEALED_WRITE.
    HIGH_ASSURANCE_TIER1 = "high_assurance_tier1"


class ExecutionSecurityPolicy(Protocol):
    """The one, explicit, typed seam `store.transition()` consults when
    entering `EXECUTING` -- never an ad-hoc boolean, never caller-
    controlled: the concrete instance used for any one contract is always
    selected exclusively from the authoritative static capability
    registration (`shape_a_registry.WRITE_CAPABILITY_SECURITY_CLASS`),
    keyed by that contract's own `capability`, never by anything a
    caller/request/contract payload supplies."""

    # A read-only `@property`, not a plain settable attribute: both
    # concrete implementations below are frozen dataclasses, whose
    # fields are readable but never settable -- a plain-attribute
    # Protocol member requires the implementation to support both get
    # and set, which a frozen dataclass field deliberately does not.
    # Mirrors `write_adapter_support.py`'s own `ConfiguredApplianceTargetLike`
    # fix for the identical mypy read-only-vs-settable-attribute issue.
    @property
    def security_class(self) -> WriteSecurityClass: ...

    def participates_in_witness(self) -> bool:
        """`True` iff this policy's `EXECUTING` transition must invoke
        the store's `HighWaterMark`/`AntiRollbackAnchor` gate. The rate
        policy (damage containment, not authorization) is deliberately
        NOT part of this seam -- it remains universal, unconditional, for
        both classes; only witness/anchor participation is class-gated."""
        ...


@dataclass(frozen=True, slots=True)
class HighAssuranceTier1ExecutionPolicy:
    """Reproduces the exact, unmodified, pre-existing behavior: every
    `EXECUTING` transition for a HIGH_ASSURANCE_TIER1 contract still
    invokes `HighWaterMark.before_executing_transition()` whenever the
    store has an anchor configured -- byte-for-byte the same call this
    codebase already made for every capability before this phase."""

    security_class: WriteSecurityClass = field(default=WriteSecurityClass.HIGH_ASSURANCE_TIER1, init=False)

    def participates_in_witness(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class StandardSealedExecutionPolicy:
    """Deliberately, documentedly performs NO anchor/witness contact of
    any kind at `EXECUTING`. This is a declared, adversarially-tested
    property of this policy object, not an omission."""

    security_class: WriteSecurityClass = field(default=WriteSecurityClass.STANDARD_SEALED_WRITE, init=False)

    def participates_in_witness(self) -> bool:
        return False


#: The one, fixed, closed translation from a `WriteSecurityClass` value to
#: its execution policy object. Never constructed ad hoc elsewhere --
#: `MutationExecutor.execute()` looks a contract's registry-authoritative
#: class up here, exactly once, per execution attempt.
_execution_policies: dict[WriteSecurityClass, ExecutionSecurityPolicy] = {
    WriteSecurityClass.HIGH_ASSURANCE_TIER1: HighAssuranceTier1ExecutionPolicy(),
    WriteSecurityClass.STANDARD_SEALED_WRITE: StandardSealedExecutionPolicy(),
}
EXECUTION_POLICIES: Mapping[WriteSecurityClass, ExecutionSecurityPolicy] = MappingProxyType(_execution_policies)

__all__ = [
    "EXECUTION_POLICIES",
    "ExecutionSecurityPolicy",
    "HighAssuranceTier1ExecutionPolicy",
    "StandardSealedExecutionPolicy",
    "WriteSecurityClass",
]
