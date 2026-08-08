"""Inert Tier 1 safety primitives.

This package is deliberately not imported by the production application,
factory, tool registry, or READ client. It contains no endpoint, transport,
tool registration, or mutation executor.
"""

from .audit import Tier1AuditEvent
from .canonical import DigestPurpose, canonical_json, digest_value
from .contract import ProtectedArtifact, RecoveryContract
from .policy import INACTIVE_TIER1_POLICY, MutationPolicy, MutationRule
from .state_machine import RecoveryState
from .store import SqliteRecoveryContractStore

__all__ = [
    "DigestPurpose",
    "INACTIVE_TIER1_POLICY",
    "MutationPolicy",
    "MutationRule",
    "ProtectedArtifact",
    "RecoveryContract",
    "RecoveryState",
    "SqliteRecoveryContractStore",
    "Tier1AuditEvent",
    "canonical_json",
    "digest_value",
]
