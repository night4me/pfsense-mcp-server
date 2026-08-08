"""Inert Tier 1 safety primitives.

This package is deliberately not imported by the production application,
factory, tool registry, or READ client. It contains no endpoint, transport,
tool registration, or mutation executor.
"""

from .audit import Tier1AuditEvent
from .canonical import DigestPurpose, canonical_json, digest_value, frame_bytes, frame_str
from .confirmation import ConfirmationEvidence, ConfirmationVerifier
from .contract import ProtectedArtifact, RecoveryContract, derive_idempotency_key
from .crypto import ArtifactAlgorithm, ArtifactRole, build_nonce, decrypt_artifact, encrypt_artifact
from .key_lifecycle import KeyPurpose, KeyRecord, NonceCounter, RotationReport, load_key_material, rotate_key
from .policy import INACTIVE_TIER1_POLICY, MutationPolicy, MutationRule
from .state_machine import RecoveryState
from .store import SqliteRecoveryContractStore

__all__ = [
    "ArtifactAlgorithm",
    "ArtifactRole",
    "DigestPurpose",
    "ConfirmationEvidence",
    "ConfirmationVerifier",
    "INACTIVE_TIER1_POLICY",
    "KeyPurpose",
    "KeyRecord",
    "MutationPolicy",
    "MutationRule",
    "NonceCounter",
    "ProtectedArtifact",
    "RecoveryContract",
    "RecoveryState",
    "RotationReport",
    "SqliteRecoveryContractStore",
    "Tier1AuditEvent",
    "build_nonce",
    "canonical_json",
    "decrypt_artifact",
    "derive_idempotency_key",
    "digest_value",
    "encrypt_artifact",
    "frame_bytes",
    "frame_str",
    "load_key_material",
    "rotate_key",
]
