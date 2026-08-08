"""Protected-artifact encryption codec for inert Tier 1 records.

Not constructed by production. AES-256-GCM via `cryptography`, with a
domain-separated, length-framed associated-data binding that ties each
artifact to its exact contract and role so ciphertext cannot be
substituted across contracts or fields even with the correct key. This
module never generates or persists nonce state itself -- see
key_lifecycle.py's NonceCounter, which owns that durability property; a
caller assembles a nonce via build_nonce() from a key's epoch and a
freshly-issued NonceCounter value before calling encrypt_artifact().

See docs/tier1/specs/protected_artifact_encryption.md for the full
specification and docs/adr/ADR-009 for why AES-256-GCM was selected.
"""

from __future__ import annotations

from enum import Enum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import frame_str
from .contract import ProtectedArtifact
from .errors import ArtifactDecryptionError

_KEY_BYTES = 32
_NONCE_BYTES = 12
_EPOCH_BYTES = 4
_COUNTER_BYTES = 8
_MAX_EPOCH = 2**32
_MAX_COUNTER = 2**64
_DOMAIN_PREFIX = "pfSense-MCP/Tier1/ArtifactAEAD/v1"


class ArtifactAlgorithm(str, Enum):
    AES_256_GCM_V1 = "aes-256-gcm-v1"


class ArtifactRole(str, Enum):
    TARGET_IDENTITY = "target-identity"
    INTENT = "intent"
    SNAPSHOT = "snapshot"


def build_nonce(*, epoch: int, counter: int) -> bytes:
    """Assemble a 12-byte AES-GCM nonce from a key's epoch and a
    key_lifecycle.NonceCounter value that has already been durably
    persisted. Never derive a nonce any other way -- see
    key_lifecycle.md for why a random 96-bit nonce is unsafe here."""

    if not isinstance(epoch, int) or isinstance(epoch, bool) or not (0 <= epoch < _MAX_EPOCH):
        raise ArtifactDecryptionError("Nonce epoch is invalid.")
    if not isinstance(counter, int) or isinstance(counter, bool) or not (0 <= counter < _MAX_COUNTER):
        raise ArtifactDecryptionError("Nonce counter is invalid.")
    return epoch.to_bytes(_EPOCH_BYTES, "big") + counter.to_bytes(_COUNTER_BYTES, "big")


def _associated_data(contract_id: str, role: ArtifactRole) -> bytes:
    return frame_str(_DOMAIN_PREFIX) + frame_str(contract_id) + frame_str(role.value)


def encrypt_artifact(
    *,
    key: bytes,
    key_id: str,
    contract_id: str,
    role: ArtifactRole,
    plaintext: bytes,
    nonce: bytes,
) -> ProtectedArtifact:
    """Encrypt `plaintext` under `key`, binding the ciphertext to
    `contract_id`/`role` via associated data. `nonce` must be exactly 12
    bytes and must never have been used before under `key` -- callers
    are expected to build it via build_nonce() from a freshly-issued
    NonceCounter value."""

    if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
        raise ArtifactDecryptionError("Encryption key must be exactly 32 bytes.")
    if not isinstance(nonce, bytes) or len(nonce) != _NONCE_BYTES:
        raise ArtifactDecryptionError("Nonce must be exactly 12 bytes.")
    if not isinstance(plaintext, bytes):
        raise ArtifactDecryptionError("Plaintext must be bytes.")

    sealed = AESGCM(key).encrypt(nonce, plaintext, _associated_data(contract_id, role))
    return ProtectedArtifact(
        key_id=key_id,
        algorithm=ArtifactAlgorithm.AES_256_GCM_V1.value,
        ciphertext=nonce + sealed,
    )


def decrypt_artifact(
    *,
    key: bytes,
    artifact: ProtectedArtifact,
    contract_id: str,
    role: ArtifactRole,
) -> bytes:
    """Decrypt and authenticate `artifact`. Raises ArtifactDecryptionError
    -- never anything else -- on a wrong key, tampered ciphertext, an
    unrecognized algorithm, or artifact/AAD substitution across contracts
    or roles. Never returns partially-verified plaintext: the AEAD tag is
    checked before any byte is returned."""

    if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
        raise ArtifactDecryptionError("Decryption key must be exactly 32 bytes.")
    try:
        algorithm = ArtifactAlgorithm(artifact.algorithm)
    except ValueError:
        raise ArtifactDecryptionError("Protected artifact algorithm is not recognized.") from None
    if algorithm != ArtifactAlgorithm.AES_256_GCM_V1:
        raise ArtifactDecryptionError("Protected artifact algorithm is not supported.")
    if len(artifact.ciphertext) <= _NONCE_BYTES:
        raise ArtifactDecryptionError("Protected artifact ciphertext is too short.")

    nonce, sealed = artifact.ciphertext[:_NONCE_BYTES], artifact.ciphertext[_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, sealed, _associated_data(contract_id, role))
    except (InvalidTag, ValueError):
        raise ArtifactDecryptionError("Protected artifact failed authenticated decryption.") from None
