"""Key lifecycle for inert Tier 1 encryption/integrity key material.

Not constructed by production. Loads key material through the same
O_NOFOLLOW/fstat()-validated descriptor discipline already proven for the
pfSense API key in `pfsense_mcp.config`, and maintains a durable,
fsync-before-return monotonic nonce counter per active encryption key so
AES-GCM nonces can never repeat under one key. See
docs/tier1/specs/key_lifecycle.md for the full specification.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..secure_file import open_nofollow, validate_descriptor
from .contract import ProtectedArtifact
from .errors import KeyExhaustedError, KeyMaterialError
from .store import SqliteRecoveryContractStore

_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_KEY_MATERIAL_BYTES = 32
_KEY_FILE_MAX_BYTES = 4096
_COUNTER_FILE_MAX_BYTES = 64

# Retirement threshold: 2**32 of the 8-byte (2**64) counter half of the
# AES-GCM nonce (see protected_artifact_encryption.md's nonce
# construction). Conservative by a wide margin; never reused for
# encryption once reached.
MAX_NONCE_COUNTER = 2**32


class KeyPurpose(str, Enum):
    ENCRYPTION = "encryption"
    INTEGRITY = "integrity"


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    epoch: int
    material: bytes
    purpose: KeyPurpose
    retired: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not _KEY_ID.fullmatch(self.key_id):
            raise KeyMaterialError("Key record identifier is invalid.")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or self.epoch < 0:
            raise KeyMaterialError("Key record epoch is invalid.")
        if not isinstance(self.material, bytes) or len(self.material) != _KEY_MATERIAL_BYTES:
            raise KeyMaterialError("Key record material must be exactly 32 bytes.")
        if not isinstance(self.purpose, KeyPurpose):
            raise KeyMaterialError("Key record purpose is invalid.")


def load_key_material(path: Path, *, purpose: KeyPurpose) -> KeyRecord:
    """Load one KeyRecord from a single-line JSON document:
    {"key_id": "...", "epoch": 0, "material_hex": "<64 lowercase hex chars>"}

    Validated through an O_NOFOLLOW-opened, fstat()-checked descriptor
    (regular file, owner-only, bounded size) — the same discipline
    already proven for the pfSense API key in pfsense_mcp.config.
    """

    descriptor = open_nofollow(path, on_error=KeyMaterialError)
    try:
        validate_descriptor(path, descriptor, max_bytes=_KEY_FILE_MAX_BYTES, on_error=KeyMaterialError)
        try:
            raw = os.read(descriptor, _KEY_FILE_MAX_BYTES + 1)
        except OSError:
            raise KeyMaterialError(f"Key material file could not be read: {path}") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise KeyMaterialError(f"Key material descriptor could not be closed: {path}") from None

    if len(raw) > _KEY_FILE_MAX_BYTES:
        raise KeyMaterialError(f"Key material file is too large: {path}")

    try:
        text = raw.decode("utf-8").strip()
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeyMaterialError(f"Key material file is not valid JSON: {path}") from exc

    if not isinstance(value, dict) or set(value) != {"key_id", "epoch", "material_hex"}:
        raise KeyMaterialError(f"Key material file has an unexpected shape: {path}")
    key_id, epoch, material_hex = value["key_id"], value["epoch"], value["material_hex"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise KeyMaterialError(f"Key material file has an invalid key_id: {path}")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise KeyMaterialError(f"Key material file has an invalid epoch: {path}")
    if not isinstance(material_hex, str) or not _HEX_64.fullmatch(material_hex):
        raise KeyMaterialError(f"Key material file has invalid material encoding: {path}")

    return KeyRecord(key_id=key_id, epoch=epoch, material=bytes.fromhex(material_hex), purpose=purpose)


class NonceCounter:
    """Durable, fsync-before-return monotonic counter scoped to one
    KeyRecord. One instance per active encryption key. The counter is
    persisted and fsynced *before* `next()` returns, so a crash can only
    skip counter values (safe) and never reuse one (unsafe)."""

    def __init__(self, path: Path, *, key_id: str) -> None:
        if not _KEY_ID.fullmatch(key_id):
            raise KeyMaterialError("Nonce counter key identifier is invalid.")
        self._path = path
        self._key_id = key_id
        self._prepare()

    def _prepare(self) -> None:
        if not self._path.exists():
            self._write(0)
            return
        self._read()  # validates the existing file is parseable and matches this key_id

    def _read(self) -> int:
        descriptor = open_nofollow(self._path, on_error=KeyMaterialError)
        try:
            validate_descriptor(self._path, descriptor, max_bytes=_COUNTER_FILE_MAX_BYTES, on_error=KeyMaterialError)
            try:
                raw = os.read(descriptor, _COUNTER_FILE_MAX_BYTES + 1)
            except OSError:
                raise KeyMaterialError(f"Nonce counter file could not be read: {self._path}") from None
        finally:
            try:
                os.close(descriptor)
            except OSError:
                raise KeyMaterialError(f"Nonce counter descriptor could not be closed: {self._path}") from None

        if len(raw) > _COUNTER_FILE_MAX_BYTES:
            raise KeyMaterialError(f"Nonce counter file is too large: {self._path}")
        try:
            value = json.loads(raw.decode("utf-8").strip())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KeyMaterialError(f"Nonce counter file is corrupted: {self._path}") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"key_id", "counter"}
            or value["key_id"] != self._key_id
            or not isinstance(value["counter"], int)
            or isinstance(value["counter"], bool)
            or value["counter"] < 0
        ):
            raise KeyMaterialError(f"Nonce counter file does not match this key: {self._path}")
        return int(value["counter"])

    def _write(self, counter: int) -> None:
        payload = json.dumps({"key_id": self._key_id, "counter": counter}).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self._path, flags, 0o600)
        try:
            os.ftruncate(fd, 0)
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)

    def next(self) -> int:
        """Increment and durably persist before returning the new value.
        Raises KeyExhaustedError once MAX_NONCE_COUNTER is reached."""

        current = self._read()
        if current >= MAX_NONCE_COUNTER:
            raise KeyExhaustedError(f"Key {self._key_id!r} has exhausted its nonce counter.")
        updated = current + 1
        self._write(updated)
        return updated


RotationDecrypt = Callable[[ProtectedArtifact], bytes]
RotationEncrypt = Callable[[bytes], ProtectedArtifact]


@dataclass(frozen=True)
class RotationReport:
    rotated_contract_ids: tuple[str, ...]
    already_rotated_contract_ids: tuple[str, ...]


def rotate_key(
    *,
    new_key_id: str,
    store: SqliteRecoveryContractStore,
    decrypt: RotationDecrypt,
    encrypt: RotationEncrypt,
) -> RotationReport:
    """Re-encrypt every stored contract's protected artifacts under
    `new_key_id`, one contract at a time via store.rotate_artifacts()'s
    existing per-record compare-and-set transaction. Resumable: a
    contract whose protected_intent.key_id already equals new_key_id is
    skipped, so an interrupted run can simply be re-invoked. Never holds
    more than one contract's plaintext in memory at a time. The old key
    is never destroyed by this function — that remains a separate,
    explicit operator action after confirming zero contracts reference
    it (query store.all_contracts() and check protected_intent.key_id)."""

    rotated: list[str] = []
    already_rotated: list[str] = []
    for contract in store.all_contracts():
        if contract.protected_intent.key_id == new_key_id:
            already_rotated.append(contract.contract_id)
            continue
        store.rotate_artifacts(
            contract.contract_id,
            expected_version=contract.state_version,
            protected_target_identity=encrypt(decrypt(contract.protected_target_identity)),
            protected_intent=encrypt(decrypt(contract.protected_intent)),
            protected_snapshot=encrypt(decrypt(contract.protected_snapshot)),
        )
        rotated.append(contract.contract_id)
    return RotationReport(rotated_contract_ids=tuple(rotated), already_rotated_contract_ids=tuple(already_rotated))
