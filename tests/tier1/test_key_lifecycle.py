from __future__ import annotations

import json
import os
from dataclasses import replace

import pytest

from pfsense_mcp.tier1.contract import ProtectedArtifact
from pfsense_mcp.tier1.errors import KeyExhaustedError, KeyMaterialError
from pfsense_mcp.tier1.key_lifecycle import (
    MAX_NONCE_COUNTER,
    KeyPurpose,
    NonceCounter,
    load_key_material,
    rotate_key,
)
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

_MATERIAL_HEX = "ab" * 32
_INTEGRITY_KEY = b"synthetic-test-integrity-key-32bytes!"


def _write_key_file(path, *, key_id="enc-0001", epoch=0, material_hex=_MATERIAL_HEX, mode=0o600):
    path.write_text(json.dumps({"key_id": key_id, "epoch": epoch, "material_hex": material_hex}))
    os.chmod(path, mode)


def test_load_key_material_reads_a_valid_file(tmp_path):
    path = tmp_path / "enc.key"
    _write_key_file(path)

    record = load_key_material(path, purpose=KeyPurpose.ENCRYPTION)

    assert record.key_id == "enc-0001"
    assert record.epoch == 0
    assert record.material == bytes.fromhex(_MATERIAL_HEX)
    assert record.purpose == KeyPurpose.ENCRYPTION
    assert not record.retired


def test_load_key_material_rejects_group_readable_file(tmp_path):
    path = tmp_path / "enc.key"
    _write_key_file(path, mode=0o640)

    with pytest.raises(KeyMaterialError, match="group or other"):
        load_key_material(path, purpose=KeyPurpose.ENCRYPTION)


def test_load_key_material_rejects_symlink(tmp_path):
    target = tmp_path / "real.key"
    _write_key_file(target)
    link = tmp_path / "enc.key"
    link.symlink_to(target)

    with pytest.raises(KeyMaterialError, match="symbolic link"):
        load_key_material(link, purpose=KeyPurpose.ENCRYPTION)


def test_load_key_material_rejects_malformed_json(tmp_path):
    path = tmp_path / "enc.key"
    path.write_text("not json")
    os.chmod(path, 0o600)

    with pytest.raises(KeyMaterialError, match="not valid JSON"):
        load_key_material(path, purpose=KeyPurpose.ENCRYPTION)


@pytest.mark.parametrize(
    "overrides",
    [
        {"key_id": ""},
        {"key_id": "bad id with spaces"},
        {"epoch": -1},
        {"material_hex": "not-hex"},
        {"material_hex": "ab" * 16},
    ],
)
def test_load_key_material_rejects_invalid_fields(tmp_path, overrides):
    path = tmp_path / "enc.key"
    fields = {"key_id": "enc-0001", "epoch": 0, "material_hex": _MATERIAL_HEX}
    fields.update(overrides)
    path.write_text(json.dumps(fields))
    os.chmod(path, 0o600)

    with pytest.raises(KeyMaterialError):
        load_key_material(path, purpose=KeyPurpose.ENCRYPTION)


def test_load_key_material_rejects_unknown_fields(tmp_path):
    path = tmp_path / "enc.key"
    path.write_text(json.dumps({"key_id": "enc-0001", "epoch": 0, "material_hex": _MATERIAL_HEX, "extra": "x"}))
    os.chmod(path, 0o600)

    with pytest.raises(KeyMaterialError, match="unexpected shape"):
        load_key_material(path, purpose=KeyPurpose.ENCRYPTION)


def test_nonce_counter_is_monotonic_and_survives_restart(tmp_path):
    path = tmp_path / "counter.json"
    counter = NonceCounter(path, key_id="enc-0001")

    values = [counter.next() for _ in range(5)]
    assert values == sorted(values)
    assert len(set(values)) == 5

    restarted = NonceCounter(path, key_id="enc-0001")
    next_value = restarted.next()
    assert next_value == values[-1] + 1


def test_nonce_counter_rejects_mismatched_key_id(tmp_path):
    path = tmp_path / "counter.json"
    NonceCounter(path, key_id="enc-0001")

    with pytest.raises(KeyMaterialError, match="does not match"):
        NonceCounter(path, key_id="enc-0002")


def test_nonce_counter_rejects_corrupted_file(tmp_path):
    path = tmp_path / "counter.json"
    path.write_text("not json")
    os.chmod(path, 0o600)

    with pytest.raises(KeyMaterialError, match="corrupted"):
        NonceCounter(path, key_id="enc-0001")


def test_nonce_counter_raises_once_exhausted(tmp_path):
    path = tmp_path / "counter.json"
    path.write_text(json.dumps({"key_id": "enc-0001", "counter": MAX_NONCE_COUNTER}))
    os.chmod(path, 0o600)

    counter = NonceCounter(path, key_id="enc-0001")
    with pytest.raises(KeyExhaustedError):
        counter.next()


class _AcceptingVerifier:
    def verify(self, evidence):
        return evidence.proof == b"synthetic-valid-proof"


def _store(tmp_path):
    directory = tmp_path / "store"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return SqliteRecoveryContractStore(
        directory / "contracts.sqlite3",
        integrity_key=_INTEGRITY_KEY,
        store_id="synthetic-store",
        confirmation_verifier=_AcceptingVerifier(),
    )


def _identity_encrypt(target_key_id: str):
    def encrypt(plaintext: bytes) -> ProtectedArtifact:
        return ProtectedArtifact(key_id=target_key_id, algorithm="test-only", ciphertext=plaintext)

    return encrypt


def _identity_decrypt(artifact: ProtectedArtifact) -> bytes:
    return artifact.ciphertext


def test_rotate_key_reencrypts_every_contract_and_is_resumable(tmp_path, contract_factory):
    store = _store(tmp_path)
    old_artifact = ProtectedArtifact(key_id="old-key", algorithm="test-only", ciphertext=b"old-plaintext")
    first = contract_factory(contract_id="contract-001", operation_id="operation-001")
    first = replace(
        first,
        protected_target_identity=old_artifact,
        protected_intent=old_artifact,
        protected_snapshot=old_artifact,
    )
    store.create(first)

    report = rotate_key(
        new_key_id="new-key",
        store=store,
        decrypt=_identity_decrypt,
        encrypt=_identity_encrypt("new-key"),
    )

    assert report.rotated_contract_ids == ("contract-001",)
    assert report.already_rotated_contract_ids == ()

    reloaded = store.load("contract-001")
    assert reloaded.protected_intent.key_id == "new-key"
    assert reloaded.protected_intent.ciphertext == b"old-plaintext"
    assert reloaded.state == RecoveryState.PREPARING
    assert reloaded.state_version == first.state_version + 1

    second_report = rotate_key(
        new_key_id="new-key",
        store=store,
        decrypt=_identity_decrypt,
        encrypt=_identity_encrypt("new-key"),
    )
    assert second_report.rotated_contract_ids == ()
    assert second_report.already_rotated_contract_ids == ("contract-001",)
