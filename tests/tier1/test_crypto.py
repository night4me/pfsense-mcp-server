from __future__ import annotations

import os

import pytest

from pfsense_mcp.tier1.canonical import canonical_json
from pfsense_mcp.tier1.contract import ProtectedArtifact
from pfsense_mcp.tier1.crypto import (
    ArtifactAlgorithm,
    ArtifactRole,
    build_nonce,
    decrypt_artifact,
    encrypt_artifact,
)
from pfsense_mcp.tier1.errors import ArtifactDecryptionError

_KEY = os.urandom(32)
_OTHER_KEY = os.urandom(32)


def _encrypt(plaintext: bytes, *, contract_id="contract-001", role=ArtifactRole.INTENT, counter=1, key=_KEY):
    nonce = build_nonce(epoch=0, counter=counter)
    return encrypt_artifact(
        key=key, key_id="enc-0001", contract_id=contract_id, role=role, plaintext=plaintext, nonce=nonce
    )


@pytest.mark.parametrize("plaintext", [b"x", canonical_json({"a": 1}), b"y" * 65536])
def test_round_trip_recovers_exact_plaintext(plaintext):
    artifact = _encrypt(plaintext)
    recovered = decrypt_artifact(key=_KEY, artifact=artifact, contract_id="contract-001", role=ArtifactRole.INTENT)
    assert recovered == plaintext


@pytest.mark.parametrize("field", ["ciphertext", "algorithm", "key_id"])
def test_tampering_is_detected(field):
    artifact = _encrypt(b"synthetic-plaintext")
    if field == "ciphertext":
        corrupted = artifact.ciphertext[:-1] + bytes([artifact.ciphertext[-1] ^ 0x01])
        tampered = ProtectedArtifact(key_id=artifact.key_id, algorithm=artifact.algorithm, ciphertext=corrupted)
    elif field == "algorithm":
        tampered = ProtectedArtifact(key_id=artifact.key_id, algorithm="test-only", ciphertext=artifact.ciphertext)
    else:
        tampered = ProtectedArtifact(
            key_id="different-key-id", algorithm=artifact.algorithm, ciphertext=artifact.ciphertext
        )

    if field == "algorithm":
        with pytest.raises(ArtifactDecryptionError, match="not recognized"):
            decrypt_artifact(key=_KEY, artifact=tampered, contract_id="contract-001", role=ArtifactRole.INTENT)
    elif field == "key_id":
        # key_id is not itself authenticated by the AEAD tag (only contract_id/role are, via
        # associated data) -- it is authenticated by the store's own record-level HMAC. Confirm
        # that expectation explicitly: ciphertext still decrypts under the same key/contract/role.
        recovered = decrypt_artifact(key=_KEY, artifact=tampered, contract_id="contract-001", role=ArtifactRole.INTENT)
        assert recovered == b"synthetic-plaintext"
    else:
        with pytest.raises(ArtifactDecryptionError, match="authenticated decryption"):
            decrypt_artifact(key=_KEY, artifact=tampered, contract_id="contract-001", role=ArtifactRole.INTENT)


@pytest.mark.parametrize(
    ("wrong_contract_id", "wrong_role"),
    [("contract-002", ArtifactRole.INTENT), ("contract-001", ArtifactRole.SNAPSHOT)],
)
def test_associated_data_binds_contract_and_role(wrong_contract_id, wrong_role):
    artifact = _encrypt(b"synthetic-plaintext", contract_id="contract-001", role=ArtifactRole.INTENT)

    with pytest.raises(ArtifactDecryptionError, match="authenticated decryption"):
        decrypt_artifact(key=_KEY, artifact=artifact, contract_id=wrong_contract_id, role=wrong_role)


def test_wrong_key_fails_decryption():
    artifact = _encrypt(b"synthetic-plaintext")

    with pytest.raises(ArtifactDecryptionError, match="authenticated decryption"):
        decrypt_artifact(key=_OTHER_KEY, artifact=artifact, contract_id="contract-001", role=ArtifactRole.INTENT)


def test_unknown_algorithm_refuses_before_decrypting():
    artifact = _encrypt(b"synthetic-plaintext")
    unknown = ProtectedArtifact(key_id=artifact.key_id, algorithm="future-codec-v2", ciphertext=artifact.ciphertext)

    with pytest.raises(ArtifactDecryptionError, match="not recognized"):
        decrypt_artifact(key=_KEY, artifact=unknown, contract_id="contract-001", role=ArtifactRole.INTENT)


def test_nonce_uniqueness_across_many_encryptions():
    nonces = {build_nonce(epoch=0, counter=i) for i in range(1, 5001)}
    assert len(nonces) == 5000


def test_algorithm_value_matches_expected_identifier():
    artifact = _encrypt(b"synthetic-plaintext")
    assert artifact.algorithm == ArtifactAlgorithm.AES_256_GCM_V1.value


@pytest.mark.parametrize(
    "ciphertext",
    [
        os.urandom(1),
        os.urandom(11),
        os.urandom(12),
        os.urandom(28),
        os.urandom(200),
    ],
)
def test_random_ciphertext_never_raises_anything_but_artifact_decryption_error(ciphertext):
    artifact = ProtectedArtifact(
        key_id="enc-0001", algorithm=ArtifactAlgorithm.AES_256_GCM_V1.value, ciphertext=ciphertext
    )

    with pytest.raises(ArtifactDecryptionError):
        decrypt_artifact(key=_KEY, artifact=artifact, contract_id="contract-001", role=ArtifactRole.INTENT)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key": b"too-short", "nonce": build_nonce(epoch=0, counter=1)},
        {"key": _KEY, "nonce": b"too-short"},
    ],
)
def test_encrypt_artifact_rejects_malformed_key_or_nonce(kwargs):
    with pytest.raises(ArtifactDecryptionError):
        encrypt_artifact(
            key_id="enc-0001",
            contract_id="contract-001",
            role=ArtifactRole.INTENT,
            plaintext=b"data",
            **kwargs,
        )


def test_build_nonce_rejects_out_of_range_values():
    with pytest.raises(ArtifactDecryptionError):
        build_nonce(epoch=-1, counter=0)
    with pytest.raises(ArtifactDecryptionError):
        build_nonce(epoch=0, counter=-1)
    with pytest.raises(ArtifactDecryptionError):
        build_nonce(epoch=2**32, counter=0)
