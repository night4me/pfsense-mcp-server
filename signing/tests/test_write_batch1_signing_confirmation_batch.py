"""Tests for the 2026-09-05 confirmation-side batch ceremony:
`sign_confirmation_batch_command()` and the `sign-confirmation-batch`
CLI subcommand -- the confirmation-side mirror of
`test_write_batch1_signing_batch.py`. Exactly ONE literal owner `yes`
for a whole batch of pending confirmation requests, then N individually
signed and independently verifiable `ConfirmationEvidence` artifacts,
each cryptographically bound to its own batch owner approval via
`verify_confirmation_evidence_batch_membership()`.

All keys/evidence here are synthetic and ephemeral.
"""

from __future__ import annotations

import builtins
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.shape_a_acceptance_orchestration import artifact_paths_for
from pfsense_mcp.tier1.shape_a_artifact_exchange import (
    ShapeAPendingConfirmationRequest,
    load_signed_confirmation_evidence,
    shape_a_pending_confirmation_request_to_bytes,
    write_secure_new,
)
from signing.shape_a_confirmation_batch_owner_approval import (
    shape_a_confirmation_batch_owner_approval_from_bytes,
    verify_confirmation_evidence_batch_membership,
    verify_shape_a_confirmation_batch_owner_approval_signature,
)
from signing.write_batch1_signing import (
    SigningError,
    _load_confirmation_config,
    _one_confirmation,
    sign_confirmation_batch_command,
)

_AUTHORITY_ID = "confirm-owner-1"
_INTEGRITY_KEY_HEX = "cd" * 32
_NOW = datetime.now(timezone.utc)
_EXPIRES_REQUEST = _NOW + timedelta(minutes=5)

_FIVE_SYMBOLS = (
    "NTP_TIME_SERVER_PREFER",
    "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
    "LOG_DISPLAY_PREFERENCES",
    "LOG_RETENTION_SETTINGS",
    "SYSTEM_TIMEZONE",
)


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _secure_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _authority_file(path: Path, authority: PinnedAuthority) -> None:
    _secure_write(
        path,
        json.dumps({"authority_id": authority.authority_id, "public_key_hex": authority.public_key.hex()}).encode(),
    )


def _private_key_file(path: Path, private_key: Ed25519PrivateKey) -> None:
    raw = private_key.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )
    _secure_write(path, raw)


def _integrity_key_file(path: Path) -> None:
    _secure_write(
        path, json.dumps({"key_id": "signing-integrity", "epoch": 0, "material_hex": _INTEGRITY_KEY_HEX}).encode()
    )


def _integrity_key_bytes() -> bytes:
    return bytes.fromhex(_INTEGRITY_KEY_HEX)


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    confirmation_private_key, confirmation_public_key = _keypair()
    authority = PinnedAuthority(authority_id=_AUTHORITY_ID, public_key=confirmation_public_key)

    authority_path = tmp_path / "confirmation-authority.json"
    private_key_path = tmp_path / "confirmation-private.key"
    integrity_key_path = tmp_path / "pending-integrity.json"
    _authority_file(authority_path, authority)
    _private_key_file(private_key_path, confirmation_private_key)
    _integrity_key_file(integrity_key_path)

    env = {
        "PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY": str(tmp_path / "artifacts"),
        "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE": str(authority_path),
        "PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_PRIVATE_KEY_FILE": str(private_key_path),
        "PFSENSE_SIGNING_SHAPE_A_PENDING_INTEGRITY_KEY_FILE": str(integrity_key_path),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return env


def _write_pending(env: dict[str, str], capability_symbol: str) -> ShapeAPendingConfirmationRequest:
    pending = ShapeAPendingConfirmationRequest(
        capability_symbol=capability_symbol,
        contract_id=f"contract-{capability_symbol.lower()}",
        operation_id=f"operation-{capability_symbol.lower()}",
        semantic_fields=(("field", "value"),),
        target_identity_digest="a" * 64,
        target_fingerprint="b" * 64,
        intent_digest=f"{abs(hash(capability_symbol)) % 16:01x}" * 64,
        expires_at=_EXPIRES_REQUEST,
        expected_authority_id=_AUTHORITY_ID,
        expected_algorithm=ACCEPTED_ALGORITHM,
    )
    paths = artifact_paths_for(Path(env["PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY"]), capability_symbol)
    paths.confirmation_pending_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_secure_new(
        paths.confirmation_pending_file,
        shape_a_pending_confirmation_request_to_bytes(pending, integrity_key=_integrity_key_bytes()),
    )
    return pending


def _counting_yes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _fake_input(prompt: str = "") -> str:
        calls.append(prompt)
        return "yes"

    monkeypatch.setattr(builtins, "input", _fake_input)
    return calls


def _find_confirmation_batch_owner_approval_path(artifact_base_directory: Path) -> Path:
    matches = list((artifact_base_directory / "_batches").glob("*/confirmation-batch-owner-approval.json"))
    assert len(matches) == 1
    return matches[0]


def test_batch_prompts_exactly_once_for_five_capabilities(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_pending(env, symbol)
    prompts = _counting_yes(monkeypatch)

    assert sign_confirmation_batch_command(list(_FIVE_SYMBOLS)) == 0
    assert len(prompts) == 1

    config = _load_confirmation_config()
    for symbol in _FIVE_SYMBOLS:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        assert paths.confirmation_signed_file.exists()


def test_batch_produces_a_verifiable_signed_batch_owner_approval(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_pending(env, symbol)
    _counting_yes(monkeypatch)

    assert sign_confirmation_batch_command(list(_FIVE_SYMBOLS)) == 0

    config = _load_confirmation_config()
    authority_data = json.loads(Path(env["PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE"]).read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )
    authorities = PinnedAuthoritySet((authority,))

    approval_path = _find_confirmation_batch_owner_approval_path(config.artifact_base_directory)
    approval = shape_a_confirmation_batch_owner_approval_from_bytes(approval_path.read_bytes())

    assert verify_shape_a_confirmation_batch_owner_approval_signature(approval, authorities) is True
    assert {entry.capability_symbol for entry in approval.entries} == set(_FIVE_SYMBOLS)


def test_every_produced_evidence_satisfies_batch_membership_against_its_own_approval(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_pending(env, symbol)
    _counting_yes(monkeypatch)

    assert sign_confirmation_batch_command(list(_FIVE_SYMBOLS)) == 0

    config = _load_confirmation_config()
    authority_data = json.loads(Path(env["PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE"]).read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )
    authorities = PinnedAuthoritySet((authority,))
    approval_path = _find_confirmation_batch_owner_approval_path(config.artifact_base_directory)
    approval = shape_a_confirmation_batch_owner_approval_from_bytes(approval_path.read_bytes())

    for symbol in _FIVE_SYMBOLS:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        evidence = load_signed_confirmation_evidence(paths.confirmation_signed_file)
        assert (
            verify_confirmation_evidence_batch_membership(
                evidence, approval, capability_symbol=symbol, authorities=authorities
            )
            is True
        )


def test_evidence_from_one_batch_does_not_satisfy_a_different_batchs_approval(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_pending(env, symbol)
    _counting_yes(monkeypatch)

    first_batch = list(_FIVE_SYMBOLS[:2])
    second_batch = list(_FIVE_SYMBOLS[2:])
    assert sign_confirmation_batch_command(first_batch) == 0
    assert sign_confirmation_batch_command(second_batch) == 0

    config = _load_confirmation_config()
    authority_data = json.loads(Path(env["PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE"]).read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )
    authorities = PinnedAuthoritySet((authority,))

    approval_paths = list(
        (config.artifact_base_directory / "_batches").glob("*/confirmation-batch-owner-approval.json")
    )
    assert len(approval_paths) == 2
    approvals = [shape_a_confirmation_batch_owner_approval_from_bytes(path.read_bytes()) for path in approval_paths]
    approval_covering_first = next(a for a in approvals if first_batch[0] in {e.capability_symbol for e in a.entries})
    approval_covering_second = next(a for a in approvals if second_batch[0] in {e.capability_symbol for e in a.entries})

    first_capability = first_batch[0]
    paths = artifact_paths_for(config.artifact_base_directory, first_capability)
    evidence_from_first_batch = load_signed_confirmation_evidence(paths.confirmation_signed_file)

    assert (
        verify_confirmation_evidence_batch_membership(
            evidence_from_first_batch,
            approval_covering_first,
            capability_symbol=first_capability,
            authorities=authorities,
        )
        is True
    )
    assert (
        verify_confirmation_evidence_batch_membership(
            evidence_from_first_batch,
            approval_covering_second,
            capability_symbol=first_capability,
            authorities=authorities,
        )
        is False
    )


def test_batch_refuses_whole_batch_if_a_pending_request_is_missing(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS[:-1]:
        _write_pending(env, symbol)
    prompts = _counting_yes(monkeypatch)

    with pytest.raises(SigningError, match="no pending confirmation present"):
        sign_confirmation_batch_command(list(_FIVE_SYMBOLS))

    assert len(prompts) == 0


def test_batch_refuses_whole_batch_if_a_signed_confirmation_already_exists(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_pending(env, symbol)
    config = _load_confirmation_config()
    already_signed = artifact_paths_for(config.artifact_base_directory, _FIVE_SYMBOLS[0])
    write_secure_new(already_signed.confirmation_signed_file, b'{"already": "signed"}')
    prompts = _counting_yes(monkeypatch)

    with pytest.raises(SigningError, match="already exists"):
        sign_confirmation_batch_command(list(_FIVE_SYMBOLS))

    assert len(prompts) == 0


def test_batch_refuses_duplicate_capability():
    with pytest.raises(SigningError, match="duplicate"):
        sign_confirmation_batch_command(["SYSTEM_TIMEZONE", "SYSTEM_TIMEZONE"])


def test_batch_refuses_empty_capability_list():
    with pytest.raises(SigningError, match="at least one"):
        sign_confirmation_batch_command([])


def test_one_confirmation_rejects_a_substituted_contract_id(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    _write_pending(env, "SYSTEM_TIMEZONE")
    _counting_yes(monkeypatch)
    config = _load_confirmation_config()

    with pytest.raises(SigningError, match="no longer matches"):
        _one_confirmation(
            config,
            "SYSTEM_TIMEZONE",
            require_approval=False,
            expected_contract_id="a-different-contract",
            expected_operation_id="operation-system_timezone",
            expected_intent_digest="e" * 64,
        )

    paths = artifact_paths_for(config.artifact_base_directory, "SYSTEM_TIMEZONE")
    assert not paths.confirmation_signed_file.exists()


def test_ordinary_single_capability_confirmation_path_is_unaffected(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    _write_pending(env, "SYSTEM_TIMEZONE")
    prompts = _counting_yes(monkeypatch)
    config = _load_confirmation_config()

    result = _one_confirmation(config, "SYSTEM_TIMEZONE")

    assert result == 0
    assert len(prompts) == 1
    paths = artifact_paths_for(config.artifact_base_directory, "SYSTEM_TIMEZONE")
    assert paths.confirmation_signed_file.exists()


def test_already_exists_skip_reports_whether_existing_confirmation_is_still_valid(tmp_path, monkeypatch, capsys):
    env = _fixture(tmp_path, monkeypatch)
    _write_pending(env, "SYSTEM_TIMEZONE")
    _counting_yes(monkeypatch)
    config = _load_confirmation_config()

    assert _one_confirmation(config, "SYSTEM_TIMEZONE") == 0
    capsys.readouterr()

    result = _one_confirmation(config, "SYSTEM_TIMEZONE")

    assert result == 0
    captured = capsys.readouterr()
    assert "already exists" in captured.out
    assert "still valid" in captured.out
    assert "EXPIRED" not in captured.out
