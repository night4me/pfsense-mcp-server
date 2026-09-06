"""Functional and adversarial tests for `signing.standard_sealed_write_signing`
-- the local, operator-only `sign-approval` command that produces a fresh,
signed `SealedWriteApproval`.

Run explicitly: `pytest signing/` (excluded from the default suite by
`pyproject.toml`'s `addopts`, matching `lab/`/`witness_daemon/`'s own
established precedent for separate, off-host/off-runtime deployables).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.sealed_write_approval import (
    build_sealed_write_approval_payload,
    sealed_write_approval_from_bytes,
    sealed_write_approval_to_bytes,
    verify_sealed_write_approval_signature,
)
from pfsense_mcp.tier1.write_security_class import WriteSecurityClass
from signing.standard_sealed_write_signing import (
    STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
    SigningError,
    main,
    render_approval_review,
    sign_standard_sealed_write_approval,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
CONTRACT_ID = "ntppref-abc123"
STATE_VERSION = 1
INTENT_DIGEST = "a" * 64
TARGET_DIGEST = "b" * 64


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _authority(
    authority_id: str = STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
) -> tuple[Ed25519PrivateKey, PinnedAuthority]:
    private, public = _keypair()
    return private, PinnedAuthority(authority_id=authority_id, public_key=public)


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


# ---------------------------------------------------------------------------
# sign_standard_sealed_write_approval() -- pure functional tests
# ---------------------------------------------------------------------------


def test_valid_signing_produces_a_self_verifying_approval():
    private_key, authority = _authority()
    approval = sign_standard_sealed_write_approval(
        contract_id=CONTRACT_ID,
        state_version=STATE_VERSION,
        execution_intent_digest=INTENT_DIGEST,
        target_identity_digest=TARGET_DIGEST,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        private_key=private_key,
        authority=authority,
    )
    assert approval.contract_id == CONTRACT_ID
    assert approval.state_version == STATE_VERSION
    assert approval.security_class == WriteSecurityClass.STANDARD_SEALED_WRITE
    assert approval.execution_intent_digest == INTENT_DIGEST
    assert approval.target_identity_digest == TARGET_DIGEST
    assert approval.authority_id == STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID
    assert verify_sealed_write_approval_signature(approval, PinnedAuthoritySet((authority,)))


def test_refuses_authority_not_named_standard_sealed_write_approval_authority_v1():
    private_key, wrong_authority = _authority(authority_id="some-other-authority")
    with pytest.raises(SigningError, match="standard-sealed-write-approval-authority-v1"):
        sign_standard_sealed_write_approval(
            contract_id=CONTRACT_ID,
            state_version=STATE_VERSION,
            execution_intent_digest=INTENT_DIGEST,
            target_identity_digest=TARGET_DIGEST,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            private_key=private_key,
            authority=wrong_authority,
        )


def test_self_verification_fails_closed_when_private_key_does_not_match_authority():
    private_key, _ = _authority()
    _, mismatched_authority = _authority()  # different keypair, same authority_id
    with pytest.raises(SigningError, match="failed self-verification"):
        sign_standard_sealed_write_approval(
            contract_id=CONTRACT_ID,
            state_version=STATE_VERSION,
            execution_intent_digest=INTENT_DIGEST,
            target_identity_digest=TARGET_DIGEST,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            private_key=private_key,
            authority=mismatched_authority,
        )


@pytest.mark.parametrize(
    "issued_at,expires_at",
    [
        (NOW, NOW),  # zero-width window
        (NOW, NOW - timedelta(minutes=1)),  # expires before issued
        (NOW.replace(tzinfo=None), NOW + timedelta(minutes=5)),  # naive issued_at
    ],
)
def test_invalid_timestamps_are_refused(issued_at, expires_at):
    private_key, authority = _authority()
    with pytest.raises(SigningError, match="could not build the SealedWriteApproval payload"):
        sign_standard_sealed_write_approval(
            contract_id=CONTRACT_ID,
            state_version=STATE_VERSION,
            execution_intent_digest=INTENT_DIGEST,
            target_identity_digest=TARGET_DIGEST,
            issued_at=issued_at,
            expires_at=expires_at,
            private_key=private_key,
            authority=authority,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("contract_id", ""),
        ("contract_id", "has a space"),
        ("state_version", -1),
        ("execution_intent_digest", "not-hex"),
        ("execution_intent_digest", "a" * 63),
        ("target_identity_digest", "not-hex"),
        ("target_identity_digest", "b" * 65),
    ],
)
def test_malformed_request_fields_are_refused(field, value):
    private_key, authority = _authority()
    kwargs = {
        "contract_id": CONTRACT_ID,
        "state_version": STATE_VERSION,
        "execution_intent_digest": INTENT_DIGEST,
        "target_identity_digest": TARGET_DIGEST,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=30),
        "private_key": private_key,
        "authority": authority,
    }
    kwargs[field] = value
    with pytest.raises(SigningError, match="could not build the SealedWriteApproval payload"):
        sign_standard_sealed_write_approval(**kwargs)


def test_this_signer_never_accepts_a_security_class_parameter():
    """Structural proof, not just documentation: `sign_standard_sealed_
    write_approval()`'s own signature has no `security_class` keyword at
    all -- it is impossible for any caller of this function to request
    a HIGH_ASSURANCE_TIER1 approval from this signer."""

    import inspect

    parameters = inspect.signature(sign_standard_sealed_write_approval).parameters
    assert "security_class" not in parameters


def test_render_approval_review_shows_every_signed_field():
    review = render_approval_review(
        contract_id=CONTRACT_ID,
        state_version=STATE_VERSION,
        security_class=WriteSecurityClass.STANDARD_SEALED_WRITE,
        execution_intent_digest=INTENT_DIGEST,
        target_identity_digest=TARGET_DIGEST,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
    )
    for expected in (
        CONTRACT_ID,
        str(STATE_VERSION),
        "standard_sealed_write",
        INTENT_DIGEST,
        TARGET_DIGEST,
        STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
    ):
        assert expected in review


# ---------------------------------------------------------------------------
# sign_approval_command() -- end-to-end CLI workflow
# ---------------------------------------------------------------------------


def _configure_env(tmp_path: Path, monkeypatch, *, authority: PinnedAuthority, private_key: Ed25519PrivateKey) -> Path:
    authority_file = tmp_path / "keys" / "standard-sealed-write-authority.json"
    private_key_file = tmp_path / "keys" / "standard-sealed-write-private.key"
    _authority_file(authority_file, authority)
    _private_key_file(private_key_file, private_key)
    monkeypatch.setenv("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_AUTHORITY_FILE", str(authority_file))
    monkeypatch.setenv("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_PRIVATE_KEY_FILE", str(private_key_file))
    output_dir = tmp_path / "output"
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    return output_dir / "standard-sealed-write-approval.json"


def _cli_args(output_file: Path) -> list[str]:
    return [
        "sign-approval",
        "--contract-id",
        CONTRACT_ID,
        "--state-version",
        str(STATE_VERSION),
        "--execution-intent-digest",
        INTENT_DIGEST,
        "--target-identity-digest",
        TARGET_DIGEST,
        "--ttl-minutes",
        "30",
        "--output",
        str(output_file),
    ]


def test_sign_approval_command_end_to_end_with_approval(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    exit_code = main(_cli_args(output_file))

    assert exit_code == 0
    assert output_file.exists()
    approval = sealed_write_approval_from_bytes(output_file.read_bytes())
    assert approval.contract_id == CONTRACT_ID
    assert approval.state_version == STATE_VERSION
    assert approval.security_class == WriteSecurityClass.STANDARD_SEALED_WRITE
    assert approval.execution_intent_digest == INTENT_DIGEST
    assert approval.target_identity_digest == TARGET_DIGEST
    assert verify_sealed_write_approval_signature(approval, PinnedAuthoritySet((authority,)))


def test_sign_approval_command_refuses_on_operator_decline(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    monkeypatch.setattr("builtins.input", lambda _: "no")

    exit_code = main(_cli_args(output_file))

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_approval_command_refuses_overwrite_of_existing_output(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    output_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_file.write_bytes(b"pre-existing content")
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    exit_code = main(_cli_args(output_file))

    assert exit_code == 1
    assert output_file.read_bytes() == b"pre-existing content"


def test_sign_approval_command_refuses_wrong_authority_file(tmp_path, monkeypatch):
    private_key, wrong_authority = _authority(authority_id="not-the-standard-authority")
    output_file = _configure_env(tmp_path, monkeypatch, authority=wrong_authority, private_key=private_key)
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    exit_code = main(_cli_args(output_file))

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_approval_command_rejects_non_positive_ttl(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    args = _cli_args(output_file)
    args[args.index("--ttl-minutes") + 1] = "0"

    exit_code = main(args)

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_approval_command_rejects_negative_state_version(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    args = _cli_args(output_file)
    args[args.index("--state-version") + 1] = "-1"

    exit_code = main(args)

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_approval_command_refuses_missing_env_vars(tmp_path, monkeypatch):
    output_file = tmp_path / "output" / "standard-sealed-write-approval.json"
    monkeypatch.delenv("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_AUTHORITY_FILE", raising=False)
    monkeypatch.delenv("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_PRIVATE_KEY_FILE", raising=False)

    exit_code = main(_cli_args(output_file))

    assert exit_code == 1
    assert not output_file.exists()


# ---------------------------------------------------------------------------
# Private-key/authority file permission and symlink refusal
# ---------------------------------------------------------------------------


def test_sign_approval_command_refuses_world_readable_private_key(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    private_key_file = Path(os.environ["PFSENSE_SIGNING_STANDARD_SEALED_WRITE_PRIVATE_KEY_FILE"])
    os.chmod(private_key_file, 0o644)
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    exit_code = main(_cli_args(output_file))

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_approval_command_refuses_symlinked_private_key(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    real_key_file = Path(os.environ["PFSENSE_SIGNING_STANDARD_SEALED_WRITE_PRIVATE_KEY_FILE"])
    symlink_path = real_key_file.with_name("standard-sealed-write-private-symlink.key")
    symlink_path.symlink_to(real_key_file)
    monkeypatch.setenv("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_PRIVATE_KEY_FILE", str(symlink_path))
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    exit_code = main(_cli_args(output_file))

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_approval_command_refuses_symlinked_authority_file(tmp_path, monkeypatch):
    private_key, authority = _authority()
    output_file = _configure_env(tmp_path, monkeypatch, authority=authority, private_key=private_key)
    real_authority_file = Path(os.environ["PFSENSE_SIGNING_STANDARD_SEALED_WRITE_AUTHORITY_FILE"])
    symlink_path = real_authority_file.with_name("standard-sealed-write-authority-symlink.json")
    symlink_path.symlink_to(real_authority_file)
    monkeypatch.setenv("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_AUTHORITY_FILE", str(symlink_path))
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    exit_code = main(_cli_args(output_file))

    assert exit_code == 1
    assert not output_file.exists()


# ---------------------------------------------------------------------------
# Serialization / self-verification round-trip
# ---------------------------------------------------------------------------


def test_serialization_round_trip_preserves_signature_validity():
    private_key, authority = _authority()
    approval = sign_standard_sealed_write_approval(
        contract_id=CONTRACT_ID,
        state_version=STATE_VERSION,
        execution_intent_digest=INTENT_DIGEST,
        target_identity_digest=TARGET_DIGEST,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        private_key=private_key,
        authority=authority,
    )
    reparsed = sealed_write_approval_from_bytes(sealed_write_approval_to_bytes(approval))
    assert reparsed == approval
    assert verify_sealed_write_approval_signature(reparsed, PinnedAuthoritySet((authority,)))


def test_build_payload_matches_what_the_command_signs():
    """Cross-check: the payload this module builds is byte-identical, per
    field, to what a caller building it directly via the same production
    primitive would get -- proving no field is silently transformed."""

    payload = build_sealed_write_approval_payload(
        contract_id=CONTRACT_ID,
        state_version=STATE_VERSION,
        security_class=WriteSecurityClass.STANDARD_SEALED_WRITE,
        execution_intent_digest=INTENT_DIGEST,
        target_identity_digest=TARGET_DIGEST,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    private_key, authority = _authority()
    approval = sign_standard_sealed_write_approval(
        contract_id=CONTRACT_ID,
        state_version=STATE_VERSION,
        execution_intent_digest=INTENT_DIGEST,
        target_identity_digest=TARGET_DIGEST,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        private_key=private_key,
        authority=authority,
    )
    assert approval.contract_id == payload.contract_id
    assert approval.state_version == payload.state_version
    assert approval.security_class == payload.security_class
    assert approval.execution_intent_digest == payload.execution_intent_digest
    assert approval.target_identity_digest == payload.target_identity_digest
    assert approval.issued_at == payload.issued_at
    assert approval.expires_at == payload.expires_at
