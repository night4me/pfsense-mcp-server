"""Tests for the 2026-09-05 batch-ceremony addition to
`write_batch1_signing.py`: `sign_authorization_batch_command()` and the
`sign-authorization-batch` CLI subcommand. The owner-directed redesign
this covers: preserve one signed `PlanAuthorizationV2` per capability
(unchanged, individually verifiable exactly as before), but require
exactly ONE literal owner `yes` for an entire homogeneous batch instead
of one `yes` per capability.

All keys/evidence here are synthetic and ephemeral -- never a real
production signer key or real pfSense evidence.
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

from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_v2_signature
from pfsense_mcp.security_plan import (
    MILESTONE_9_WRITE_STEP_ID,
    MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
    MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
    generate_security_posture_plan_from_discovery,
)
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.tier1.anchor_evidence_export import (
    anchor_evidence_export_to_bytes,
    build_anchor_evidence_export_payload,
    sign_anchor_evidence_export,
)
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.shape_a_acceptance_orchestration import artifact_paths_for
from pfsense_mcp.tier1.shape_a_artifact_exchange import (
    ShapeAAuthorizationPreview,
    load_signed_plan_authorization_v2,
    shape_a_authorization_preview_to_bytes,
    write_secure_new,
)
from signing.shape_a_batch_owner_approval import (
    shape_a_batch_owner_approval_from_bytes,
    verify_plan_authorization_v2_batch_membership,
    verify_shape_a_batch_owner_approval_signature,
)
from signing.write_batch1_signing import (
    _BATCH_AUTHORIZATION_VALIDITY,
    SigningError,
    _build_discovery_from_export,
    _load_authorization_config,
    _one_authorization,
    sign_authorization_batch_command,
)

_STORE_ID = "tier1-production-anchor"
_HANDLE = "0x01500000"
_BASELINE = 4
_PROVISIONED_AT = "2026-08-10T15:10:16.416050+00:00"
_ISSUED_AT = datetime.now(timezone.utc) - timedelta(seconds=1)
_EXPIRES_AT = _ISSUED_AT + timedelta(minutes=5)

_FIVE_SYMBOLS = (
    "NTP_TIME_SERVER_PREFER",
    "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
    "LOG_DISPLAY_PREFERENCES",
    "LOG_RETENTION_SETTINGS",
    "SYSTEM_TIMEZONE",
)
_INTEGRITY_KEY_HEX = "ab" * 32


class _FakeAnchor:
    def __init__(self, value: int) -> None:
        self._value = value

    def read(self) -> int:
        return self._value

    def advance(self, *, expected_current: int) -> int:
        raise AssertionError("must never call advance()")


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


def _write_export_and_authority(tmp_path: Path) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    payload = build_anchor_evidence_export_payload(
        store_id=_STORE_ID,
        handle=_HANDLE,
        baseline=_BASELINE,
        provisioned_at=_PROVISIONED_AT,
        issued_at=_ISSUED_AT,
        expires_at=_EXPIRES_AT,
    )
    export = sign_anchor_evidence_export(payload, authority_id="posture-evidence-authority-v1", private_key=private_key)

    export_path = tmp_path / "anchor-evidence-export.json"
    export_path.write_bytes(anchor_evidence_export_to_bytes(export))
    os.chmod(export_path, 0o600)

    authority_path = tmp_path / "posture-evidence-authority.json"
    authority_path.write_text(
        json.dumps({"authority_id": "posture-evidence-authority-v1", "public_key_hex": public_key.hex()})
    )
    os.chmod(authority_path, 0o600)
    return export_path, authority_path


def _base_env(tmp_path: Path, export_path: Path, authority_path: Path) -> dict[str, str]:
    return {
        "PFSENSE_SIGNING_ANCHOR_EVIDENCE_EXPORT_FILE": str(export_path),
        "PFSENSE_SIGNING_POSTURE_EVIDENCE_AUTHORITY_FILE": str(authority_path),
        "PFSENSE_SIGNING_EXPECTED_STORE_ID": _STORE_ID,
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": "/tmp/does-not-matter-client.crt",
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": "/tmp/does-not-matter-client.key",
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": "/tmp/does-not-matter-server.crt",
        "PFSENSE_PROFILE": "write_protected",
        "PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY": str(tmp_path / "artifacts"),
    }


def _patch_witness(monkeypatch: pytest.MonkeyPatch, value: int) -> None:
    import pfsense_mcp.security_discovery_export as module

    monkeypatch.setattr(module, "_build_read_only_witness_client", lambda config: _FakeAnchor(value))


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Sets up: export-based discovery env, a fresh authorization
    authority+key pair, a preview-integrity key, and puts everything in
    os.environ (the CLI functions under test read `os.environ` directly,
    not an injected mapping) -- mirrors how the real signer invokes
    these commands from its shell environment."""

    _patch_witness(monkeypatch, _BASELINE)
    export_path, authority_path = _write_export_and_authority(tmp_path)
    env = _base_env(tmp_path, export_path, authority_path)

    authorization_private_key, authorization_public_key = _keypair()
    authorization_authority = PinnedAuthority(
        authority_id="test-authorization-authority", public_key=authorization_public_key
    )
    authority_path_2 = tmp_path / "authorization-authority.json"
    private_key_path = tmp_path / "authorization-private.key"
    _authority_file(authority_path_2, authorization_authority)
    _private_key_file(private_key_path, authorization_private_key)
    env["PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE"] = str(authority_path_2)
    env["PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_PRIVATE_KEY_FILE"] = str(private_key_path)

    integrity_key_path = tmp_path / "preview-integrity.json"
    _integrity_key_file(integrity_key_path)
    env["PFSENSE_SIGNING_SHAPE_A_PREVIEW_INTEGRITY_KEY_FILE"] = str(integrity_key_path)

    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return env


def _write_preview(
    tmp_path: Path, env: dict[str, str], capability_symbol: str, *, digest_seed: str | None = None
) -> str:
    discovery = _build_discovery_from_export(env)
    assert discovery is not None
    plan = generate_security_posture_plan_from_discovery(
        discovery, MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE, MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE
    )
    plan_digest = compute_plan_digest(plan)
    execution_intent_digest = (digest_seed or capability_symbol).encode().hex()
    execution_intent_digest = (execution_intent_digest * 4)[:64]

    preview = ShapeAAuthorizationPreview(
        capability_symbol=capability_symbol,
        semantic_fields=(("field", "value"),),
        execution_intent_digest=execution_intent_digest,
        requested_plan_digest=plan_digest,
        requested_step_id=MILESTONE_9_WRITE_STEP_ID,
        target_capability_posture=MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
        target_anchor_assurance=MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        generated_at=datetime.now(timezone.utc),
    )
    paths = artifact_paths_for(Path(env["PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY"]), capability_symbol)
    paths.authorization_preview_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_secure_new(
        paths.authorization_preview_file,
        shape_a_authorization_preview_to_bytes(preview, integrity_key=_integrity_key_bytes()),
    )
    return execution_intent_digest


def _counting_yes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _fake_input(prompt: str = "") -> str:
        calls.append(prompt)
        return "yes"

    monkeypatch.setattr(builtins, "input", _fake_input)
    return calls


# ---------------------------------------------------------------------------
# One prompt for N capabilities, TTL correctness, per-artifact verifiability
# ---------------------------------------------------------------------------


def test_batch_command_prompts_exactly_once_for_five_capabilities(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    prompts = _counting_yes(monkeypatch)

    result = sign_authorization_batch_command(list(_FIVE_SYMBOLS))

    assert result == 0
    assert len(prompts) == 1

    config = _load_authorization_config()
    for symbol in _FIVE_SYMBOLS:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        assert paths.authorization_inbox_file.exists()
        authz = load_signed_plan_authorization_v2(paths.authorization_inbox_file)
        assert authz.expires_at - authz.issued_at == _BATCH_AUTHORIZATION_VALIDITY


def test_batch_command_produces_independently_verifiable_authorizations(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    _counting_yes(monkeypatch)

    authority_path = Path(env["PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE"])
    authority_data = json.loads(authority_path.read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )

    assert sign_authorization_batch_command(list(_FIVE_SYMBOLS)) == 0

    config = _load_authorization_config()
    for symbol in _FIVE_SYMBOLS:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        authz = load_signed_plan_authorization_v2(paths.authorization_inbox_file)
        assert verify_plan_authorization_v2_signature(authz, PinnedAuthoritySet((authority,))) is True


def test_batch_refusal_leaves_no_signatures(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)

    def _fake_input(prompt: str = "") -> str:
        return "no"

    monkeypatch.setattr(builtins, "input", _fake_input)

    assert sign_authorization_batch_command(list(_FIVE_SYMBOLS)) == 1

    config = _load_authorization_config()
    for symbol in _FIVE_SYMBOLS:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        assert not paths.authorization_inbox_file.exists()


# ---------------------------------------------------------------------------
# Fail-closed: no ambiguous partial states
# ---------------------------------------------------------------------------


def test_batch_refuses_whole_batch_if_a_preview_is_missing(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS[:-1]:
        _write_preview(tmp_path, env, symbol)
    prompts = _counting_yes(monkeypatch)

    with pytest.raises(SigningError, match="no authorization preview present"):
        sign_authorization_batch_command(list(_FIVE_SYMBOLS))

    assert len(prompts) == 0
    config = _load_authorization_config()
    for symbol in _FIVE_SYMBOLS[:-1]:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        assert not paths.authorization_inbox_file.exists()


def test_batch_refuses_whole_batch_if_an_inbox_already_exists(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    config = _load_authorization_config()
    already_signed_paths = artifact_paths_for(config.artifact_base_directory, _FIVE_SYMBOLS[0])
    write_secure_new(already_signed_paths.authorization_inbox_file, b'{"already": "signed"}')
    prompts = _counting_yes(monkeypatch)

    with pytest.raises(SigningError, match="already exists"):
        sign_authorization_batch_command(list(_FIVE_SYMBOLS))

    assert len(prompts) == 0
    for symbol in _FIVE_SYMBOLS[1:]:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        assert not paths.authorization_inbox_file.exists()


def test_batch_refuses_duplicate_capability_in_the_list(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    _write_preview(tmp_path, env, "SYSTEM_TIMEZONE")

    with pytest.raises(SigningError, match="duplicate"):
        sign_authorization_batch_command(["SYSTEM_TIMEZONE", "SYSTEM_TIMEZONE"])


def test_batch_refuses_empty_capability_list(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)

    with pytest.raises(SigningError, match="at least one"):
        sign_authorization_batch_command([])


def test_batch_refuses_unregistered_capability(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)

    with pytest.raises(SigningError, match="not a registered Shape-A capability"):
        sign_authorization_batch_command(["NOT_A_REAL_CAPABILITY"])


def test_partial_retry_is_safe_with_only_the_remaining_capabilities(tmp_path, monkeypatch):
    """Simulates a signer crash after the first capability's artifact was
    written: a retry of the FULL original list must refuse (ambiguous
    partial state); a retry with only the still-pending capabilities
    must succeed as its own freshly-approved, smaller batch."""

    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    _counting_yes(monkeypatch)

    assert sign_authorization_batch_command([_FIVE_SYMBOLS[0]]) == 0

    with pytest.raises(SigningError, match="already exists"):
        sign_authorization_batch_command(list(_FIVE_SYMBOLS))

    remaining = list(_FIVE_SYMBOLS[1:])
    assert sign_authorization_batch_command(remaining) == 0

    config = _load_authorization_config()
    for symbol in _FIVE_SYMBOLS:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        assert paths.authorization_inbox_file.exists()


# ---------------------------------------------------------------------------
# Defense in depth: execution_intent_digest substitution between manifest
# approval and this capability's turn to sign (`_one_authorization()` unit)
# ---------------------------------------------------------------------------


def test_one_authorization_rejects_a_substituted_execution_intent_digest(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    _write_preview(tmp_path, env, "SYSTEM_TIMEZONE")
    _counting_yes(monkeypatch)
    config = _load_authorization_config()
    discovery = _build_discovery_from_export(env)

    with pytest.raises(SigningError, match="no longer matches"):
        _one_authorization(
            config,
            "SYSTEM_TIMEZONE",
            require_approval=False,
            validity=_BATCH_AUTHORIZATION_VALIDITY,
            discovery=discovery,
            expected_execution_intent_digest="f" * 64,
        )

    paths = artifact_paths_for(config.artifact_base_directory, "SYSTEM_TIMEZONE")
    assert not paths.authorization_inbox_file.exists()


def test_one_authorization_with_require_approval_false_never_prompts(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    digest = _write_preview(tmp_path, env, "SYSTEM_TIMEZONE")
    prompts = _counting_yes(monkeypatch)
    config = _load_authorization_config()
    discovery = _build_discovery_from_export(env)

    result = _one_authorization(
        config,
        "SYSTEM_TIMEZONE",
        require_approval=False,
        validity=_BATCH_AUTHORIZATION_VALIDITY,
        discovery=discovery,
        expected_execution_intent_digest=digest,
    )

    assert result == 0
    assert len(prompts) == 0
    paths = artifact_paths_for(config.artifact_base_directory, "SYSTEM_TIMEZONE")
    assert paths.authorization_inbox_file.exists()


def test_ordinary_single_capability_path_is_unaffected(tmp_path, monkeypatch):
    """The pre-existing `sign-authorization` (non-batch) behavior must be
    byte-for-byte unchanged: default `require_approval=True`, default
    5-minute `_AUTHORIZATION_VALIDITY`, and still one prompt per call."""

    from signing.write_batch1_signing import _AUTHORIZATION_VALIDITY

    env = _fixture(tmp_path, monkeypatch)
    _write_preview(tmp_path, env, "SYSTEM_TIMEZONE")
    prompts = _counting_yes(monkeypatch)
    config = _load_authorization_config()

    result = _one_authorization(config, "SYSTEM_TIMEZONE")

    assert result == 0
    assert len(prompts) == 1
    paths = artifact_paths_for(config.artifact_base_directory, "SYSTEM_TIMEZONE")
    authz = load_signed_plan_authorization_v2(paths.authorization_inbox_file)
    assert authz.expires_at - authz.issued_at == _AUTHORIZATION_VALIDITY


# ---------------------------------------------------------------------------
# 2026-09-05 owner review: cryptographic batch-owner-approval binding
# ---------------------------------------------------------------------------


def _find_batch_owner_approval_path(artifact_base_directory: Path) -> Path:
    matches = list((artifact_base_directory / "_batches").glob("*/batch-owner-approval.json"))
    assert len(matches) == 1, "expected exactly one batch owner approval artifact"
    return matches[0]


def test_batch_produces_a_verifiable_signed_batch_owner_approval(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    _counting_yes(monkeypatch)

    assert sign_authorization_batch_command(list(_FIVE_SYMBOLS)) == 0

    config = _load_authorization_config()
    authority_data = json.loads(Path(env["PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE"]).read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )
    authorities = PinnedAuthoritySet((authority,))

    approval_path = _find_batch_owner_approval_path(config.artifact_base_directory)
    approval = shape_a_batch_owner_approval_from_bytes(approval_path.read_bytes())

    assert verify_shape_a_batch_owner_approval_signature(approval, authorities) is True
    assert {entry.capability_symbol for entry in approval.entries} == set(_FIVE_SYMBOLS)
    assert approval.expires_at - approval.issued_at == _BATCH_AUTHORIZATION_VALIDITY


def test_every_produced_authorization_satisfies_batch_membership_against_its_own_approval(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    _counting_yes(monkeypatch)

    assert sign_authorization_batch_command(list(_FIVE_SYMBOLS)) == 0

    config = _load_authorization_config()
    authority_data = json.loads(Path(env["PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE"]).read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )
    authorities = PinnedAuthoritySet((authority,))

    approval_path = _find_batch_owner_approval_path(config.artifact_base_directory)
    approval = shape_a_batch_owner_approval_from_bytes(approval_path.read_bytes())

    for symbol in _FIVE_SYMBOLS:
        paths = artifact_paths_for(config.artifact_base_directory, symbol)
        authz = load_signed_plan_authorization_v2(paths.authorization_inbox_file)
        assert (
            verify_plan_authorization_v2_batch_membership(
                authz, approval, capability_symbol=symbol, authorities=authorities
            )
            is True
        )


def test_authorization_from_one_batch_does_not_satisfy_a_different_batchs_approval(tmp_path, monkeypatch):
    """Runs two SEPARATE batches (disjoint capability sets, since a real
    capability can only ever be signed once) and proves an authorization
    genuinely produced under batch A's approval does not satisfy
    membership against batch B's approval for a capability A never
    covered -- and, conversely, that B's approval has no entry at all
    for a capability only A ever signed."""

    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    _counting_yes(monkeypatch)

    first_batch = list(_FIVE_SYMBOLS[:2])
    second_batch = list(_FIVE_SYMBOLS[2:])
    assert sign_authorization_batch_command(first_batch) == 0
    assert sign_authorization_batch_command(second_batch) == 0

    config = _load_authorization_config()
    authority_data = json.loads(Path(env["PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE"]).read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )
    authorities = PinnedAuthoritySet((authority,))

    approval_paths = list((config.artifact_base_directory / "_batches").glob("*/batch-owner-approval.json"))
    assert len(approval_paths) == 2
    approvals = [shape_a_batch_owner_approval_from_bytes(path.read_bytes()) for path in approval_paths]
    approval_covering_first = next(a for a in approvals if first_batch[0] in {e.capability_symbol for e in a.entries})
    approval_covering_second = next(a for a in approvals if second_batch[0] in {e.capability_symbol for e in a.entries})
    assert approval_covering_first is not approval_covering_second

    first_capability = first_batch[0]
    paths = artifact_paths_for(config.artifact_base_directory, first_capability)
    authz_from_first_batch = load_signed_plan_authorization_v2(paths.authorization_inbox_file)

    # Genuinely belongs to its own batch's approval.
    assert (
        verify_plan_authorization_v2_batch_membership(
            authz_from_first_batch, approval_covering_first, capability_symbol=first_capability, authorities=authorities
        )
        is True
    )
    # The OTHER batch's approval has no entry for this capability at all,
    # so membership must fail -- proving an authorization cannot be
    # laundered into a batch it was never part of.
    assert (
        verify_plan_authorization_v2_batch_membership(
            authz_from_first_batch,
            approval_covering_second,
            capability_symbol=first_capability,
            authorities=authorities,
        )
        is False
    )


def test_already_exists_skip_reports_whether_existing_authorization_is_still_valid(tmp_path, monkeypatch, capsys):
    """2026-09-05 owner review: a retry must never leave an operator
    wondering whether an "already exists" skip refers to a live or
    expired artifact."""

    env = _fixture(tmp_path, monkeypatch)
    _write_preview(tmp_path, env, "SYSTEM_TIMEZONE")
    _counting_yes(monkeypatch)
    config = _load_authorization_config()

    assert _one_authorization(config, "SYSTEM_TIMEZONE") == 0
    capsys.readouterr()

    result = _one_authorization(config, "SYSTEM_TIMEZONE")

    assert result == 0
    captured = capsys.readouterr()
    assert "already exists" in captured.out
    assert "still valid" in captured.out
    assert "EXPIRED" not in captured.out
