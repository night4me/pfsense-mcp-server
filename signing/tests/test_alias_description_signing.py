"""Adversarial and functional tests for `signing.alias_description_signing`
-- the off-host, operator-only `sign-confirmation` command.

Run explicitly: `pytest signing/` (excluded from the default suite by
`pyproject.toml`'s `addopts`, matching `lab/`/`witness_daemon/`'s own
established precedent for separate, off-host deployables).
"""

from __future__ import annotations

import inspect
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from pfsense_mcp.security_authorization import PlanAuthorizationV2
from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_v2_signature
from pfsense_mcp.security_plan import (
    ALIAS_DESCRIPTION_WRITE_STEP_ID,
    ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
    ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
    generate_security_posture_plan,
)
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.tier1.artifact_exchange import AuthorizationPreview, PendingConfirmationRequest
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import ArtifactExchangeError
from signing.alias_description_signing import (
    SigningError,
    main,
    render_authorization_review,
    render_confirmation_review,
    sign_authorization_command,
    sign_authorization_preview,
    sign_confirmation_command,
    sign_pending_confirmation,
)
from tests.test_security_discovery import _WITNESS_ENV, _FakeAnchor, _patch_witness_anchor, _provisioned_store_env

NOW = datetime.now(timezone.utc).replace(microsecond=0)
_INTEGRITY_KEY_HEX = "ab" * 32


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _pending(**changes: object) -> PendingConfirmationRequest:
    values: dict[str, object] = {
        "operation": "set_firewall_alias_description_v1",
        "contract_id": "contract-001",
        "operation_id": "operation-001",
        "alias_name": "LAB_ALIAS_TEST",
        "previous_description": "before",
        "requested_description": "after",
        "target_identity_digest": "a" * 64,
        "target_fingerprint": "b" * 64,
        "intent_digest": "c" * 64,
        "expires_at": NOW + timedelta(minutes=5),
        "expected_authority_id": "confirm-owner-1",
        "expected_algorithm": ACCEPTED_ALGORITHM,
    }
    values.update(changes)
    return PendingConfirmationRequest(**values)  # type: ignore[arg-type]


def _authority(authority_id: str = "confirm-owner-1") -> tuple[Ed25519PrivateKey, PinnedAuthority]:
    private, public = _keypair()
    return private, PinnedAuthority(authority_id=authority_id, public_key=public)


def _secure_write(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _authority_file(path: Path, authority: PinnedAuthority) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _secure_write(
        path,
        json.dumps({"authority_id": authority.authority_id, "public_key_hex": authority.public_key.hex()}).encode(),
    )


def _private_key_file(path: Path, private_key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = private_key.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )
    _secure_write(path, raw)


def _integrity_key_file(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _secure_write(
        path, json.dumps({"key_id": "signing-integrity", "epoch": 0, "material_hex": _INTEGRITY_KEY_HEX}).encode()
    )


def _integrity_key_bytes() -> bytes:
    return bytes.fromhex(_INTEGRITY_KEY_HEX)


def _pending_bytes(pending: PendingConfirmationRequest) -> bytes:
    from pfsense_mcp.tier1.artifact_exchange import pending_confirmation_request_to_bytes

    return pending_confirmation_request_to_bytes(pending, integrity_key=_integrity_key_bytes())


# --------------------------------------------------------------------------
# sign_pending_confirmation() -- pure signing logic
# --------------------------------------------------------------------------


def test_sign_pending_confirmation_valid_produces_verifiable_evidence():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)

    evidence = sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)

    assert isinstance(evidence, ConfirmationEvidence)
    assert evidence.contract_id == pending.contract_id
    assert evidence.operation_id == pending.operation_id
    assert evidence.target_identity_digest == pending.target_identity_digest
    assert evidence.target_fingerprint == pending.target_fingerprint
    assert evidence.intent_digest == pending.intent_digest
    assert evidence.expires_at == pending.expires_at
    assert evidence.authority_id == authority.authority_id
    assert Ed25519ConfirmationVerifier((authority,)).verify(evidence)


def test_sign_pending_confirmation_wrong_authority_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id="a-different-authority")

    with pytest.raises(SigningError, match="own pinned authority"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)


def test_sign_pending_confirmation_unsupported_algorithm_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id, expected_algorithm="ed25519-v2")

    with pytest.raises(SigningError, match="unsupported algorithm"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)


def test_sign_pending_confirmation_expired_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id, expires_at=NOW - timedelta(seconds=1))

    with pytest.raises(SigningError, match="expired"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)


def test_sign_pending_confirmation_naive_now_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)

    with pytest.raises(SigningError, match="UTC"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=datetime.now())


def test_sign_pending_confirmation_wrong_key_fails_self_verification():
    _matching_private, authority = _authority()
    wrong_private, _wrong_public = _keypair()
    pending = _pending(expected_authority_id=authority.authority_id)

    with pytest.raises(SigningError, match="self-verification"):
        sign_pending_confirmation(pending=pending, private_key=wrong_private, authority=authority, now=NOW)


def test_sign_pending_confirmation_cannot_substitute_contract_or_digest_fields():
    """Structural: the function accepts only `pending`/`private_key`/
    `authority`/`now` -- there is no parameter shaped like contract_id,
    operation_id, or any digest a caller could substitute."""

    signature = inspect.signature(sign_pending_confirmation)
    assert set(signature.parameters) == {"pending", "private_key", "authority", "now"}


def test_sign_pending_confirmation_operation_mismatch_is_defended_in_depth():
    """PendingConfirmationRequest.__post_init__ already refuses a
    non-accepted operation at construction time (tested in
    tests/tier1/test_artifact_exchange.py) -- this proves
    sign_pending_confirmation() also carries its own redundant check,
    never relying solely on the upstream type's own validation."""

    source = inspect.getsource(sign_pending_confirmation)
    assert "pending.operation != SEMANTIC_UNIT" in source


def test_render_confirmation_review_contains_required_semantic_fields():
    pending = _pending()
    review = render_confirmation_review(pending)
    for expected in (
        pending.operation,
        pending.contract_id,
        pending.operation_id,
        pending.alias_name,
        pending.previous_description,
        pending.requested_description,
        pending.target_identity_digest,
        pending.target_fingerprint,
        pending.intent_digest,
        pending.expected_authority_id,
    ):
        assert expected in review


def test_render_confirmation_review_never_dumps_raw_object():
    """No secrets/keys can appear in the review since PendingConfirmationRequest
    itself never carries any -- structural guard against a future field
    addition being rendered via repr()/vars() instead of explicit fields."""

    review = render_confirmation_review(_pending())
    assert "PendingConfirmationRequest(" not in review


# --------------------------------------------------------------------------
# sign_authorization_preview() -- pure signing logic (W3 Slice 5B)
# --------------------------------------------------------------------------


def _write_protected_env(tmp_path: Path, *, witness_baseline: int = 2) -> dict[str, str]:
    return {
        **_provisioned_store_env(tmp_path, value=witness_baseline, handle="0x01500000"),
        **_WITNESS_ENV,
        "PFSENSE_PROFILE": "write_protected",
    }


def _matching_preview(
    monkeypatch, tmp_path: Path, *, witness_baseline: int = 2, **changes: object
) -> tuple[AuthorizationPreview, dict[str, str]]:
    """A preview whose `requested_plan_digest` matches EXACTLY what
    `generate_security_posture_plan()` independently produces for
    `env` -- the ordinary, non-tampered case a real production process
    would emit."""

    env = _write_protected_env(tmp_path, witness_baseline=witness_baseline)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(witness_baseline))
    plan = generate_security_posture_plan(
        ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE, ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE, env
    )
    values: dict[str, object] = {
        "operation": "set_firewall_alias_description_v1",
        "alias_name": "LAB_ALIAS_TEST",
        "previous_description": "before",
        "requested_description": "after",
        "execution_intent_digest": "e" * 64,
        "requested_plan_digest": compute_plan_digest(plan),
        "requested_step_id": ALIAS_DESCRIPTION_WRITE_STEP_ID,
        "target_capability_posture": ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
        "target_anchor_assurance": ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
        "generated_at": NOW,
    }
    values.update(changes)
    return AuthorizationPreview(**values), env  # type: ignore[arg-type]


def test_sign_authorization_preview_valid_produces_verifiable_authorization(monkeypatch, tmp_path):
    private, authority = _authority(authority_id="authz-owner-1")
    preview, env = _matching_preview(monkeypatch, tmp_path)

    authz = sign_authorization_preview(
        preview=preview,
        private_key=private,
        authority=authority,
        authorization_id="authz-test-1",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        env=env,
    )

    assert isinstance(authz, PlanAuthorizationV2)
    assert authz.plan_digest == preview.requested_plan_digest
    assert len(authz.authorized_executions) == 1
    (binding,) = authz.authorized_executions
    assert binding.step_id == ALIAS_DESCRIPTION_WRITE_STEP_ID
    assert binding.execution_intent_digest == preview.execution_intent_digest
    assert authz.authority_id == authority.authority_id
    assert verify_plan_authorization_v2_signature(authz, PinnedAuthoritySet((authority,)))


def test_sign_authorization_preview_stale_plan_digest_refused(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path, requested_plan_digest="d" * 64)

    with pytest.raises(SigningError, match="stale"):
        sign_authorization_preview(
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_wrong_step_id_refused(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path, requested_step_id="not.the.real.step")

    with pytest.raises(SigningError, match="unsupported step_id"):
        sign_authorization_preview(
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_wrong_target_capability_posture_refused(monkeypatch, tmp_path):
    from pfsense_mcp.security_discovery import CapabilityPosture

    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path, target_capability_posture=CapabilityPosture.READ_ONLY)

    with pytest.raises(SigningError, match="unsupported capability posture"):
        sign_authorization_preview(
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_wrong_target_anchor_assurance_refused(monkeypatch, tmp_path):
    from pfsense_mcp.security_discovery import AnchorAssurance

    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path, target_anchor_assurance=AnchorAssurance.NONE)

    with pytest.raises(SigningError, match="unsupported anchor assurance"):
        sign_authorization_preview(
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_wrong_operation_refused(monkeypatch, tmp_path):
    """Structural defense-in-depth (AuthorizationPreview.__post_init__
    already refuses at construction, tested in
    tests/tier1/test_artifact_exchange.py) -- proves this module also
    checks it independently."""

    source = inspect.getsource(sign_authorization_preview)
    assert "preview.operation != SEMANTIC_UNIT" in source


def test_sign_authorization_preview_changed_security_posture_invalidates_stale_authorization(monkeypatch, tmp_path):
    """W3 Slice 5's own required regression: a live security-posture
    change between when a preview was generated and when it is signed
    must invalidate the preview. Uses two independently CLEAN
    (`safe_to_proceed=True`) environments with different, internally
    self-consistent witness baselines -- deliberately not a mismatch
    scenario (covered separately by
    `test_sign_authorization_preview_refuses_when_posture_is_not_safe_to_proceed`)
    -- so this test isolates exactly the digest-staleness check, not the
    anomaly-detection check."""

    private, authority = _authority()
    (tmp_path / "v1").mkdir()
    (tmp_path / "v2").mkdir()
    preview, _original_env = _matching_preview(monkeypatch, tmp_path / "v1", witness_baseline=2)

    later_env = _write_protected_env(tmp_path / "v2", witness_baseline=5)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(5))  # a DIFFERENT, but still internally consistent, posture
    later_plan = generate_security_posture_plan(
        ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE, ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE, later_env
    )
    assert later_plan.safe_to_proceed is True  # sanity: this env is clean on its own
    assert compute_plan_digest(later_plan) != preview.requested_plan_digest  # sanity: genuinely a different posture

    with pytest.raises(SigningError, match="stale"):
        sign_authorization_preview(
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=later_env,
        )


def test_sign_authorization_preview_refuses_when_posture_is_not_safe_to_proceed(monkeypatch, tmp_path):
    """Defense in depth, independent of the digest-match check: even a
    preview whose digest exactly matches a freshly re-derived plan must
    still be refused if that plan itself reports a detected security
    anomaly (here: a store/witness mismatch)."""

    env = _write_protected_env(tmp_path, witness_baseline=2)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(7))  # mismatch vs. the persisted baseline (2)
    plan = generate_security_posture_plan(
        ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE, ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE, env
    )
    assert plan.safe_to_proceed is False  # sanity: this scenario is a genuine anomaly, not a mistake

    preview = AuthorizationPreview(
        operation="set_firewall_alias_description_v1",
        alias_name="LAB_ALIAS_TEST",
        previous_description="before",
        requested_description="after",
        execution_intent_digest="e" * 64,
        requested_plan_digest=compute_plan_digest(plan),  # matches exactly, on purpose
        requested_step_id=ALIAS_DESCRIPTION_WRITE_STEP_ID,
        target_capability_posture=ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
        target_anchor_assurance=ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
        generated_at=NOW,
    )
    private, authority = _authority()

    with pytest.raises(SigningError, match="not currently safe to proceed"):
        sign_authorization_preview(
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_wrong_key_fails_self_verification(monkeypatch, tmp_path):
    _matching_private, authority = _authority()
    wrong_private, _wrong_public = _keypair()
    preview, env = _matching_preview(monkeypatch, tmp_path)

    with pytest.raises(SigningError, match="self-verification"):
        sign_authorization_preview(
            preview=preview,
            private_key=wrong_private,
            authority=authority,
            authorization_id="authz-test",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_cannot_substitute_security_critical_bindings():
    """Structural: no parameter exists for plan_digest, step_id,
    execution_intent_digest, or authority_id -- every one of those is
    either read from `preview` or `authority`, or independently
    re-derived internally; none can be substituted by a caller."""

    signature = inspect.signature(sign_authorization_preview)
    assert set(signature.parameters) == {
        "preview",
        "private_key",
        "authority",
        "authorization_id",
        "issued_at",
        "expires_at",
        "env",
    }


def test_authorization_preview_from_a_different_request_cannot_be_spliced_into_a_matching_one(monkeypatch, tmp_path):
    """Preview/artifact splicing fails closed: substituting a genuine
    execution_intent_digest from a DIFFERENT, unrelated preview into an
    otherwise-matching one still produces a signed artifact bound to
    the SPLICED digest, not the original -- proving there is no way to
    silently keep the original semantic content while swapping in a
    different execution's digest without the operator seeing exactly
    what they are about to sign (render_authorization_review always
    reflects the object actually passed to signing)."""

    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path)
    spliced = AuthorizationPreview(
        operation=preview.operation,
        alias_name=preview.alias_name,
        previous_description=preview.previous_description,
        requested_description=preview.requested_description,
        execution_intent_digest="f" * 64,  # a DIFFERENT, unrelated execution's digest
        requested_plan_digest=preview.requested_plan_digest,
        requested_step_id=preview.requested_step_id,
        target_capability_posture=preview.target_capability_posture,
        target_anchor_assurance=preview.target_anchor_assurance,
        generated_at=preview.generated_at,
    )

    authz = sign_authorization_preview(
        preview=spliced,
        private_key=private,
        authority=authority,
        authorization_id="authz-test",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        env=env,
    )

    # The signed artifact is bound to exactly the spliced digest -- never
    # silently substituted back to the "original" -- and the review the
    # operator would have seen (render_authorization_review(spliced))
    # shows that exact, spliced digest, never a hidden one.
    (binding,) = authz.authorized_executions
    assert binding.execution_intent_digest == "f" * 64
    assert "f" * 64 in render_authorization_review(spliced)


def test_render_authorization_review_contains_required_semantic_fields(monkeypatch, tmp_path):
    preview, _env = _matching_preview(monkeypatch, tmp_path)
    review = render_authorization_review(preview)
    for expected in (
        preview.operation,
        preview.alias_name,
        preview.previous_description,
        preview.requested_description,
        preview.target_capability_posture.value,
        preview.target_anchor_assurance.value,
        preview.requested_step_id,
        preview.requested_plan_digest,
        preview.execution_intent_digest,
    ):
        assert expected in review


def test_render_authorization_review_never_dumps_raw_object(monkeypatch, tmp_path):
    preview, _env = _matching_preview(monkeypatch, tmp_path)
    review = render_authorization_review(preview)
    assert "AuthorizationPreview(" not in review


# --------------------------------------------------------------------------
# sign_authorization_command() -- full CLI workflow (W3 Slice 5B)
# --------------------------------------------------------------------------


def _set_authorization_env(
    monkeypatch,
    tmp_path: Path,
    *,
    preview: AuthorizationPreview,
    authority: PinnedAuthority,
    private_key: Ed25519PrivateKey,
    posture_env: dict[str, str],
) -> Path:
    preview_file = tmp_path / "preview.json"
    integrity_key_file = tmp_path / "integrity.json"
    authority_file = tmp_path / "authority.json"
    private_key_file = tmp_path / "private.key"
    output_file = tmp_path / "signed-authorization.json"

    from pfsense_mcp.tier1.artifact_exchange import authorization_preview_to_bytes

    _secure_write(preview_file, authorization_preview_to_bytes(preview, integrity_key=_integrity_key_bytes()))
    _integrity_key_file(integrity_key_file)
    _authority_file(authority_file, authority)
    _private_key_file(private_key_file, private_key)

    monkeypatch.setenv("PFSENSE_SIGNING_AUTHORIZATION_PREVIEW_FILE", str(preview_file))
    monkeypatch.setenv("PFSENSE_SIGNING_AUTHORIZATION_PREVIEW_INTEGRITY_KEY_FILE", str(integrity_key_file))
    monkeypatch.setenv("PFSENSE_SIGNING_AUTHORIZATION_AUTHORITY_FILE", str(authority_file))
    monkeypatch.setenv("PFSENSE_SIGNING_AUTHORIZATION_PRIVATE_KEY_FILE", str(private_key_file))
    monkeypatch.setenv("PFSENSE_SIGNING_AUTHORIZATION_OUTPUT_FILE", str(output_file))
    for key, value in posture_env.items():
        monkeypatch.setenv(key, value)
    return output_file


def test_sign_authorization_command_end_to_end_with_approval(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path)
    output_file = _set_authorization_env(
        monkeypatch, tmp_path, preview=preview, authority=authority, private_key=private, posture_env=env
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    exit_code = sign_authorization_command()

    assert exit_code == 0
    assert output_file.exists()
    from pfsense_mcp.tier1.artifact_exchange import load_signed_plan_authorization_v2

    authz = load_signed_plan_authorization_v2(output_file)
    assert verify_plan_authorization_v2_signature(authz, PinnedAuthoritySet((authority,)))
    assert authz.plan_digest == preview.requested_plan_digest


def test_sign_authorization_command_refused_without_explicit_approval(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path)
    output_file = _set_authorization_env(
        monkeypatch, tmp_path, preview=preview, authority=authority, private_key=private, posture_env=env
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    exit_code = sign_authorization_command()

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_authorization_command_malformed_preview_refused(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path)
    output_file = _set_authorization_env(
        monkeypatch, tmp_path, preview=preview, authority=authority, private_key=private, posture_env=env
    )
    _secure_write(Path(os.environ["PFSENSE_SIGNING_AUTHORIZATION_PREVIEW_FILE"]), b"not json")
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("must never prompt for a malformed artifact"))

    with pytest.raises(ArtifactExchangeError):
        sign_authorization_command()
    assert not output_file.exists()


def test_sign_authorization_command_existing_output_not_overwritten(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path)
    output_file = _set_authorization_env(
        monkeypatch, tmp_path, preview=preview, authority=authority, private_key=private, posture_env=env
    )
    _secure_write(output_file, b'{"unrelated": "leftover-artifact"}')
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    with pytest.raises(ArtifactExchangeError, match="could not be created"):
        sign_authorization_command()
    assert output_file.read_bytes() == b'{"unrelated": "leftover-artifact"}'


def test_sign_authorization_command_altered_signed_artifact_fails_verification(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path)
    output_file = _set_authorization_env(
        monkeypatch, tmp_path, preview=preview, authority=authority, private_key=private, posture_env=env
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    sign_authorization_command()

    from pfsense_mcp.tier1.artifact_exchange import load_signed_plan_authorization_v2

    raw = json.loads(output_file.read_text())
    raw["authorization_id"] = "a-different-authorization-id"
    output_file.unlink()
    _secure_write(output_file, json.dumps(raw).encode())

    tampered = load_signed_plan_authorization_v2(output_file)
    assert not verify_plan_authorization_v2_signature(tampered, PinnedAuthoritySet((authority,)))


def test_main_dispatches_to_sign_authorization(monkeypatch, tmp_path):
    private, authority = _authority()
    preview, env = _matching_preview(monkeypatch, tmp_path)
    output_file = _set_authorization_env(
        monkeypatch, tmp_path, preview=preview, authority=authority, private_key=private, posture_env=env
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    exit_code = main(["sign-authorization"])

    assert exit_code == 0
    assert output_file.exists()


# --------------------------------------------------------------------------
# sign_confirmation_command() / main() -- full CLI workflow
# --------------------------------------------------------------------------


def _set_env(
    monkeypatch,
    tmp_path: Path,
    *,
    pending: PendingConfirmationRequest,
    authority: PinnedAuthority,
    private_key: Ed25519PrivateKey,
) -> Path:
    pending_file = tmp_path / "pending.json"
    integrity_key_file = tmp_path / "integrity.json"
    authority_file = tmp_path / "authority.json"
    private_key_file = tmp_path / "private.key"
    output_file = tmp_path / "signed.json"

    _secure_write(pending_file, _pending_bytes(pending))
    _integrity_key_file(integrity_key_file)
    _authority_file(authority_file, authority)
    _private_key_file(private_key_file, private_key)

    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE", str(pending_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_PENDING_INTEGRITY_KEY_FILE", str(integrity_key_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_AUTHORITY_FILE", str(authority_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_PRIVATE_KEY_FILE", str(private_key_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_OUTPUT_FILE", str(output_file))
    return output_file


def test_sign_confirmation_command_end_to_end_with_approval(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    exit_code = sign_confirmation_command()

    assert exit_code == 0
    assert output_file.exists()
    from pfsense_mcp.tier1.artifact_exchange import load_signed_confirmation_evidence

    evidence = load_signed_confirmation_evidence(output_file)
    assert Ed25519ConfirmationVerifier((authority,)).verify(evidence)
    assert evidence.contract_id == pending.contract_id


def test_sign_confirmation_command_refused_without_explicit_approval(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    exit_code = sign_confirmation_command()

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_confirmation_command_refused_on_empty_input(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")

    exit_code = sign_confirmation_command()

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_confirmation_command_malformed_pending_refused(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    _secure_write(Path(os.environ["PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE"]), b"not json")
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("must never prompt for a malformed artifact"))

    with pytest.raises(ArtifactExchangeError):
        sign_confirmation_command()
    assert not output_file.exists()


def test_sign_confirmation_command_tampered_pending_refused(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    pending_path = Path(os.environ["PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE"])
    raw = json.loads(pending_path.read_text())
    raw["requested_description"] = "an attacker-edited description"
    pending_path.unlink()
    _secure_write(pending_path, json.dumps(raw).encode())
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("must never prompt for a tampered artifact"))

    with pytest.raises(ArtifactExchangeError, match="integrity"):
        sign_confirmation_command()
    assert not output_file.exists()


def test_sign_confirmation_command_unsupported_schema_refused(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    pending_path = Path(os.environ["PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE"])
    raw = json.loads(pending_path.read_text())
    raw["schema_version"] = 999
    pending_path.unlink()
    _secure_write(pending_path, json.dumps(raw).encode())
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("must never prompt for an unsupported schema"))

    with pytest.raises(ArtifactExchangeError, match="malformed"):
        sign_confirmation_command()
    assert not output_file.exists()


def test_sign_confirmation_command_existing_output_not_overwritten(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    _secure_write(output_file, b'{"unrelated": "leftover-artifact"}')
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    with pytest.raises(ArtifactExchangeError, match="could not be created"):
        sign_confirmation_command()
    assert output_file.read_bytes() == b'{"unrelated": "leftover-artifact"}'


def test_sign_confirmation_command_altered_signed_artifact_fails_verification(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    sign_confirmation_command()

    from pfsense_mcp.tier1.artifact_exchange import load_signed_confirmation_evidence

    raw = json.loads(output_file.read_text())
    raw["contract_id"] = "a-different-contract-id"
    output_file.unlink()
    _secure_write(output_file, json.dumps(raw).encode())

    tampered = load_signed_confirmation_evidence(output_file)
    assert not Ed25519ConfirmationVerifier((authority,)).verify(tampered)


def test_main_dispatches_to_sign_confirmation(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    exit_code = main(["sign-confirmation"])

    assert exit_code == 0
    assert output_file.exists()


def test_main_rejects_unknown_command():
    with pytest.raises(SystemExit):
        main(["not-a-real-command"])


def test_main_catches_and_reports_signing_errors_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE", raising=False)

    exit_code = main(["sign-confirmation"])

    assert exit_code == 1
    assert "Refused:" in capsys.readouterr().out


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


def _code_only_source(module) -> str:
    """`inspect.getsource()` minus the module's own leading docstring --
    isolates actual code (imports, calls, string literals used as CLI
    flags) from explanatory prose that legitimately *names* things this
    module must never do, so a structural check does not false-positive
    on its own documentation."""

    import ast

    tree = ast.parse(inspect.getsource(module))
    body = (
        tree.body[1:]
        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant)
        else tree.body
    )
    return "\n".join(ast.unparse(node) for node in body)


def test_no_automatic_signing_flag_exists():
    """Structural: no argparse flag anywhere in this module's actual code
    can bypass the interactive input() approval gate."""

    import signing.alias_description_signing as module

    code = _code_only_source(module)
    for forbidden in ("--yes", "--force", "--auto", "--no-confirm", "--non-interactive"):
        assert forbidden not in code


def test_module_never_imports_pfsense_network_transport():
    import ast

    import signing.alias_description_signing as module

    tree = ast.parse(inspect.getsource(module))
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported_names.add(node.module or "")
            imported_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported_names.update(alias.name for alias in node.names)
    forbidden = {
        "httpx",
        "WriteApiClient",
        "PfSenseClient",
        "rest_api_client",
        "build_pfsense_client",
        "build_write_client",
    }
    assert imported_names.isdisjoint(forbidden)


def test_module_never_imports_or_references_production_runtime():
    import ast

    import signing.alias_description_signing as module

    tree = ast.parse(inspect.getsource(module))
    imported_modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any("production_runtime" in name for name in imported_modules)


def test_module_loads_no_private_signing_key_material_it_does_not_own():
    """The only private-key-shaped symbol this module ever references is
    its own Ed25519PrivateKey usage for signing -- never a symmetric
    production encryption/consumption key beyond the one integrity key
    it needs to verify the pending artifact's MAC."""

    import signing.alias_description_signing as module

    source = inspect.getsource(module)
    assert "KeyPurpose.ENCRYPTION" not in source
