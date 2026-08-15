from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync
from pfsense_mcp.security_authorization import (
    PlanAuthorizationStepBinding,
    build_plan_authorization_v2_payload,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.alias_description import (
    SEMANTIC_UNIT,
    AliasDescriptionChangeV1,
    AliasDescriptionPreparerV1,
    ConfiguredApplianceTargetV1,
)
from pfsense_mcp.tier1.artifact_exchange import (
    AuthorizationPreview,
    PendingConfirmationRequest,
    authorization_preview_from_preparation,
    authorization_preview_to_bytes,
    confirmation_evidence_to_bytes,
    load_authorization_preview,
    load_pending_confirmation_request,
    load_signed_confirmation_evidence,
    load_signed_plan_authorization_v2,
    pending_confirmation_request_from_contract,
    pending_confirmation_request_to_bytes,
    plan_authorization_v2_to_bytes,
    write_secure_new,
)
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier, signing_payload
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
from pfsense_mcp.tier1.errors import ArtifactExchangeError
from pfsense_mcp.tier1.prepared_execution_intent import compute_execution_intent_digest
from pfsense_mcp.tls import TLSMode
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

NOW = datetime.now(timezone.utc).replace(microsecond=0)
_INTEGRITY_KEY = b"artifact-exchange-test-integrity-key-32"


class _ReadClient:
    """Minimal synthetic read client, mirroring
    `test_slice3_composition.py`'s own established pattern -- just
    enough to drive `AliasDescriptionPreparerV1.prepare()` to a real,
    fully-validated `PreparedAliasDescriptionExecutionV1` offline."""

    def __init__(self, *, descr: str = "before") -> None:
        self.aliases = [
            FirewallAlias(id=0, name="LAB_ALIAS_TEST", type="host", descr=descr, address=["192.0.2.10"], detail=[""])
        ]

    def get_firewall_aliases(self, *, include_identifying_metadata: bool = False, limit: int = 100):
        return list(self.aliases)

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus:
        return SystemStatus(
            platform="synthetic",
            uptime="1 day",
            cpu_model="synthetic",
            cpu_count=1,
            cpu_usage=0.0,
            mem_usage=1,
            swap_usage=0,
            disk_usage=1,
            netgate_id="netgate-synthetic",
        )

    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync:
        values = {name: False for name, field in SystemHaSync.model_fields.items() if field.annotation is bool}
        values.update(
            {
                "pfsyncinterface": "none",
                "pfsyncpeerip": None,
                "synchronizetoip": None,
                "pfhostid": None,
                "username": None,
            }
        )
        return SystemHaSync.model_validate(values)


def _request() -> AliasDescriptionChangeV1:
    return AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")


def _prepared(*, descr: str = "before", request: AliasDescriptionChangeV1 | None = None):
    target = ConfiguredApplianceTargetV1(base_url="https://pfsense.invalid", tls_mode=TLSMode.STRICT)
    preparer = AliasDescriptionPreparerV1(read_client=_ReadClient(descr=descr), configured_target=target)
    return preparer.prepare(request or _request())


def _secure(path, value: bytes) -> None:
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _authorization(private: Ed25519PrivateKey, digest: str = "a" * 64, **changes: object):
    plan = _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="first.write.alias.description",
                order=1,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
            ),
        )
    )
    values: dict[str, object] = {
        "plan": plan,
        "authorized_executions": (
            PlanAuthorizationStepBinding(step_id="first.write.alias.description", execution_intent_digest=digest),
        ),
        "authorization_id": "authz-v2-artifact-exchange",
        "authority_id": "owner-v2",
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=4),
    }
    values.update(changes)
    return sign_plan_authorization_v2(build_plan_authorization_v2_payload(**values), private)  # type: ignore[arg-type]


def _confirmation(private: Ed25519PrivateKey, contract, **changes: object) -> ConfirmationEvidence:
    values: dict[str, object] = {
        "authority_id": "owner-confirm",
        "algorithm": ACCEPTED_ALGORITHM,
        "nonce": "nonce-1",
        "contract_id": contract.contract_id,
        "operation_id": contract.operation_id,
        "target_identity_digest": contract.target_identity_digest,
        "target_fingerprint": contract.target_fingerprint,
        "intent_digest": contract.intent_digest,
        "expires_at": contract.expires_at,
        "issued_at": NOW - timedelta(seconds=1),
    }
    values.update(changes)
    unsigned = ConfirmationEvidence(**values, proof=b"x" * 64)  # type: ignore[arg-type]
    proof = private.sign(signing_payload(unsigned))
    return ConfirmationEvidence(**{**values, "proof": proof})  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# write_secure_new
# --------------------------------------------------------------------------


def test_write_secure_new_round_trips(tmp_path):
    target = tmp_path / "artifact.json"
    write_secure_new(target, b"hello")
    assert target.read_bytes() == b"hello"
    assert (target.stat().st_mode & 0o777) == 0o600


def test_write_secure_new_refuses_to_overwrite_existing_artifact(tmp_path):
    target = tmp_path / "artifact.json"
    write_secure_new(target, b"first")
    with pytest.raises(ArtifactExchangeError, match="could not be created"):
        write_secure_new(target, b"second")
    assert target.read_bytes() == b"first"


def test_write_secure_new_refuses_symlink_target(tmp_path):
    real = tmp_path / "real.json"
    real.write_bytes(b"x")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ArtifactExchangeError, match="could not be created"):
        write_secure_new(link, b"second")


def test_partial_secure_write_removes_incomplete_artifact(tmp_path, monkeypatch):
    output = tmp_path / "artifact.json"

    def fail_write(_fd, _value):
        return 0

    monkeypatch.setattr(os, "write", fail_write)
    with pytest.raises(ArtifactExchangeError, match="could not be written"):
        write_secure_new(output, b"evidence")
    assert not output.exists()


# --------------------------------------------------------------------------
# PlanAuthorizationV2
# --------------------------------------------------------------------------


def test_plan_authorization_v2_round_trips(tmp_path):
    private, _public = _keypair()
    authorization = _authorization(private)
    path = tmp_path / "authorization.json"
    write_secure_new(path, plan_authorization_v2_to_bytes(authorization))

    loaded = load_signed_plan_authorization_v2(path)

    assert loaded == authorization


def test_plan_authorization_v2_encode_rejects_non_authorization():
    with pytest.raises(ArtifactExchangeError, match="Expected PlanAuthorizationV2"):
        plan_authorization_v2_to_bytes(object())  # type: ignore[arg-type]


def test_load_signed_plan_authorization_v2_rejects_malformed_json(tmp_path):
    path = tmp_path / "authorization.json"
    _secure(path, b"not json")
    with pytest.raises(ArtifactExchangeError, match="malformed"):
        load_signed_plan_authorization_v2(path)


def test_load_signed_plan_authorization_v2_rejects_missing_file(tmp_path):
    with pytest.raises(ArtifactExchangeError):
        load_signed_plan_authorization_v2(tmp_path / "missing.json")


@pytest.mark.parametrize("mutation", ["drop_key", "extra_key", "wrong_schema_version", "empty_bindings"])
def test_load_signed_plan_authorization_v2_rejects_wrong_shape(tmp_path, mutation):
    import json

    private, _public = _keypair()
    raw = json.loads(plan_authorization_v2_to_bytes(_authorization(private)))
    if mutation == "drop_key":
        del raw["plan_digest"]
    elif mutation == "extra_key":
        raw["unexpected"] = "value"
    elif mutation == "wrong_schema_version":
        raw["schema_version"] = 999
    elif mutation == "empty_bindings":
        raw["authorized_executions"] = []
    path = tmp_path / "authorization.json"
    _secure(path, json.dumps(raw).encode())
    with pytest.raises(ArtifactExchangeError, match="malformed"):
        load_signed_plan_authorization_v2(path)


def test_load_signed_plan_authorization_v2_rejects_bad_proof_encoding(tmp_path):
    import json

    private, _public = _keypair()
    raw = json.loads(plan_authorization_v2_to_bytes(_authorization(private)))
    raw["proof"] = "not-base64!!"
    path = tmp_path / "authorization.json"
    _secure(path, json.dumps(raw).encode())
    with pytest.raises(ArtifactExchangeError, match="malformed"):
        load_signed_plan_authorization_v2(path)


def test_load_signed_plan_authorization_v2_rejects_short_proof(tmp_path):
    import json

    private, _public = _keypair()
    raw = json.loads(plan_authorization_v2_to_bytes(_authorization(private)))
    raw["proof"] = base64.b64encode(b"short").decode("ascii")
    path = tmp_path / "authorization.json"
    _secure(path, json.dumps(raw).encode())
    with pytest.raises(ArtifactExchangeError, match="malformed"):
        load_signed_plan_authorization_v2(path)


def test_plan_authorization_v2_permissions_and_symlink_fail_closed(tmp_path):
    private, _public = _keypair()
    authorization = _authorization(private)
    path = tmp_path / "authorization.json"
    write_secure_new(path, plan_authorization_v2_to_bytes(authorization))
    os.chmod(path, 0o644)
    with pytest.raises(ArtifactExchangeError):
        load_signed_plan_authorization_v2(path)

    path.unlink()
    target = tmp_path / "target.json"
    _secure(target, plan_authorization_v2_to_bytes(authorization))
    path.symlink_to(target)
    with pytest.raises(ArtifactExchangeError):
        load_signed_plan_authorization_v2(path)


def test_plan_authorization_v2_oversized_file_fails_closed(tmp_path):
    private, _public = _keypair()
    authorization = _authorization(private)
    body = plan_authorization_v2_to_bytes(authorization)
    padded = body[:-1] + b'"' + b" " * 20_000 + b'"}'
    path = tmp_path / "authorization.json"
    _secure(path, padded)
    with pytest.raises(ArtifactExchangeError):
        load_signed_plan_authorization_v2(path)


# --------------------------------------------------------------------------
# AuthorizationPreview (W3 Slice 5A)
# --------------------------------------------------------------------------


def _preview(**changes: object) -> AuthorizationPreview:
    prepared = _prepared()
    values: dict[str, object] = {
        "request": _request(),
        "prepared": prepared,
        "requested_plan_digest": "a" * 64,
        "requested_step_id": "capability_posture.milestone_9_activation",
        "target_capability_posture": CapabilityPosture.WRITE_PROTECTED,
        "target_anchor_assurance": AnchorAssurance.HARDWARE_WITNESS,
        "generated_at": NOW,
    }
    values.update(changes)
    return authorization_preview_from_preparation(**values)  # type: ignore[arg-type]


def test_authorization_preview_generated_only_from_fresh_authoritative_preparation():
    prepared = _prepared(descr="the current live description")
    preview = authorization_preview_from_preparation(
        _request(),
        prepared,
        requested_plan_digest="a" * 64,
        requested_step_id="capability_posture.milestone_9_activation",
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        generated_at=NOW,
    )
    assert preview.operation == SEMANTIC_UNIT
    assert preview.alias_name == "LAB_ALIAS_TEST"
    assert preview.previous_description == "the current live description"
    assert preview.requested_description == "after"
    assert preview.execution_intent_digest == compute_execution_intent_digest(prepared.intent)
    assert preview.requested_plan_digest == "a" * 64
    assert preview.requested_step_id == "capability_posture.milestone_9_activation"
    assert preview.target_capability_posture is CapabilityPosture.WRITE_PROTECTED
    assert preview.target_anchor_assurance is AnchorAssurance.HARDWARE_WITNESS
    assert preview.generated_at == NOW


def test_authorization_preview_execution_intent_digest_cannot_be_substituted():
    """Structural: `authorization_preview_from_preparation()` has no
    `execution_intent_digest` parameter at all -- there is no way for a
    caller to supply one that does not correspond to `prepared.intent`,
    and therefore no way to reuse a digest computed for a different
    alias/description pair."""

    import inspect

    signature = inspect.signature(authorization_preview_from_preparation)
    assert "execution_intent_digest" not in signature.parameters


def test_authorization_preview_reflects_a_different_request_and_preparation():
    """Two different (request, prepared) pairs never produce the same
    execution_intent_digest -- proves the digest genuinely tracks the
    exact semantic content, not a fixed/ignored value."""

    first = _preview()
    other_request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="a completely different value")
    second = authorization_preview_from_preparation(
        other_request,
        _prepared(request=other_request),
        requested_plan_digest="a" * 64,
        requested_step_id="capability_posture.milestone_9_activation",
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        generated_at=NOW,
    )
    assert first.execution_intent_digest != second.execution_intent_digest
    assert first.requested_description != second.requested_description


def test_authorization_preview_round_trips(tmp_path):
    preview = _preview()
    path = tmp_path / "preview.json"
    write_secure_new(path, authorization_preview_to_bytes(preview, integrity_key=_INTEGRITY_KEY))

    loaded = load_authorization_preview(path, integrity_key=_INTEGRITY_KEY)

    assert loaded == preview


def test_authorization_preview_rejects_invalid_fields():
    prepared = _prepared()
    with pytest.raises(ArtifactExchangeError, match="operation"):
        AuthorizationPreview(
            operation="not-the-fixed-operation",
            alias_name="LAB_ALIAS_TEST",
            previous_description="before",
            requested_description="after",
            execution_intent_digest=compute_execution_intent_digest(prepared.intent),
            requested_plan_digest="a" * 64,
            requested_step_id="capability_posture.milestone_9_activation",
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            generated_at=NOW,
        )
    with pytest.raises(ArtifactExchangeError, match="alias_name"):
        AuthorizationPreview(
            operation=SEMANTIC_UNIT,
            alias_name="",
            previous_description="before",
            requested_description="after",
            execution_intent_digest=compute_execution_intent_digest(prepared.intent),
            requested_plan_digest="a" * 64,
            requested_step_id="capability_posture.milestone_9_activation",
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            generated_at=NOW,
        )
    with pytest.raises(ArtifactExchangeError, match="digest"):
        AuthorizationPreview(
            operation=SEMANTIC_UNIT,
            alias_name="LAB_ALIAS_TEST",
            previous_description="before",
            requested_description="after",
            execution_intent_digest="not-hex",
            requested_plan_digest="a" * 64,
            requested_step_id="capability_posture.milestone_9_activation",
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            generated_at=NOW,
        )
    with pytest.raises(ArtifactExchangeError, match="UTC"):
        AuthorizationPreview(
            operation=SEMANTIC_UNIT,
            alias_name="LAB_ALIAS_TEST",
            previous_description="before",
            requested_description="after",
            execution_intent_digest=compute_execution_intent_digest(prepared.intent),
            requested_plan_digest="a" * 64,
            requested_step_id="capability_posture.milestone_9_activation",
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            generated_at=datetime.now(),  # naive -- not UTC
        )


def test_authorization_preview_tamper_fails_closed(tmp_path):
    preview = _preview()
    path = tmp_path / "preview.json"
    write_secure_new(path, authorization_preview_to_bytes(preview, integrity_key=_INTEGRITY_KEY))

    import json

    raw = json.loads(path.read_text())
    raw["requested_description"] = "an attacker-edited description"
    path.unlink()
    _secure(path, json.dumps(raw).encode())

    with pytest.raises(ArtifactExchangeError, match="integrity"):
        load_authorization_preview(path, integrity_key=_INTEGRITY_KEY)


def test_authorization_preview_cannot_reuse_a_different_previews_digest(tmp_path):
    """Splicing a genuine `requested_description`/`execution_intent_digest`
    pair from a DIFFERENT, otherwise-unrelated genuine preview into this
    one's on-disk JSON still fails the integrity MAC -- the digest and
    the semantic fields are bound together as one unit by the MAC, never
    independently swappable, even when both halves are individually
    "genuine" values from real previews."""

    import json

    genuine = _preview()
    different_request = AliasDescriptionChangeV1(
        alias_name="LAB_ALIAS_TEST", description="a totally different description"
    )
    other = authorization_preview_from_preparation(
        different_request,
        _prepared(request=different_request),
        requested_plan_digest="a" * 64,
        requested_step_id="capability_posture.milestone_9_activation",
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        generated_at=NOW,
    )
    assert genuine.execution_intent_digest != other.execution_intent_digest

    path = tmp_path / "preview.json"
    write_secure_new(path, authorization_preview_to_bytes(genuine, integrity_key=_INTEGRITY_KEY))
    raw = json.loads(path.read_text())
    raw["requested_description"] = other.requested_description
    raw["execution_intent_digest"] = other.execution_intent_digest
    path.unlink()
    _secure(path, json.dumps(raw).encode())

    with pytest.raises(ArtifactExchangeError, match="integrity"):
        load_authorization_preview(path, integrity_key=_INTEGRITY_KEY)


def test_authorization_preview_wrong_integrity_key_fails_closed(tmp_path):
    preview = _preview()
    path = tmp_path / "preview.json"
    write_secure_new(path, authorization_preview_to_bytes(preview, integrity_key=_INTEGRITY_KEY))

    with pytest.raises(ArtifactExchangeError, match="integrity"):
        load_authorization_preview(path, integrity_key=b"a-completely-different-32-byte-key")


def test_authorization_preview_permissions_and_symlink_fail_closed(tmp_path):
    preview = _preview()
    body = authorization_preview_to_bytes(preview, integrity_key=_INTEGRITY_KEY)
    path = tmp_path / "preview.json"
    _secure(path, body)
    os.chmod(path, 0o644)
    with pytest.raises(ArtifactExchangeError):
        load_authorization_preview(path, integrity_key=_INTEGRITY_KEY)

    path.unlink()
    target = tmp_path / "target.json"
    _secure(target, body)
    path.symlink_to(target)
    with pytest.raises(ArtifactExchangeError):
        load_authorization_preview(path, integrity_key=_INTEGRITY_KEY)


def test_authorization_preview_to_bytes_rejects_non_preview():
    with pytest.raises(ArtifactExchangeError, match="Expected AuthorizationPreview"):
        authorization_preview_to_bytes(object(), integrity_key=_INTEGRITY_KEY)  # type: ignore[arg-type]


def test_authorization_preview_from_preparation_rejects_wrong_types():
    with pytest.raises(ArtifactExchangeError, match="Expected"):
        authorization_preview_from_preparation(
            object(),  # type: ignore[arg-type]
            _prepared(),
            requested_plan_digest="a" * 64,
            requested_step_id="capability_posture.milestone_9_activation",
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            generated_at=NOW,
        )


def test_authorization_preview_grants_no_authority_by_itself():
    """The preview type carries no signature/proof field and is never
    consulted by any verification primitive -- structural proof that
    possessing or reading one cannot itself authorize anything."""

    preview = _preview()
    assert not hasattr(preview, "proof")
    assert not hasattr(preview, "signature")


# --------------------------------------------------------------------------
# PendingConfirmationRequest
# --------------------------------------------------------------------------


def test_pending_confirmation_request_from_contract(contract_factory):
    contract = contract_factory()
    pending = pending_confirmation_request_from_contract(
        contract,
        alias_name="LAB_ALIAS_TEST",
        previous_description="before",
        requested_description="after",
        expected_authority_id="owner-confirm",
    )
    assert pending.operation == SEMANTIC_UNIT
    assert pending.contract_id == contract.contract_id
    assert pending.operation_id == contract.operation_id
    assert pending.alias_name == "LAB_ALIAS_TEST"
    assert pending.previous_description == "before"
    assert pending.requested_description == "after"
    assert pending.target_identity_digest == contract.target_identity_digest
    assert pending.target_fingerprint == contract.target_fingerprint
    assert pending.intent_digest == contract.intent_digest
    assert pending.expires_at == contract.expires_at
    assert pending.expected_authority_id == "owner-confirm"
    assert pending.expected_algorithm == ACCEPTED_ALGORITHM


def test_pending_confirmation_request_round_trips(tmp_path, contract_factory):
    contract = contract_factory()
    pending = pending_confirmation_request_from_contract(
        contract,
        alias_name="LAB_ALIAS_TEST",
        previous_description="before",
        requested_description="after",
        expected_authority_id="owner-confirm",
    )
    path = tmp_path / "pending.json"
    write_secure_new(path, pending_confirmation_request_to_bytes(pending, integrity_key=_INTEGRITY_KEY))

    loaded = load_pending_confirmation_request(path, integrity_key=_INTEGRITY_KEY)

    assert loaded == pending


def test_pending_confirmation_request_rejects_invalid_fields(contract_factory):
    contract = contract_factory()
    with pytest.raises(ArtifactExchangeError, match="digest"):
        PendingConfirmationRequest(
            operation=SEMANTIC_UNIT,
            contract_id=contract.contract_id,
            operation_id=contract.operation_id,
            alias_name="LAB_ALIAS_TEST",
            previous_description="before",
            requested_description="after",
            target_identity_digest="not-hex",
            target_fingerprint=contract.target_fingerprint,
            intent_digest=contract.intent_digest,
            expires_at=contract.expires_at,
            expected_authority_id="owner-confirm",
            expected_algorithm=ACCEPTED_ALGORITHM,
        )
    with pytest.raises(ArtifactExchangeError, match="UTC"):
        PendingConfirmationRequest(
            operation=SEMANTIC_UNIT,
            contract_id=contract.contract_id,
            operation_id=contract.operation_id,
            alias_name="LAB_ALIAS_TEST",
            previous_description="before",
            requested_description="after",
            target_identity_digest=contract.target_identity_digest,
            target_fingerprint=contract.target_fingerprint,
            intent_digest=contract.intent_digest,
            expires_at=datetime.now(),  # naive -- not UTC
            expected_authority_id="owner-confirm",
            expected_algorithm=ACCEPTED_ALGORITHM,
        )
    with pytest.raises(ArtifactExchangeError, match="operation"):
        PendingConfirmationRequest(
            operation="not-the-fixed-operation",
            contract_id=contract.contract_id,
            operation_id=contract.operation_id,
            alias_name="LAB_ALIAS_TEST",
            previous_description="before",
            requested_description="after",
            target_identity_digest=contract.target_identity_digest,
            target_fingerprint=contract.target_fingerprint,
            intent_digest=contract.intent_digest,
            expires_at=contract.expires_at,
            expected_authority_id="owner-confirm",
            expected_algorithm=ACCEPTED_ALGORITHM,
        )
    with pytest.raises(ArtifactExchangeError, match="alias_name"):
        PendingConfirmationRequest(
            operation=SEMANTIC_UNIT,
            contract_id=contract.contract_id,
            operation_id=contract.operation_id,
            alias_name="",
            previous_description="before",
            requested_description="after",
            target_identity_digest=contract.target_identity_digest,
            target_fingerprint=contract.target_fingerprint,
            intent_digest=contract.intent_digest,
            expires_at=contract.expires_at,
            expected_authority_id="owner-confirm",
            expected_algorithm=ACCEPTED_ALGORITHM,
        )


def test_pending_confirmation_request_tamper_fails_closed(tmp_path, contract_factory):
    contract = contract_factory()
    pending = pending_confirmation_request_from_contract(
        contract,
        alias_name="LAB_ALIAS_TEST",
        previous_description="before",
        requested_description="after",
        expected_authority_id="owner-confirm",
    )
    path = tmp_path / "pending.json"
    write_secure_new(path, pending_confirmation_request_to_bytes(pending, integrity_key=_INTEGRITY_KEY))

    import json

    raw = json.loads(path.read_text())
    raw["target_identity_digest"] = "b" * 64
    path.unlink()
    _secure(path, json.dumps(raw).encode())

    with pytest.raises(ArtifactExchangeError, match="integrity"):
        load_pending_confirmation_request(path, integrity_key=_INTEGRITY_KEY)


def test_pending_confirmation_request_wrong_integrity_key_fails_closed(tmp_path, contract_factory):
    contract = contract_factory()
    pending = pending_confirmation_request_from_contract(
        contract,
        alias_name="LAB_ALIAS_TEST",
        previous_description="before",
        requested_description="after",
        expected_authority_id="owner-confirm",
    )
    path = tmp_path / "pending.json"
    write_secure_new(path, pending_confirmation_request_to_bytes(pending, integrity_key=_INTEGRITY_KEY))

    with pytest.raises(ArtifactExchangeError, match="integrity"):
        load_pending_confirmation_request(path, integrity_key=b"a-completely-different-32-byte-key")


def test_pending_confirmation_request_permissions_and_symlink_fail_closed(tmp_path, contract_factory):
    contract = contract_factory()
    pending = pending_confirmation_request_from_contract(
        contract,
        alias_name="LAB_ALIAS_TEST",
        previous_description="before",
        requested_description="after",
        expected_authority_id="owner-confirm",
    )
    body = pending_confirmation_request_to_bytes(pending, integrity_key=_INTEGRITY_KEY)
    path = tmp_path / "pending.json"
    _secure(path, body)
    os.chmod(path, 0o644)
    with pytest.raises(ArtifactExchangeError):
        load_pending_confirmation_request(path, integrity_key=_INTEGRITY_KEY)

    path.unlink()
    target = tmp_path / "target.json"
    _secure(target, body)
    path.symlink_to(target)
    with pytest.raises(ArtifactExchangeError):
        load_pending_confirmation_request(path, integrity_key=_INTEGRITY_KEY)


def test_pending_confirmation_request_to_bytes_rejects_non_pending():
    with pytest.raises(ArtifactExchangeError, match="Expected PendingConfirmationRequest"):
        pending_confirmation_request_to_bytes(object(), integrity_key=_INTEGRITY_KEY)  # type: ignore[arg-type]


def test_pending_confirmation_request_mac_rejects_short_integrity_key(contract_factory):
    contract = contract_factory()
    pending = pending_confirmation_request_from_contract(
        contract,
        alias_name="LAB_ALIAS_TEST",
        previous_description="before",
        requested_description="after",
        expected_authority_id="owner-confirm",
    )
    with pytest.raises(ArtifactExchangeError, match="integrity key"):
        pending_confirmation_request_to_bytes(pending, integrity_key=b"short")


# --------------------------------------------------------------------------
# ConfirmationEvidence (signed)
# --------------------------------------------------------------------------


def test_confirmation_evidence_round_trips(tmp_path, contract_factory):
    private, public = _keypair()
    contract = contract_factory()
    evidence = _confirmation(private, contract)
    path = tmp_path / "confirmation.json"
    write_secure_new(path, confirmation_evidence_to_bytes(evidence))

    loaded = load_signed_confirmation_evidence(path)

    assert loaded == evidence
    verifier = Ed25519ConfirmationVerifier((PinnedAuthority(authority_id="owner-confirm", public_key=public),))
    assert verifier.verify(loaded)
    loaded.verify_bindings(contract)


def test_confirmation_evidence_encode_rejects_non_evidence():
    with pytest.raises(ArtifactExchangeError, match="Expected ConfirmationEvidence"):
        confirmation_evidence_to_bytes(object())  # type: ignore[arg-type]


def test_load_signed_confirmation_evidence_rejects_malformed_json(tmp_path):
    path = tmp_path / "confirmation.json"
    _secure(path, b"{not json")
    with pytest.raises(ArtifactExchangeError, match="malformed"):
        load_signed_confirmation_evidence(path)


@pytest.mark.parametrize("mutation", ["drop_key", "extra_key", "wrong_schema_version"])
def test_load_signed_confirmation_evidence_rejects_wrong_shape(tmp_path, contract_factory, mutation):
    import json

    private, _public = _keypair()
    contract = contract_factory()
    raw = json.loads(confirmation_evidence_to_bytes(_confirmation(private, contract)))
    if mutation == "drop_key":
        del raw["nonce"]
    elif mutation == "extra_key":
        raw["unexpected"] = "value"
    elif mutation == "wrong_schema_version":
        raw["schema_version"] = 999
    path = tmp_path / "confirmation.json"
    _secure(path, json.dumps(raw).encode())
    with pytest.raises(ArtifactExchangeError, match="malformed"):
        load_signed_confirmation_evidence(path)


def test_confirmation_evidence_permissions_and_symlink_fail_closed(tmp_path, contract_factory):
    private, _public = _keypair()
    contract = contract_factory()
    evidence = _confirmation(private, contract)
    path = tmp_path / "confirmation.json"
    write_secure_new(path, confirmation_evidence_to_bytes(evidence))
    os.chmod(path, 0o644)
    with pytest.raises(ArtifactExchangeError):
        load_signed_confirmation_evidence(path)

    path.unlink()
    target = tmp_path / "target.json"
    _secure(target, confirmation_evidence_to_bytes(evidence))
    path.symlink_to(target)
    with pytest.raises(ArtifactExchangeError):
        load_signed_confirmation_evidence(path)


def test_confirmation_evidence_wrong_authority_fails_verification_not_decode(tmp_path, contract_factory):
    # Decoding never judges authenticity -- a structurally valid artifact
    # signed by an unpinned authority decodes cleanly and only fails at
    # the (separate, already-existing) verifier.
    private, _public = _keypair()
    _other_private, other_public = _keypair()
    contract = contract_factory()
    evidence = _confirmation(private, contract)
    path = tmp_path / "confirmation.json"
    write_secure_new(path, confirmation_evidence_to_bytes(evidence))

    loaded = load_signed_confirmation_evidence(path)
    verifier = Ed25519ConfirmationVerifier((PinnedAuthority(authority_id="owner-confirm", public_key=other_public),))
    assert not verifier.verify(loaded)
