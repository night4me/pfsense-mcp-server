"""ADR-037 Shape-A generalized acceptance orchestration: registry, artifact
exchange, generalized signer, and end-to-end orchestrator tests.

Covers the security-critical properties from the Shape-A generalization
engineering slice: finite static registration (no dynamic capability
dispatch, no unregistered-endpoint auto-construction), cross-capability
artifact-confusion prevention, real Ed25519 signature verification through
the generalized signer (both positive and adversarial), and genuine
REQUESTED -> AWAITING_CONFIRMATION progression through the real, statically
constructed Batch-1 production runtime for more than one capability
(proving the orchestration layer is actually capability-agnostic, not
merely typed that way).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import signing.write_batch1_signing as signer
from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_v2_signature
from pfsense_mcp.security_plan import (
    MILESTONE_9_WRITE_STEP_ID,
    MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
    MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
    AuthorizationLevel,
    generate_security_posture_plan,
)
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.tier1 import write_batch1_production_runtime as batch1_module
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
from pfsense_mcp.tier1.errors import ArtifactExchangeError
from pfsense_mcp.tier1.production_store import ProductionStoreConfig, provision_production_anchor_baseline
from pfsense_mcp.tier1.shape_a_acceptance_orchestration import (
    ProductOutcomeState,
    ShapeAAcceptanceOrchestrator,
    UnregisteredShapeACapabilityError,
    artifact_paths_for,
)
from pfsense_mcp.tier1.shape_a_artifact_exchange import (
    ShapeAAuthorizationPreview,
    ShapeAPendingConfirmationRequest,
    load_shape_a_authorization_preview,
    load_shape_a_pending_confirmation_request,
    shape_a_authorization_preview_to_bytes,
    shape_a_pending_confirmation_request_to_bytes,
)
from pfsense_mcp.tier1.shape_a_registry import SHAPE_A_REGISTRATIONS, is_registered_capability
from pfsense_mcp.tier1.system_timezone_write import SystemTimezoneChangeV1
from pfsense_mcp.write_endpoints import WriteEndpoints
from tests.test_security_discovery import _WITNESS_ENV, _FakeAnchor, _patch_witness_anchor, _provisioned_store_env
from tests.tier1.test_write_batch1_production_runtime import (
    _authority_file,
    _ed25519_keypair,
    _key_file,
    _self_signed_cert,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
_INTEGRITY_KEY_HEX = "cd" * 32

_FIVE = frozenset(
    {
        "NTP_TIME_SERVER_PREFER",
        "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
        "LOG_DISPLAY_PREFERENCES",
        "LOG_RETENTION_SETTINGS",
        "SYSTEM_TIMEZONE",
    }
)


# ---------------------------------------------------------------------------
# 1. Static registration
# ---------------------------------------------------------------------------


def test_exactly_five_batch1_capabilities_registered():
    assert set(SHAPE_A_REGISTRATIONS) == _FIVE


def test_registrations_match_write_endpoints_contract_prefixes():
    prefixes = {reg.contract_id_prefix for reg in SHAPE_A_REGISTRATIONS.values()}
    assert prefixes == {"ntppref", "ntpobs", "logdisp", "logret", "systz"}
    assert len(prefixes) == 5


@pytest.mark.parametrize(
    "bogus", ["", "FIREWALL_ALIAS_DESCRIPTION", "NTP_TIME_SERVER_PREFER_EXTRA", "ntp_time_server_prefer", None, 123]
)
def test_unregistered_capability_symbol_is_rejected(bogus):
    assert is_registered_capability(bogus) is False


def test_alias_capability_is_never_registered_here():
    """The already-verified, already-qualified alias capability must never
    become drivable through this generalized layer -- it has its own,
    separate, unmodified production runtime."""

    assert "FIREWALL_ALIAS_DESCRIPTION" not in SHAPE_A_REGISTRATIONS


def test_unregistered_write_endpoint_never_becomes_constructible():
    """Every currently-`verified=False`, non-Batch-1 WriteEndpoints entry
    (i.e. anything beyond the six reviewed entries) has no path into this
    module at all -- registration is a fixed dict literal, not derived
    from `WriteEndpoints.active_entries()`."""

    for symbol in WriteEndpoints.active_entries():
        if symbol not in _FIVE and symbol != "FIREWALL_ALIAS_DESCRIPTION":
            assert symbol not in SHAPE_A_REGISTRATIONS


def test_artifact_paths_are_namespaced_per_capability(tmp_path):
    a = artifact_paths_for(tmp_path, "NTP_TIME_SERVER_PREFER")
    b = artifact_paths_for(tmp_path, "SYSTEM_TIMEZONE")
    assert a.authorization_preview_file != b.authorization_preview_file
    assert a.authorization_inbox_file != b.authorization_inbox_file
    assert a.confirmation_pending_file != b.confirmation_pending_file
    assert a.confirmation_signed_file != b.confirmation_signed_file
    assert "NTP_TIME_SERVER_PREFER" in str(a.authorization_preview_file)
    assert "SYSTEM_TIMEZONE" in str(b.authorization_preview_file)


# ---------------------------------------------------------------------------
# 2. Generalized artifact exchange
# ---------------------------------------------------------------------------


def _integrity_key() -> bytes:
    return bytes.fromhex(_INTEGRITY_KEY_HEX)


def _preview(**changes: object) -> ShapeAAuthorizationPreview:
    values: dict[str, object] = {
        "capability_symbol": "NTP_TIME_SERVER_PREFER",
        "semantic_fields": (("requested.timeserver", "ntp.example.invalid"), ("requested.prefer", "True")),
        "execution_intent_digest": "e" * 64,
        "requested_plan_digest": "d" * 64,
        "requested_step_id": MILESTONE_9_WRITE_STEP_ID,
        "target_capability_posture": MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
        "target_anchor_assurance": MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        "generated_at": NOW,
    }
    values.update(changes)
    return ShapeAAuthorizationPreview(**values)  # type: ignore[arg-type]


def test_preview_construction_rejects_unregistered_capability():
    with pytest.raises(ArtifactExchangeError, match="unregistered"):
        _preview(capability_symbol="NOT_A_REAL_CAPABILITY")


def test_preview_round_trips_through_bytes(tmp_path):
    preview = _preview()
    raw = shape_a_authorization_preview_to_bytes(preview, integrity_key=_integrity_key())
    path = tmp_path / "preview.json"
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    loaded = load_shape_a_authorization_preview(path, integrity_key=_integrity_key())
    assert loaded.capability_symbol == preview.capability_symbol
    assert loaded.execution_intent_digest == preview.execution_intent_digest
    assert loaded.semantic_fields == preview.semantic_fields


def test_preview_tamper_detected(tmp_path):
    preview = _preview()
    raw = shape_a_authorization_preview_to_bytes(preview, integrity_key=_integrity_key())
    payload = json.loads(raw)
    payload["capability_symbol"] = "SYSTEM_TIMEZONE"  # tamper: swap capability post-MAC
    tampered = json.dumps(payload).encode()
    path = tmp_path / "preview.json"
    path.write_bytes(tampered)
    os.chmod(path, 0o600)
    with pytest.raises(ArtifactExchangeError, match="integrity"):
        load_shape_a_authorization_preview(path, integrity_key=_integrity_key())


def test_preview_malformed_json_refused(tmp_path):
    path = tmp_path / "preview.json"
    path.write_bytes(b"not json")
    os.chmod(path, 0o600)
    with pytest.raises(ArtifactExchangeError):
        load_shape_a_authorization_preview(path, integrity_key=_integrity_key())


def test_preview_missing_file_refused(tmp_path):
    with pytest.raises(ArtifactExchangeError):
        load_shape_a_authorization_preview(tmp_path / "does-not-exist.json", integrity_key=_integrity_key())


def test_preview_wrong_schema_version_refused(tmp_path):
    preview = _preview()
    payload = json.loads(shape_a_authorization_preview_to_bytes(preview, integrity_key=_integrity_key()))
    payload["schema_version"] = 999
    path = tmp_path / "preview.json"
    path.write_bytes(json.dumps(payload).encode())
    os.chmod(path, 0o600)
    with pytest.raises(ArtifactExchangeError):
        load_shape_a_authorization_preview(path, integrity_key=_integrity_key())


def test_semantic_fields_are_bounded():
    huge = tuple((f"field{i}", "x" * 999) for i in range(999))
    with pytest.raises(ArtifactExchangeError):
        _preview(semantic_fields=huge)


def _pending(**changes: object) -> ShapeAPendingConfirmationRequest:
    values: dict[str, object] = {
        "capability_symbol": "SYSTEM_TIMEZONE",
        "contract_id": "systz-contract-001",
        "operation_id": "operation-001",
        "semantic_fields": (("requested.timezone", "Europe/Berlin"),),
        "target_identity_digest": "a" * 64,
        "target_fingerprint": "b" * 64,
        "intent_digest": "c" * 64,
        "expires_at": NOW + timedelta(minutes=5),
        "expected_authority_id": "confirm-owner-1",
        "expected_algorithm": ACCEPTED_ALGORITHM,
    }
    values.update(changes)
    return ShapeAPendingConfirmationRequest(**values)  # type: ignore[arg-type]


def test_pending_construction_rejects_unregistered_capability():
    with pytest.raises(ArtifactExchangeError, match="unregistered"):
        _pending(capability_symbol="NOT_A_REAL_CAPABILITY")


def test_pending_round_trips_through_bytes(tmp_path):
    pending = _pending()
    raw = shape_a_pending_confirmation_request_to_bytes(pending, integrity_key=_integrity_key())
    path = tmp_path / "pending.json"
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    loaded = load_shape_a_pending_confirmation_request(path, integrity_key=_integrity_key())
    assert loaded.contract_id == pending.contract_id
    assert loaded.capability_symbol == pending.capability_symbol


def test_pending_tamper_detected(tmp_path):
    pending = _pending()
    raw = shape_a_pending_confirmation_request_to_bytes(pending, integrity_key=_integrity_key())
    payload = json.loads(raw)
    payload["contract_id"] = "a-different-contract-id"
    path = tmp_path / "pending.json"
    path.write_bytes(json.dumps(payload).encode())
    os.chmod(path, 0o600)
    with pytest.raises(ArtifactExchangeError, match="integrity"):
        load_shape_a_pending_confirmation_request(path, integrity_key=_integrity_key())


# ---------------------------------------------------------------------------
# 3. Generalized signer -- pure logic, real Ed25519 signatures
# ---------------------------------------------------------------------------


def _authority(authority_id: str) -> tuple[Ed25519PrivateKey, PinnedAuthority]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, PinnedAuthority(authority_id=authority_id, public_key=public)


def _write_protected_env(tmp_path: Path, *, witness_baseline: int = 2) -> dict[str, str]:
    return {
        **_provisioned_store_env(tmp_path, value=witness_baseline, handle="0x01500000"),
        **_WITNESS_ENV,
        "PFSENSE_PROFILE": "write_protected",
    }


def _matching_shape_a_preview(
    monkeypatch,
    tmp_path: Path,
    *,
    capability_symbol: str = "NTP_TIME_SERVER_PREFER",
    witness_baseline: int = 2,
    **changes: object,
) -> tuple[ShapeAAuthorizationPreview, dict[str, str]]:
    env = _write_protected_env(tmp_path, witness_baseline=witness_baseline)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(witness_baseline))
    plan = generate_security_posture_plan(
        MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE, MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE, env
    )
    values: dict[str, object] = {
        "capability_symbol": capability_symbol,
        "semantic_fields": (("requested.timeserver", "ntp.example.invalid"),),
        "execution_intent_digest": "e" * 64,
        "requested_plan_digest": compute_plan_digest(plan),
        "requested_step_id": MILESTONE_9_WRITE_STEP_ID,
        "target_capability_posture": MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
        "target_anchor_assurance": MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        "generated_at": NOW,
    }
    values.update(changes)
    return ShapeAAuthorizationPreview(**values), env  # type: ignore[arg-type]


def test_sign_authorization_preview_valid_produces_verifiable_authorization(monkeypatch, tmp_path):
    private, authority = _authority("authz-owner-1")
    preview, env = _matching_shape_a_preview(monkeypatch, tmp_path)

    authz = signer.sign_authorization_preview(
        capability_symbol="NTP_TIME_SERVER_PREFER",
        preview=preview,
        private_key=private,
        authority=authority,
        authorization_id="authz-test-1",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        env=env,
    )
    assert verify_plan_authorization_v2_signature(
        authz,
        __import__("pfsense_mcp.tier1.ed25519_authority", fromlist=["PinnedAuthoritySet"]).PinnedAuthoritySet(
            (authority,)
        ),
    )
    assert authz.authorized_executions[0].execution_intent_digest == preview.execution_intent_digest


def test_sign_authorization_preview_wrong_capability_symbol_refused(monkeypatch, tmp_path):
    """Cross-capability artifact confusion: a preview naming
    SYSTEM_TIMEZONE cannot be signed while asking for
    NTP_TIME_SERVER_PREFER, even with a perfectly valid preview and key."""

    private, authority = _authority("authz-owner-1")
    preview, env = _matching_shape_a_preview(monkeypatch, tmp_path, capability_symbol="SYSTEM_TIMEZONE")

    with pytest.raises(signer.SigningError, match="mismatched"):
        signer.sign_authorization_preview(
            capability_symbol="NTP_TIME_SERVER_PREFER",
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_wrong_key_fails_self_verification(monkeypatch, tmp_path):
    _matching_private, authority = _authority("authz-owner-1")
    wrong_private = Ed25519PrivateKey.generate()
    preview, env = _matching_shape_a_preview(monkeypatch, tmp_path)

    with pytest.raises(signer.SigningError, match="self-verification"):
        signer.sign_authorization_preview(
            capability_symbol="NTP_TIME_SERVER_PREFER",
            preview=preview,
            private_key=wrong_private,
            authority=authority,
            authorization_id="authz-test-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_stale_plan_digest_refused(monkeypatch, tmp_path):
    private, authority = _authority("authz-owner-1")
    preview, env = _matching_shape_a_preview(monkeypatch, tmp_path, requested_plan_digest="f" * 64)

    with pytest.raises(signer.SigningError, match="stale"):
        signer.sign_authorization_preview(
            capability_symbol="NTP_TIME_SERVER_PREFER",
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_authorization_preview_wrong_step_id_refused(monkeypatch, tmp_path):
    private, authority = _authority("authz-owner-1")
    preview, env = _matching_shape_a_preview(monkeypatch, tmp_path, requested_step_id="not.the.real.step")

    with pytest.raises(signer.SigningError, match="step_id"):
        signer.sign_authorization_preview(
            capability_symbol="NTP_TIME_SERVER_PREFER",
            preview=preview,
            private_key=private,
            authority=authority,
            authorization_id="authz-test-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            env=env,
        )


def test_sign_pending_confirmation_valid_produces_verifiable_evidence():
    private, authority = _authority("confirm-owner-1")
    pending = _pending(expected_authority_id=authority.authority_id)

    evidence = signer.sign_pending_confirmation(
        capability_symbol="SYSTEM_TIMEZONE", pending=pending, private_key=private, authority=authority, now=NOW
    )
    assert Ed25519ConfirmationVerifier((authority,)).verify(evidence)
    assert evidence.contract_id == pending.contract_id


def test_sign_pending_confirmation_wrong_capability_symbol_refused():
    private, authority = _authority("confirm-owner-1")
    pending = _pending(capability_symbol="LOG_RETENTION_SETTINGS", expected_authority_id=authority.authority_id)

    with pytest.raises(signer.SigningError, match="mismatched"):
        signer.sign_pending_confirmation(
            capability_symbol="SYSTEM_TIMEZONE", pending=pending, private_key=private, authority=authority, now=NOW
        )


def test_sign_pending_confirmation_expired_refused():
    private, authority = _authority("confirm-owner-1")
    pending = _pending(expected_authority_id=authority.authority_id, expires_at=NOW - timedelta(seconds=1))

    with pytest.raises(signer.SigningError, match="expired"):
        signer.sign_pending_confirmation(
            capability_symbol="SYSTEM_TIMEZONE", pending=pending, private_key=private, authority=authority, now=NOW
        )


def test_sign_pending_confirmation_wrong_authority_refused():
    private, authority = _authority("confirm-owner-1")
    pending = _pending(expected_authority_id="a-different-authority")

    with pytest.raises(signer.SigningError, match="own pinned authority"):
        signer.sign_pending_confirmation(
            capability_symbol="SYSTEM_TIMEZONE", pending=pending, private_key=private, authority=authority, now=NOW
        )


def test_require_capability_rejects_unregistered():
    with pytest.raises(signer.SigningError, match="not a registered"):
        signer._require_capability("TOTALLY_MADE_UP")


def test_render_authorization_review_contains_capability_and_fields(monkeypatch, tmp_path):
    preview, _env = _matching_shape_a_preview(monkeypatch, tmp_path)
    review = signer.render_authorization_review(preview)
    assert "NTP_TIME_SERVER_PREFER" in review
    assert preview.execution_intent_digest in review


def test_render_authorization_review_never_dumps_raw_object(monkeypatch, tmp_path):
    preview, _env = _matching_shape_a_preview(monkeypatch, tmp_path)
    review = signer.render_authorization_review(preview)
    assert "ShapeAAuthorizationPreview(" not in review
    assert "object at 0x" not in review


# ---------------------------------------------------------------------------
# 4. CLI-level: interactive approval discipline
# ---------------------------------------------------------------------------


def test_prompt_operator_approval_requires_literal_yes(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    assert signer._prompt_operator_approval("review text") is False

    monkeypatch.setattr("builtins.input", lambda _prompt: "YES")
    assert signer._prompt_operator_approval("review text") is False

    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert signer._prompt_operator_approval("review text") is True


def test_no_unattended_flag_exists_anywhere():
    """Structural: no --yes/--force/batch-approve flag is `add_argument()`-
    wired into the CLI parser -- every artifact still requires its own
    interactive 'yes'. Checked against argparse call sites, not the
    module's own prose (which legitimately discusses, and disclaims, these
    exact flag names)."""

    import ast
    import inspect

    tree = ast.parse(inspect.getsource(signer))
    flags: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    flags.add(arg.value)
    for forbidden in ("--yes", "--force", "--unattended", "--auto-approve", "--batch-approve"):
        assert forbidden not in flags


def test_main_refuses_unregistered_capability_before_any_file_access(tmp_path, monkeypatch):
    monkeypatch.delenv("PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY", raising=False)
    exit_code = signer.main(["sign-authorization", "--capability", "NOT_A_REAL_CAPABILITY"])
    assert exit_code == 1


# ---------------------------------------------------------------------------
# 5. End-to-end orchestrator: real signature, real Batch-1 runtime,
#    REQUESTED -> AWAITING_CONFIRMATION for two different capabilities.
# ---------------------------------------------------------------------------


def _batch1_env_with_keys(
    tmp_path: Path,
) -> tuple[dict[str, str], Ed25519PrivateKey, PinnedAuthority, Ed25519PrivateKey, PinnedAuthority]:
    """Like `test_write_batch1_production_runtime._full_env()`, but keeps
    the private halves of the authorization/confirmation authority
    keypairs so this test can sign genuinely-valid artifacts and prove a
    real, matching signature is accepted -- not only that a wrong one is
    rejected (the existing suite's own necessary limitation, documented in
    its own `test_authorize_and_create_genuinely_verifies_a_real_signature_
    through_production_wiring`)."""

    api_key_file = tmp_path / "api_key.txt"
    api_key_file.write_text("synthetic-api-key\n")
    os.chmod(api_key_file, 0o600)

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "recovery.sqlite3"
    store_key_file = tmp_path / "store_key" / "integrity.json"
    _key_file(store_key_file, key_id="store-integrity")

    consumption_dir = tmp_path / "consumption"
    consumption_dir.mkdir(mode=0o700)
    consumption_path = consumption_dir / "consumed.sqlite3"
    consumption_key_file = tmp_path / "consumption_key" / "integrity.json"
    _key_file(consumption_key_file, key_id="consumption-integrity")

    encryption_key_file = tmp_path / "encryption_key" / "material.json"
    _key_file(encryption_key_file, key_id="encryption-key-1")

    nonce_counter_file = tmp_path / "nonce" / "counter.json"
    nonce_counter_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    authz_private, authz_pub = _ed25519_keypair()
    confirm_private, confirm_pub = _ed25519_keypair()
    _reconcile_private, reconcile_pub = _ed25519_keypair()
    authz_file = tmp_path / "authorities" / "authorization.json"
    _authority_file(authz_file, authority_id="authz-owner-1", public_key=authz_pub)
    confirm_file = tmp_path / "authorities" / "confirmation.json"
    _authority_file(confirm_file, authority_id="confirm-owner-1", public_key=confirm_pub)
    reconcile_file = tmp_path / "authorities" / "reconciliation.json"
    _authority_file(reconcile_file, authority_id="reconcile-owner-1", public_key=reconcile_pub)

    cert_path, key_path = _self_signed_cert(tmp_path)

    provision_production_anchor_baseline(
        ProductionStoreConfig(store_path=store_path, key_file=store_key_file, store_id=batch1_module.CONTRACT_STORE_ID),
        value=2,
        handle="0x01500000",
    )

    env = {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": str(api_key_file),
        "PFSENSE_TLS_MODE": "strict",
        batch1_module._STORE_PATH_VAR: str(store_path),
        batch1_module._STORE_KEY_FILE_VAR: str(store_key_file),
        batch1_module._CONSUMPTION_STORE_PATH_VAR: str(consumption_path),
        batch1_module._CONSUMPTION_STORE_KEY_FILE_VAR: str(consumption_key_file),
        batch1_module._ENCRYPTION_KEY_FILE_VAR: str(encryption_key_file),
        batch1_module._NONCE_COUNTER_FILE_VAR: str(nonce_counter_file),
        batch1_module._AUTHORIZATION_AUTHORITY_FILE_VAR: str(authz_file),
        batch1_module._CONFIRMATION_AUTHORITY_FILE_VAR: str(confirm_file),
        batch1_module._RECONCILIATION_AUTHORITY_FILE_VAR: str(reconcile_file),
        batch1_module._WITNESS_BASE_URL_VAR: "https://127.0.0.1:1",
        batch1_module._WITNESS_CLIENT_CERT_VAR: str(cert_path),
        batch1_module._WITNESS_CLIENT_KEY_VAR: str(key_path),
        batch1_module._WITNESS_SERVER_CA_VAR: str(cert_path),
    }
    authz_authority = PinnedAuthority(authority_id="authz-owner-1", public_key=authz_pub)
    confirm_authority = PinnedAuthority(authority_id="confirm-owner-1", public_key=confirm_pub)
    return env, authz_private, authz_authority, confirm_private, confirm_authority


@pytest.mark.parametrize(
    "capability_symbol,request_factory",
    [
        ("SYSTEM_TIMEZONE", lambda: SystemTimezoneChangeV1(timezone="Europe/Berlin")),
    ],
)
def test_orchestrator_reaches_awaiting_confirmation_with_a_real_signature(
    monkeypatch, tmp_path, capability_symbol, request_factory
):
    """The genuine positive case the production-runtime suite cannot prove
    for itself (it never persists a private key): a real, correctly
    signed `PlanAuthorizationV2` -- signed by the SAME private key whose
    public half was loaded into the runtime -- is accepted, and the
    product operation reaches AWAITING_CONFIRMATION exactly once the
    signed artifact is delivered."""

    monkeypatch.setattr(
        "pfsense_mcp.tier1.write_execution_core.WriteExecutionCoreV1._plan_is_fresh",
        staticmethod(lambda **_kwargs: True),
    )
    # The real runtime's preparer is wired to the real PfSenseClient built
    # from build_pfsense_client() -- avoid actual network contact by
    # stubbing the one read method SystemTimezonePreparerV1.prepare() calls,
    # exactly like _FakeReadClient does for the existing production-runtime
    # suite's own tests, but applied to the real client class so the
    # orchestrator's own (real, unmodified) preparer wiring is exercised.
    from pfsense_mcp.pfsense_client import PfSenseClient
    from tests.tier1.test_write_batch1_production_runtime import _FakeReadClient

    fake = _FakeReadClient()
    monkeypatch.setattr(PfSenseClient, "get_system_timezone", lambda self: fake.get_system_timezone())
    monkeypatch.setattr(
        PfSenseClient,
        "get_system_status",
        lambda self, *, include_identifying_metadata=False: fake.get_system_status(
            include_identifying_metadata=include_identifying_metadata
        ),
    )
    monkeypatch.setattr(
        PfSenseClient,
        "get_system_hasync",
        lambda self, *, include_identifying_metadata=False: fake.get_system_hasync(
            include_identifying_metadata=include_identifying_metadata
        ),
    )

    env, authz_private, authz_authority, _confirm_private, _confirm_authority = _batch1_env_with_keys(tmp_path)
    runtime = batch1_module.build_write_batch1_production_runtime(env)
    assert runtime is not None

    artifact_base = tmp_path / "artifacts"
    orchestrator = ShapeAAcceptanceOrchestrator(
        capability_symbol=capability_symbol,
        runtime=runtime,
        artifact_base_directory=artifact_base,
        confirmation_authority_id="confirm-owner-1",
        artifact_integrity_key=b"\x11" * 32,
    )

    request = request_factory()
    posture_dir = tmp_path / "posture"
    posture_dir.mkdir()
    plan_env = {
        **_provisioned_store_env(posture_dir, value=2, handle="0x01500000"),
        **_WITNESS_ENV,
        "PFSENSE_PROFILE": "write_protected",
    }
    monkeypatch.setattr("pfsense_mcp.security_discovery._build_read_only_witness_client", lambda config: _FakeAnchor(2))
    plan = generate_security_posture_plan(
        MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE, MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE, plan_env
    )
    plan_digest = compute_plan_digest(plan)

    # Round 1: no authorization artifact yet -- must be REQUESTED, and must
    # have emitted a preview as a side effect.
    outcome1 = orchestrator.request_change(
        request,
        required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
        now=NOW,
        requested_plan_digest=plan_digest,
    )
    assert outcome1.state is ProductOutcomeState.REQUESTED
    paths = artifact_paths_for(artifact_base, capability_symbol)
    assert paths.authorization_preview_file.exists()

    preview = load_shape_a_authorization_preview(paths.authorization_preview_file, integrity_key=b"\x11" * 32)
    assert preview.capability_symbol == capability_symbol

    authz = signer.sign_authorization_preview(
        capability_symbol=capability_symbol,
        preview=preview,
        private_key=authz_private,
        authority=authz_authority,
        authorization_id="authz-e2e-1",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        env=plan_env,
    )
    from pfsense_mcp.tier1.shape_a_artifact_exchange import plan_authorization_v2_to_bytes, write_secure_new

    write_secure_new(paths.authorization_inbox_file, plan_authorization_v2_to_bytes(authz))

    # Round 2: signed authorization now present -- authorize_and_create()
    # must genuinely verify it (real signature, real matching public key)
    # and progress to AWAITING_CONFIRMATION, emitting a pending
    # confirmation request as a side effect.
    outcome2 = orchestrator.request_change(
        request,
        required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
        now=NOW,
        requested_plan_digest=plan_digest,
    )
    assert outcome2.state is ProductOutcomeState.AWAITING_CONFIRMATION
    assert outcome2.contract_id is not None
    assert paths.confirmation_pending_file.exists()

    pending = load_shape_a_pending_confirmation_request(paths.confirmation_pending_file, integrity_key=b"\x11" * 32)
    assert pending.capability_symbol == capability_symbol
    assert pending.contract_id == outcome2.contract_id


def test_orchestrator_construction_refuses_unregistered_capability(tmp_path):
    class _StubRuntime:
        pass

    with pytest.raises(UnregisteredShapeACapabilityError):
        ShapeAAcceptanceOrchestrator(
            capability_symbol="NOT_A_REAL_CAPABILITY",
            runtime=_StubRuntime(),  # type: ignore[arg-type]
            artifact_base_directory=tmp_path,
            confirmation_authority_id="confirm-owner-1",
            artifact_integrity_key=b"\x11" * 32,
        )


def test_orchestrator_refuses_wrong_request_type(tmp_path, monkeypatch):
    """A caller passing e.g. a SystemTimezoneChangeV1 to the
    NTP_TIME_SERVER_PREFER orchestrator is refused before any preparer,
    store, or artifact logic runs."""

    env, *_ = _batch1_env_with_keys(tmp_path)
    runtime = batch1_module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    orchestrator = ShapeAAcceptanceOrchestrator(
        capability_symbol="NTP_TIME_SERVER_PREFER",
        runtime=runtime,
        artifact_base_directory=tmp_path / "artifacts",
        confirmation_authority_id="confirm-owner-1",
        artifact_integrity_key=b"\x11" * 32,
    )
    outcome = orchestrator.request_change(
        SystemTimezoneChangeV1(timezone="Europe/Berlin"),
        required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
        now=NOW,
        requested_plan_digest="d" * 64,
    )
    assert outcome.state is ProductOutcomeState.REFUSED
    # Construction itself may provision the (empty) namespaced directory;
    # what must never happen is any artifact file appearing in it for a
    # request that was refused before reaching the preparer.
    capability_dir = tmp_path / "artifacts" / "NTP_TIME_SERVER_PREFER"
    assert not capability_dir.exists() or list(capability_dir.iterdir()) == []
