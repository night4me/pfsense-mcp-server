"""Regression tests for the 2026-09-05 export-based discovery wiring in
`write_batch1_signing.py`: `_build_discovery_from_export()` and the new
`discovery` parameter on `sign_authorization_preview()`. Together these
let the isolated Batch-1 signer independently re-derive the security
posture from a signed `AnchorEvidenceExport` instead of the runtime
`RecoveryContract` store, which it never holds a copy of.

All Ed25519 keys here are synthetic and ephemeral -- never a real
posture-evidence authority key.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_v2_signature
from pfsense_mcp.tier1.anchor_evidence_export import (
    anchor_evidence_export_to_bytes,
    build_anchor_evidence_export_payload,
    sign_anchor_evidence_export,
)
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthoritySet
from signing.write_batch1_signing import (
    SigningError,
    _build_discovery_from_export,
    sign_authorization_preview,
)

_STORE_ID = "tier1-production-anchor"
_HANDLE = "0x01500000"
_BASELINE = 4
_PROVISIONED_AT = "2026-08-10T15:10:16.416050+00:00"
# `_build_discovery_from_export()` calls `discover_anchor_assurance_from_export()`
# with `now=datetime.now(timezone.utc)` internally (real wall-clock time, not a
# fixture-controlled value) -- so the export's own validity window must be
# anchored to the real current time, not a fixed future/past timestamp, or the
# freshness check would (correctly) reject it as expired or not-yet-valid.
_ISSUED_AT = datetime.now(timezone.utc) - timedelta(seconds=1)
_EXPIRES_AT = _ISSUED_AT + timedelta(minutes=5)
_NOW = _ISSUED_AT + timedelta(seconds=2)


class _FakeAnchor:
    def __init__(self, value: int) -> None:
        self._value = value

    def read(self) -> int:
        return self._value

    def advance(self, *, expected_current: int) -> int:
        raise AssertionError("must never call advance()")


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


def _env(export_path: Path, authority_path: Path) -> dict[str, str]:
    return {
        "PFSENSE_SIGNING_ANCHOR_EVIDENCE_EXPORT_FILE": str(export_path),
        "PFSENSE_SIGNING_POSTURE_EVIDENCE_AUTHORITY_FILE": str(authority_path),
        "PFSENSE_SIGNING_EXPECTED_STORE_ID": _STORE_ID,
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": "/tmp/does-not-matter-client.crt",
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": "/tmp/does-not-matter-client.key",
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": "/tmp/does-not-matter-server.crt",
        "PFSENSE_PROFILE": "write_protected",
    }


def _patch_witness(monkeypatch: pytest.MonkeyPatch, value: int) -> None:
    import pfsense_mcp.security_discovery_export as module

    monkeypatch.setattr(module, "_build_read_only_witness_client", lambda config: _FakeAnchor(value))


def test_returns_none_when_no_vars_are_set():
    assert _build_discovery_from_export({}) is None


@pytest.mark.parametrize(
    "missing",
    [
        "PFSENSE_SIGNING_ANCHOR_EVIDENCE_EXPORT_FILE",
        "PFSENSE_SIGNING_POSTURE_EVIDENCE_AUTHORITY_FILE",
        "PFSENSE_SIGNING_EXPECTED_STORE_ID",
    ],
)
def test_raises_on_partial_configuration(tmp_path, missing):
    export_path, authority_path = _write_export_and_authority(tmp_path)
    env = _env(export_path, authority_path)
    del env[missing]
    with pytest.raises(SigningError, match="partial"):
        _build_discovery_from_export(env)


def test_builds_correct_discovery_from_a_valid_export(tmp_path, monkeypatch):
    _patch_witness(monkeypatch, _BASELINE)
    export_path, authority_path = _write_export_and_authority(tmp_path)
    env = _env(export_path, authority_path)

    discovery = _build_discovery_from_export(env)

    assert discovery is not None
    assert discovery.anchor_assurance.baseline == _BASELINE
    assert discovery.anchor_assurance.handle == _HANDLE
    assert discovery.anchor_assurance.provisioned_at == _PROVISIONED_AT
    assert discovery.anchor_assurance.witness_value == _BASELINE
    assert discovery.anchor_assurance.witness_matches_baseline is True
    assert discovery.capability_posture.value.value == "write_protected"


def test_sign_authorization_preview_with_discovery_produces_a_verifiable_authorization(tmp_path, monkeypatch):
    from pfsense_mcp.security_plan import (
        MILESTONE_9_WRITE_STEP_ID,
        MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
        generate_security_posture_plan_from_discovery,
    )
    from pfsense_mcp.security_plan_digest import compute_plan_digest
    from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
    from pfsense_mcp.tier1.shape_a_artifact_exchange import ShapeAAuthorizationPreview

    _patch_witness(monkeypatch, _BASELINE)
    export_path, authority_path = _write_export_and_authority(tmp_path)
    env = _env(export_path, authority_path)
    discovery = _build_discovery_from_export(env)
    assert discovery is not None

    plan = generate_security_posture_plan_from_discovery(
        discovery, MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE, MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE
    )
    expected_digest = compute_plan_digest(plan)

    preview = ShapeAAuthorizationPreview(
        capability_symbol="SYSTEM_TIMEZONE",
        semantic_fields=(("timezone", "Europe/Berlin"),),
        execution_intent_digest="e" * 64,
        requested_plan_digest=expected_digest,
        requested_step_id=MILESTONE_9_WRITE_STEP_ID,
        target_capability_posture=MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
        target_anchor_assurance=MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        generated_at=_NOW,
    )

    authorization_private_key = Ed25519PrivateKey.generate()
    authorization_authority = PinnedAuthority(
        authority_id="test-authorization-authority",
        public_key=authorization_private_key.public_key().public_bytes_raw(),
    )

    authz = sign_authorization_preview(
        capability_symbol="SYSTEM_TIMEZONE",
        preview=preview,
        private_key=authorization_private_key,
        authority=authorization_authority,
        authorization_id="authz-test",
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
        discovery=discovery,
    )

    assert verify_plan_authorization_v2_signature(authz, PinnedAuthoritySet((authorization_authority,))) is True


def test_sign_authorization_preview_with_discovery_rejects_a_stale_preview_digest(tmp_path, monkeypatch):
    from pfsense_mcp.security_plan import (
        MILESTONE_9_WRITE_STEP_ID,
        MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
    )
    from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
    from pfsense_mcp.tier1.shape_a_artifact_exchange import ShapeAAuthorizationPreview

    _patch_witness(monkeypatch, _BASELINE)
    export_path, authority_path = _write_export_and_authority(tmp_path)
    env = _env(export_path, authority_path)
    discovery = _build_discovery_from_export(env)
    assert discovery is not None

    preview = ShapeAAuthorizationPreview(
        capability_symbol="SYSTEM_TIMEZONE",
        semantic_fields=(("timezone", "Europe/Berlin"),),
        execution_intent_digest="e" * 64,
        requested_plan_digest="0" * 64,
        requested_step_id=MILESTONE_9_WRITE_STEP_ID,
        target_capability_posture=MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
        target_anchor_assurance=MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        generated_at=_NOW,
    )

    authorization_private_key = Ed25519PrivateKey.generate()
    authorization_authority = PinnedAuthority(
        authority_id="test-authorization-authority",
        public_key=authorization_private_key.public_key().public_bytes_raw(),
    )

    with pytest.raises(SigningError, match="stale"):
        sign_authorization_preview(
            capability_symbol="SYSTEM_TIMEZONE",
            preview=preview,
            private_key=authorization_private_key,
            authority=authorization_authority,
            authorization_id="authz-test",
            issued_at=_NOW,
            expires_at=_NOW + timedelta(minutes=5),
            discovery=discovery,
        )
