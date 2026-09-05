"""Regression tests proving `generate_security_posture_plan_from_
discovery()` (`security_plan.py`, 2026-09-05 ADR-021/022 amendment)
delegates to the exact same pure computation as `generate_security_
posture_plan()` -- the core guarantee behind the isolated Batch-1
signer's off-runtime `AnchorEvidenceExport` verification path: given
digest-relevant-equivalent evidence, `compute_plan_digest()` is
byte-identical regardless of whether that evidence came from the live
runtime store (`discover_anchor_assurance()`) or an authenticated
export (`discover_anchor_assurance_from_export()`). No second digest
algorithm, no signer-specific plan schema -- both paths feed the exact
same `SecurityPostureDiscovery` shape into the exact same
`_build_plan_from_discovery()`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.security_discovery_export import discover_anchor_assurance_from_export
from pfsense_mcp.security_plan import generate_security_posture_plan_from_discovery
from pfsense_mcp.security_plan_digest import compute_plan_digest, evidence_fingerprint_payload
from pfsense_mcp.security_posture_types import (
    AnchorAssurance,
    CapabilityPosture,
    CapabilityPostureDiscovery,
    SecurityPostureDiscovery,
)
from pfsense_mcp.tier1.anchor_evidence_export import build_anchor_evidence_export_payload, sign_anchor_evidence_export
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet

_STORE_ID = "tier1-production-write-batch1-store"
_HANDLE = "0x01500000"
_BASELINE = 4
_PROVISIONED_AT = "2026-08-10T15:10:16.416050+00:00"
_ISSUED_AT = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
_EXPIRES_AT = _ISSUED_AT + timedelta(minutes=5)
_NOW = _ISSUED_AT + timedelta(minutes=1)

_WITNESS_ENV = {
    "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
    "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": "/tmp/does-not-matter-client.crt",
    "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": "/tmp/does-not-matter-client.key",
    "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": "/tmp/does-not-matter-server.crt",
}


class _FakeAnchor:
    def __init__(self, value: int) -> None:
        self._value = value

    def read(self) -> int:
        return self._value

    def advance(self, *, expected_current: int) -> int:
        raise AssertionError("must never call advance()")


def _capability_posture() -> CapabilityPostureDiscovery:
    return CapabilityPostureDiscovery(
        value=CapabilityPosture.WRITE_PROTECTED,
        configured_profile_name="production-write-batch1",
        configured_profile_valid=True,
        write_capabilities_active=1,
        write_capabilities_total=6,
        allow_list_entries=("LOG_DISPLAY_PREFERENCES",),
        evidence=("some prose that is never digest-relevant",),
    )


def _export_backed_anchor_discovery(monkeypatch: pytest.MonkeyPatch, *, provisioned_at: str = _PROVISIONED_AT):
    import pfsense_mcp.security_discovery_export as module

    monkeypatch.setattr(module, "_build_read_only_witness_client", lambda config: _FakeAnchor(_BASELINE))

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="test-authority", public_key=public_key),))
    payload = build_anchor_evidence_export_payload(
        store_id=_STORE_ID,
        handle=_HANDLE,
        baseline=_BASELINE,
        provisioned_at=provisioned_at,
        issued_at=_ISSUED_AT,
        expires_at=_EXPIRES_AT,
    )
    export = sign_anchor_evidence_export(payload, authority_id="test-authority", private_key=private_key)
    return discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )


def _store_backed_anchor_discovery(tmp_path, monkeypatch: pytest.MonkeyPatch):
    import json
    import os
    from pathlib import Path

    import pfsense_mcp.security_discovery as discovery_module
    from pfsense_mcp.security_discovery import discover_anchor_assurance
    from pfsense_mcp.tier1.production_store import ProductionStoreConfig, provision_production_anchor_baseline

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    key_dir = tmp_path / "key"
    key_dir.mkdir(mode=0o700)
    key_file = key_dir / "integrity.json"
    key_file.write_text(json.dumps({"key_id": "integrity-test", "epoch": 0, "material_hex": "ab" * 32}))
    os.chmod(key_file, 0o600)

    config = ProductionStoreConfig(store_path=Path(store_path), key_file=Path(key_file))
    provision_production_anchor_baseline(config, value=_BASELINE, handle=_HANDLE)

    monkeypatch.setattr(discovery_module, "_build_read_only_witness_client", lambda config: _FakeAnchor(_BASELINE))
    env = {"PFSENSE_TIER1_STORE_PATH": str(store_path), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file), **_WITNESS_ENV}
    return discover_anchor_assurance(env)


def test_store_backed_and_export_backed_anchor_evidence_agree_on_digest_relevant_fields(tmp_path, monkeypatch):
    store_anchor = _store_backed_anchor_discovery(tmp_path, monkeypatch)
    export_anchor = _export_backed_anchor_discovery(monkeypatch, provisioned_at=store_anchor.provisioned_at)

    assert export_anchor.value == store_anchor.value
    assert export_anchor.evidence_state == store_anchor.evidence_state
    assert export_anchor.baseline == store_anchor.baseline
    assert export_anchor.witness_value == store_anchor.witness_value
    assert export_anchor.provisioned_at == store_anchor.provisioned_at
    # Prose evidence is allowed -- expected -- to differ between the two
    # sources; it is deliberately excluded from the digest fingerprint.
    assert export_anchor.evidence != store_anchor.evidence


def test_equivalent_evidence_produces_byte_identical_evidence_fingerprint(tmp_path, monkeypatch):
    capability = _capability_posture()
    store_anchor = _store_backed_anchor_discovery(tmp_path, monkeypatch)
    store_current = SecurityPostureDiscovery(capability_posture=capability, anchor_assurance=store_anchor)
    export_current = SecurityPostureDiscovery(
        capability_posture=capability,
        anchor_assurance=_export_backed_anchor_discovery(monkeypatch, provisioned_at=store_anchor.provisioned_at),
    )

    store_plan = generate_security_posture_plan_from_discovery(
        store_current, CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS
    )
    export_plan = generate_security_posture_plan_from_discovery(
        export_current, CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS
    )

    assert evidence_fingerprint_payload(store_plan) == evidence_fingerprint_payload(export_plan)


def test_equivalent_evidence_produces_byte_identical_plan_digest(tmp_path, monkeypatch):
    capability = _capability_posture()
    store_anchor = _store_backed_anchor_discovery(tmp_path, monkeypatch)
    store_current = SecurityPostureDiscovery(capability_posture=capability, anchor_assurance=store_anchor)
    export_current = SecurityPostureDiscovery(
        capability_posture=capability,
        anchor_assurance=_export_backed_anchor_discovery(monkeypatch, provisioned_at=store_anchor.provisioned_at),
    )

    store_plan = generate_security_posture_plan_from_discovery(
        store_current, CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS
    )
    export_plan = generate_security_posture_plan_from_discovery(
        export_current, CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS
    )

    assert compute_plan_digest(store_plan) == compute_plan_digest(export_plan)


def test_generate_from_discovery_rejects_unknown_target_exactly_like_the_live_path():
    capability = _capability_posture()
    from pfsense_mcp.security_posture_types import AnchorAssuranceDiscovery, AnchorEvidenceState

    current = SecurityPostureDiscovery(
        capability_posture=capability,
        anchor_assurance=AnchorAssuranceDiscovery(
            value=AnchorAssurance.NONE,
            evidence_state=AnchorEvidenceState.UNCONFIGURED,
            store_configured=False,
            store_exists=None,
            seeded=None,
            complete=None,
            handle=None,
            baseline=None,
            provisioned_at=None,
            witness_configured=False,
            witness_reachable=None,
            witness_value=None,
            witness_matches_baseline=None,
        ),
    )

    with pytest.raises(ValueError, match="not a valid plan target"):
        generate_security_posture_plan_from_discovery(current, CapabilityPosture.READ_ONLY, AnchorAssurance.UNKNOWN)
