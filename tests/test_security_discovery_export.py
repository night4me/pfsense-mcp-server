"""Focused regression tests for `pfsense_mcp.security_discovery_export`
-- the off-runtime anchor-assurance discovery path an isolated verifier
(the Batch-1 signer) uses instead of opening the runtime RecoveryContract
store. Mirrors `tests/test_security_discovery.py`'s fixture style (a
fake read-only witness anchor via monkeypatch) since this module reuses
the exact same live-witness-read discipline against a different
evidence source.

All Ed25519 keys used here are synthetic and ephemeral, generated fresh
per test -- never a real posture-evidence authority key, which this
change does not create or provision anywhere (see `tier1/
anchor_evidence_export.py`'s own module docstring).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.security_discovery_export import discover_anchor_assurance_from_export
from pfsense_mcp.security_posture_types import AnchorAssurance, AnchorEvidenceState
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
    """A read-only stand-in for `TpmHostWitnessAnchor`. `advance` is
    present but raises if ever called -- proof, not just an omission,
    that this discovery path never reaches for it."""

    def __init__(self, value: int) -> None:
        self._value = value

    def read(self) -> int:
        return self._value

    def advance(self, *, expected_current: int) -> int:
        raise AssertionError(
            "security_discovery_export must never call advance() -- this is a read-only discovery tool."
        )


def _patch_witness_anchor(monkeypatch: pytest.MonkeyPatch, anchor: _FakeAnchor) -> None:
    import pfsense_mcp.security_discovery_export as module

    monkeypatch.setattr(module, "_build_read_only_witness_client", lambda config: anchor)


def _authority() -> tuple[PinnedAuthoritySet, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    authority = PinnedAuthority(authority_id="test-authority", public_key=public_key, active=True)
    return PinnedAuthoritySet((authority,)), private_key


def _signed_export(
    private_key: Ed25519PrivateKey,
    *,
    authority_id: str = "test-authority",
    store_id: str = _STORE_ID,
    handle: str = _HANDLE,
    baseline: int = _BASELINE,
    provisioned_at: str = _PROVISIONED_AT,
    issued_at: datetime = _ISSUED_AT,
    expires_at: datetime = _EXPIRES_AT,
):
    payload = build_anchor_evidence_export_payload(
        store_id=store_id,
        handle=handle,
        baseline=baseline,
        provisioned_at=provisioned_at,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return sign_anchor_evidence_export(payload, authority_id=authority_id, private_key=private_key)


# ---------------------------------------------------------------------------
# 1. Happy path: verified signature, matching store_id, fresh, witness matches
# ---------------------------------------------------------------------------


def test_verified_export_with_matching_witness_reports_provisioned_verified(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.HARDWARE_WITNESS
    assert result.evidence_state is AnchorEvidenceState.PROVISIONED_VERIFIED
    assert result.baseline == _BASELINE
    assert result.provisioned_at == _PROVISIONED_AT
    assert result.handle == _HANDLE
    assert result.witness_value == _BASELINE
    assert result.witness_matches_baseline is True


# ---------------------------------------------------------------------------
# 2. Signature failures -- fail closed to UNKNOWN/STORE_ERROR, never trusted
# ---------------------------------------------------------------------------


def test_wrong_authority_key_is_rejected(monkeypatch):
    authorities, _ = _authority()
    _, other_private_key = _authority()
    export = _signed_export(other_private_key)  # signed by a key not in `authorities`
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.UNKNOWN
    assert result.evidence_state is AnchorEvidenceState.STORE_ERROR


def test_unknown_authority_id_is_rejected(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key, authority_id="not-pinned-authority")
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.UNKNOWN
    assert result.evidence_state is AnchorEvidenceState.STORE_ERROR


def test_inactive_authority_is_rejected(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    authorities = PinnedAuthoritySet(
        (PinnedAuthority(authority_id="test-authority", public_key=public_key, active=False),)
    )
    export = _signed_export(private_key)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.UNKNOWN
    assert result.evidence_state is AnchorEvidenceState.STORE_ERROR


def test_tampered_baseline_after_signing_is_rejected(monkeypatch):
    """A byte-level tamper of a signed field must invalidate the
    signature -- proof the signature actually covers the payload
    content, not merely accompanies it."""

    authorities, private_key = _authority()
    export = _signed_export(private_key)
    tampered = type(export)(
        schema_version=export.schema_version,
        store_id=export.store_id,
        handle=export.handle,
        baseline=export.baseline + 1,
        provisioned_at=export.provisioned_at,
        issued_at=export.issued_at,
        expires_at=export.expires_at,
        authority_id=export.authority_id,
        proof=export.proof,
    )
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        tampered, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.UNKNOWN
    assert result.evidence_state is AnchorEvidenceState.STORE_ERROR


# ---------------------------------------------------------------------------
# 3. Identity/freshness failures -- never trusted regardless of a valid signature
# ---------------------------------------------------------------------------


def test_wrong_store_id_is_rejected_even_with_a_valid_signature(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key, store_id="some-other-store")
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.UNKNOWN
    assert result.evidence_state is AnchorEvidenceState.CONFIGURATION_INVALID


def test_expired_export_is_rejected(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_EXPIRES_AT, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.UNKNOWN
    assert result.evidence_state is AnchorEvidenceState.CONFIGURATION_INVALID


def test_future_issued_export_is_rejected(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    result = discover_anchor_assurance_from_export(
        export,
        authorities=authorities,
        expected_store_id=_STORE_ID,
        now=_ISSUED_AT - timedelta(seconds=1),
        env=_WITNESS_ENV,
    )

    assert result.value is AnchorAssurance.UNKNOWN
    assert result.evidence_state is AnchorEvidenceState.CONFIGURATION_INVALID


def test_bounded_validity_window_is_enforced_at_the_boundary(monkeypatch):
    """`now == expires_at` is already expired (half-open interval), and
    `now == issued_at` is already valid -- proof the boundary itself is
    exercised, not just comfortably-inside/outside values."""

    authorities, private_key = _authority()
    export = _signed_export(private_key)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    at_issue = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_ISSUED_AT, env=_WITNESS_ENV
    )
    assert at_issue.evidence_state is AnchorEvidenceState.PROVISIONED_VERIFIED

    at_expiry = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_EXPIRES_AT, env=_WITNESS_ENV
    )
    assert at_expiry.evidence_state is AnchorEvidenceState.CONFIGURATION_INVALID


# ---------------------------------------------------------------------------
# 4. Live witness read outcomes
# ---------------------------------------------------------------------------


def test_witness_not_configured_is_provisioned_unverified(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env={}
    )

    assert result.value is AnchorAssurance.HARDWARE_WITNESS
    assert result.evidence_state is AnchorEvidenceState.PROVISIONED_UNVERIFIED
    assert result.baseline == _BASELINE


def test_witness_value_mismatch_is_reported_not_reconciled(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE + 1))

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.HARDWARE_WITNESS
    assert result.evidence_state is AnchorEvidenceState.PROVISIONED_MISMATCH
    assert result.witness_value == _BASELINE + 1
    assert result.witness_matches_baseline is False
    assert result.baseline == _BASELINE  # export's authenticated baseline is preserved, not overwritten


def test_unreachable_witness_still_reports_hardware_witness_from_export_evidence(monkeypatch):
    import pfsense_mcp.security_discovery_export as module

    # Deliberately raises `module.AnchorUnavailableError` -- the exact class
    # object this production module's own `except` clause is bound to --
    # rather than a separately, freshly imported reference. A handful of
    # unrelated pre-existing isolation tests elsewhere in this suite purge
    # `sys.modules` entries under `pfsense_mcp.tier1`, which can leave two
    # non-identical copies of the same exception class alive in one process;
    # asking the production module for its own bound name avoids ever
    # constructing the "wrong" copy, regardless of what else already ran
    # earlier in the same pytest session.
    def _raise(_config: object) -> None:
        raise module.AnchorUnavailableError("simulated witness outage")  # type: ignore[attr-defined]

    authorities, private_key = _authority()
    export = _signed_export(private_key)
    monkeypatch.setattr(module, "_build_read_only_witness_client", _raise)

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert result.value is AnchorAssurance.HARDWARE_WITNESS
    assert result.evidence_state is AnchorEvidenceState.PROVISIONED_UNREACHABLE
    assert result.witness_reachable is False


def test_partial_witness_config_is_reported_not_silently_ignored(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)
    partial_env = {"PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443"}

    result = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=partial_env
    )

    assert result.value is AnchorAssurance.HARDWARE_WITNESS
    assert result.evidence_state is AnchorEvidenceState.PROVISIONED_UNVERIFIED


def test_never_calls_advance_even_when_witness_reachable(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)
    anchor = _FakeAnchor(_BASELINE)
    _patch_witness_anchor(monkeypatch, anchor)

    discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )
    # `_FakeAnchor.advance` raises `AssertionError` if ever called; reaching
    # this line without one having been raised is itself the proof.


# ---------------------------------------------------------------------------
# 5. Determinism / no I/O
# ---------------------------------------------------------------------------


def test_discovery_is_deterministic_for_identical_export_and_environment(monkeypatch):
    authorities, private_key = _authority()
    export = _signed_export(private_key)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(_BASELINE))

    first = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )
    second = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=_STORE_ID, now=_NOW, env=_WITNESS_ENV
    )

    assert first == second
