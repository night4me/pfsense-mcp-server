import os
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lab.reconciliation_authority import (
    LAB_RECONCILIATION_AUTHORITY_ID,
    LabReconciliationError,
    LabReconciliationPaths,
    PendingReconciliation,
    load_signed_evidence,
    load_verifier,
    pending_to_bytes,
    validate_pending_against_store,
)
from lab.reconciliation_owner import main, sign_existing_pending
from pfsense_mcp.tier1.reconciliation import ReconciliationOutcome
from pfsense_mcp.tier1.state_machine import RecoveryState


def _secure(path, value):
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _paths(tmp_path, public):
    tmp_path.chmod(0o700)
    paths = LabReconciliationPaths(tmp_path / "public.key", tmp_path / "pending.json", tmp_path / "signed.json")
    _secure(paths.public_key_file, public)
    return paths


def _keys():
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw_private, raw_public


def _pending(contract):
    return PendingReconciliation.from_contract(
        contract,
        issued_at=datetime.now(timezone.utc),
        verified_target_fingerprint="a" * 64,
        verified_lifecycle_locator=contract.lifecycle_locator,
    )


def test_signer_only_signs_existing_reconciliation_operation(tmp_path, contract_factory):
    private, public = _keys()
    paths = _paths(tmp_path, public)
    contract = contract_factory(state=RecoveryState.RECONCILIATION)
    pending = _pending(contract)
    _secure(paths.pending_file, pending_to_bytes(pending))
    private_path = tmp_path / "private.key"
    _secure(private_path, private)

    sign_existing_pending(
        paths=paths,
        private_key_file=private_path,
        outcome=ReconciliationOutcome.CONFIRMED_APPLIED,
        contract_loader=lambda contract_id: contract,
    )
    evidence = load_signed_evidence(paths)

    assert load_verifier(paths).verify(evidence)
    evidence.verify_bindings(
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        state_version=contract.state_version,
        lifecycle_locator=contract.lifecycle_locator,
    )


def test_non_reconciliation_operation_cannot_be_signed(tmp_path, contract_factory):
    private, public = _keys()
    paths = _paths(tmp_path, public)
    contract = contract_factory(state=RecoveryState.RECONCILIATION)
    _secure(paths.pending_file, pending_to_bytes(_pending(contract)))
    private_path = tmp_path / "private.key"
    _secure(private_path, private)
    stale = contract_factory()
    with pytest.raises(LabReconciliationError, match="persisted operation"):
        sign_existing_pending(
            paths=paths,
            private_key_file=private_path,
            outcome=ReconciliationOutcome.CONFIRMED_APPLIED,
            contract_loader=lambda contract_id: stale,
        )
    assert not paths.signed_file.exists()


@pytest.mark.parametrize("field", ["operation_id", "state_version", "lifecycle_locator"])
def test_pending_binding_tamper_fails(field, contract_factory):
    contract = contract_factory(state=RecoveryState.RECONCILIATION)
    pending = _pending(contract)
    values = pending.__dict__.copy()
    key = {"state_version": "observed_state_version", "lifecycle_locator": "verified_lifecycle_locator"}.get(
        field, field
    )
    values[key] = "other" if field == "operation_id" else 99
    with pytest.raises(LabReconciliationError, match="persisted operation"):
        validate_pending_against_store(PendingReconciliation(**values), lambda contract_id: contract)


def test_wrong_key_authority_and_tamper_fail_closed(tmp_path, contract_factory):
    private, public = _keys()
    _other_private, other_public = _keys()
    paths = _paths(tmp_path, public)
    contract = contract_factory(state=RecoveryState.RECONCILIATION)
    _secure(paths.pending_file, pending_to_bytes(_pending(contract)))
    private_path = tmp_path / "private.key"
    _secure(private_path, private)
    sign_existing_pending(
        paths=paths,
        private_key_file=private_path,
        outcome=ReconciliationOutcome.CONFIRMED_APPLIED,
        contract_loader=lambda contract_id: contract,
    )
    evidence = load_signed_evidence(paths)
    wrong_paths = LabReconciliationPaths(tmp_path / "wrong-public.key", tmp_path / "p", tmp_path / "s")
    _secure(wrong_paths.public_key_file, other_public)
    assert not load_verifier(wrong_paths).verify(evidence)
    assert not load_verifier(paths).verify(evidence.__class__(**{**evidence.__dict__, "proof": b"x" * 64}))
    with pytest.raises(LabReconciliationError, match="pinned"):
        LabReconciliationPaths(paths.public_key_file, paths.pending_file, paths.signed_file, "other")


def test_missing_or_malformed_public_key_fails(tmp_path):
    paths = LabReconciliationPaths(tmp_path / "missing", tmp_path / "pending", tmp_path / "signed")
    with pytest.raises(LabReconciliationError):
        load_verifier(paths)
    _secure(paths.public_key_file, b"short")
    with pytest.raises(LabReconciliationError, match="malformed"):
        load_verifier(paths)


def test_private_key_is_not_part_of_runner_configuration(tmp_path):
    paths = LabReconciliationPaths(tmp_path / "public", tmp_path / "pending", tmp_path / "signed")
    assert "private" not in LabReconciliationPaths.__dataclass_fields__
    assert paths.authority_id == LAB_RECONCILIATION_AUTHORITY_ID


@pytest.mark.parametrize("argument", ["--file", "--payload", "--operation-id", "--authority-id", "--private-key"])
def test_owner_command_is_not_an_arbitrary_signing_oracle(argument):
    with pytest.raises(SystemExit):
        main(["--outcome", ReconciliationOutcome.CONFIRMED_NOT_APPLIED.value, argument, "forbidden"])


def test_runner_module_never_imports_owner_private_signer():
    runner = __import__("lab.stage3_live_runtime", fromlist=["unused"])
    assert "reconciliation_owner" not in runner.__dict__
