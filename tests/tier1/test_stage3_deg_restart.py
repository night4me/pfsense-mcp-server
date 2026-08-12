from lab.stage3_deg import OfflineRestartHarness
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.state_machine import RecoveryState


class _Verifier:
    def verify(self, evidence):
        return evidence.proof == b"valid"


def test_restart_harness_reopens_real_store_and_reconciles_executing(tmp_path, contract_factory):
    directory = tmp_path / "restart"
    directory.mkdir(mode=0o700)
    key = b"r" * 32
    harness = OfflineRestartHarness(directory / "contracts.sqlite3", key, "stage3-restart", _Verifier())
    store = harness.reconstruct_store()
    contract = contract_factory()
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    evidence = ConfirmationEvidence(
        authority_id="synthetic-owner",
        algorithm="test-verifier",
        nonce="nonce-001",
        contract_id=prepared.contract_id,
        operation_id=prepared.operation_id,
        target_identity_digest=prepared.target_identity_digest,
        target_fingerprint=prepared.target_fingerprint,
        intent_digest=prepared.intent_digest,
        expires_at=prepared.expires_at,
        issued_at=prepared.created_at,
        proof=b"valid",
    )
    confirmed = store.confirm(prepared.contract_id, evidence=evidence, expected_version=prepared.state_version)
    store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )

    fresh_store = harness.reconstruct_store()
    reconciled = fresh_store.reconcile_interrupted()

    assert [item.state for item in reconciled] == [RecoveryState.RECONCILIATION]
    assert fresh_store.load(contract.contract_id).state is RecoveryState.RECONCILIATION
