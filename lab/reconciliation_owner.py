"""Separate owner-only LAB-T1 reconciliation signing command."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.tier1.reconciliation import ReconciliationOutcome
from pfsense_mcp.tier1.reconciliation_providers import signing_payload
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

from .reconciliation_authority import (
    AuditLoader,
    ContractLoader,
    LabReconciliationError,
    LabReconciliationPaths,
    PendingReconciliation,
    _read_secure,
    load_pending,
    load_verifier,
    signed_to_bytes,
    validate_pending_against_store,
    write_secure_new,
)


def sign_existing_pending(
    *,
    paths: LabReconciliationPaths,
    private_key_file: Path,
    outcome: ReconciliationOutcome,
    contract_loader: ContractLoader,
    audit_loader: AuditLoader,
    integrity_key: bytes,
) -> None:
    pending: PendingReconciliation = load_pending(paths, integrity_key=integrity_key)
    validate_pending_against_store(pending, contract_loader, audit_loader)
    key_bytes = _read_secure(private_key_file)
    if len(key_bytes) != 32:
        raise LabReconciliationError("LAB-T1 reconciliation private key is malformed")
    unsigned = pending.evidence(outcome, b"placeholder")
    signature = Ed25519PrivateKey.from_private_bytes(key_bytes).sign(signing_payload(unsigned))
    evidence = pending.evidence(outcome, signature)
    if not load_verifier(paths).verify(evidence):
        raise LabReconciliationError("LAB-T1 reconciliation private key does not match the pinned authority")
    write_secure_new(paths.signed_file, signed_to_bytes(evidence))


def _required_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise LabReconciliationError(f"required LAB-T1 reconciliation path is missing: {name}")
    return Path(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign one persisted LAB-T1 reconciliation operation")
    parser.add_argument("--outcome", required=True, choices=tuple(item.value for item in ReconciliationOutcome))
    args = parser.parse_args(argv)
    paths = LabReconciliationPaths(
        _required_path("PFSENSE_LAB_RECONCILIATION_PUBLIC_KEY_FILE"),
        _required_path("PFSENSE_LAB_RECONCILIATION_PENDING_FILE"),
        _required_path("PFSENSE_LAB_RECONCILIATION_SIGNED_FILE"),
    )
    private_key_file = _required_path("PFSENSE_LAB_RECONCILIATION_PRIVATE_KEY_FILE")
    store_file = _required_path("PFSENSE_LAB_RECOVERY_STORE_FILE")
    integrity_key = _read_secure(_required_path("PFSENSE_LAB_RECOVERY_INTEGRITY_KEY_FILE"))
    store_id = os.environ.get("PFSENSE_LAB_RECOVERY_STORE_ID")
    if not store_id:
        raise LabReconciliationError("required LAB-T1 recovery store identifier is missing")
    store = SqliteRecoveryContractStore(
        store_file,
        integrity_key=integrity_key,
        store_id=store_id,
        reconciliation_verifier=load_verifier(paths),
    )
    sign_existing_pending(
        paths=paths,
        private_key_file=private_key_file,
        outcome=ReconciliationOutcome(args.outcome),
        contract_loader=store.load,
        audit_loader=store.audit_events,
        integrity_key=integrity_key,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
