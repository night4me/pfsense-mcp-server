"""LAB-T1-only consumption of pre-existing owner-signed reconciliation evidence."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

from .reconciliation_authority import (
    LabReconciliationError,
    LabReconciliationPaths,
    _read_secure,
    load_verifier,
    resolve_signed_evidence,
)


def _required_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise LabReconciliationError(f"required LAB-T1 reconciliation path is missing: {name}")
    return Path(value)


def main(argv: list[str] | None = None) -> int:
    """Resolve exactly the operation bound by the configured signed artifact."""

    parser = argparse.ArgumentParser(description="Resume one signed LAB-T1 reconciliation operation")
    parser.parse_args(argv)
    paths = LabReconciliationPaths(
        _required_path("PFSENSE_LAB_RECONCILIATION_PUBLIC_KEY_FILE"),
        _required_path("PFSENSE_LAB_RECONCILIATION_PENDING_FILE"),
        _required_path("PFSENSE_LAB_RECONCILIATION_SIGNED_FILE"),
    )
    integrity_key = _read_secure(_required_path("PFSENSE_LAB_RECOVERY_INTEGRITY_KEY_FILE"))
    store_id = os.environ.get("PFSENSE_LAB_RECOVERY_STORE_ID")
    if not store_id:
        raise LabReconciliationError("required LAB-T1 recovery store identifier is missing")
    store = SqliteRecoveryContractStore(
        _required_path("PFSENSE_LAB_RECOVERY_STORE_FILE"),
        integrity_key=integrity_key,
        store_id=store_id,
        reconciliation_verifier=load_verifier(paths),
    )
    resolve_signed_evidence(paths, store)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
