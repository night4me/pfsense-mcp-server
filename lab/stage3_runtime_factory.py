"""Fixed LAB-T1 runtime reconstruction for ADR-027 Slice 2.

This module is deliberately outside the production package.  Its sole factory
has no arguments: every value comes from the fixed LAB-T1 bootstrap names and
is validated before the sealed runtime is constructed.  It does not install a
write endpoint, select a scenario/fault, or expose clients/transports/keys.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tier1.executor import MutationExecutor
from pfsense_mcp.tier1.policy import MutationPolicy, MutationRule
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.transport.http import HttpTransport
from pfsense_mcp.write_api_client import WriteApiClient

from .alias_evidence import (
    ENDPOINT_SYMBOL,
    HTTP_METHOD,
    AliasDescriptionAdapter,
    _LabVerifier,
)
from .config import LabConfigError, load_lab_config, load_lab_key_material
from .fault_proxy import FaultProxy
from .reconciliation_authority import LabReconciliationPaths, _read_secure, load_verifier
from .stage3_deg import CANDIDATE

LAB_STAGE3_STORE_ID = "lab-t1-stage3-recovery-v1"
LAB_STAGE3_STORE_SCHEMA_VERSION = 7
_STORE_FILE_VAR = "PFSENSE_LAB_RECOVERY_STORE_FILE"
_STORE_ID_VAR = "PFSENSE_LAB_RECOVERY_STORE_ID"
_INTEGRITY_KEY_FILE_VAR = "PFSENSE_LAB_RECOVERY_INTEGRITY_KEY_FILE"
_ENCRYPTION_KEY_FILE_VAR = "PFSENSE_LAB_RECOVERY_ENCRYPTION_KEY_FILE"
_PUBLIC_KEY_FILE_VAR = "PFSENSE_LAB_RECONCILIATION_PUBLIC_KEY_FILE"
_PENDING_FILE_VAR = "PFSENSE_LAB_RECONCILIATION_PENDING_FILE"
_SIGNED_FILE_VAR = "PFSENSE_LAB_RECONCILIATION_SIGNED_FILE"


class LabStage3RuntimeError(RuntimeError):
    """A fixed LAB-T1 runtime could not be reconstructed safely."""


@dataclass(frozen=True)
class _RuntimeBootstrap:
    store_file: Path
    integrity_key_file: Path
    encryption_key_file: Path
    reconciliation_paths: LabReconciliationPaths


@dataclass(frozen=True, slots=True)
class _FixedLabStage3Runtime:
    """Minimum internal bundle; mutation-capable primitives stay private."""

    _store: SqliteRecoveryContractStore
    _executor: MutationExecutor
    _adapter: AliasDescriptionAdapter
    _reconciliation_paths: LabReconciliationPaths
    _transport: HttpTransport
    _fault_proxy: FaultProxy

    @property
    def store(self) -> SqliteRecoveryContractStore:
        return self._store

    @property
    def executor(self) -> MutationExecutor:
        return self._executor

    @property
    def adapter(self) -> AliasDescriptionAdapter:
        return self._adapter

    @property
    def reconciliation_paths(self) -> LabReconciliationPaths:
        return self._reconciliation_paths

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> _FixedLabStage3Runtime:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _required_absolute_path(name: str) -> Path:
    raw = os.environ.get(name)
    if not raw:
        raise LabStage3RuntimeError(f"Required LAB-T1 runtime path is missing: {name}")
    path = Path(raw)
    if not path.is_absolute():
        raise LabStage3RuntimeError(f"Required LAB-T1 runtime path must be absolute: {name}")
    return path


def _load_bootstrap() -> _RuntimeBootstrap:
    store_id = os.environ.get(_STORE_ID_VAR)
    if store_id != LAB_STAGE3_STORE_ID:
        raise LabStage3RuntimeError("LAB-T1 recovery store identifier is not the fixed Stage 3 identity")
    paths = LabReconciliationPaths(
        _required_absolute_path(_PUBLIC_KEY_FILE_VAR),
        _required_absolute_path(_PENDING_FILE_VAR),
        _required_absolute_path(_SIGNED_FILE_VAR),
    )
    bootstrap = _RuntimeBootstrap(
        _required_absolute_path(_STORE_FILE_VAR),
        _required_absolute_path(_INTEGRITY_KEY_FILE_VAR),
        _required_absolute_path(_ENCRYPTION_KEY_FILE_VAR),
        paths,
    )
    all_paths = {
        bootstrap.store_file,
        bootstrap.integrity_key_file,
        bootstrap.encryption_key_file,
        paths.public_key_file,
        paths.pending_file,
        paths.signed_file,
    }
    if len(all_paths) != 6:
        raise LabStage3RuntimeError("LAB-T1 runtime paths must be distinct")
    if bootstrap.store_file.parent in {
        bootstrap.integrity_key_file.parent,
        bootstrap.encryption_key_file.parent,
    }:
        raise LabStage3RuntimeError("LAB-T1 recovery store and keys must not share a parent directory")
    _require_secure_parent(paths.pending_file)
    _require_secure_parent(paths.signed_file)
    return bootstrap


def _require_secure_parent(path: Path) -> None:
    try:
        metadata = path.parent.lstat()
    except OSError:
        raise LabStage3RuntimeError("LAB-T1 evidence parent directory does not exist") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise LabStage3RuntimeError("LAB-T1 evidence parent directory is not secure")


def _require_existing_store(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise LabStage3RuntimeError("LAB-T1 recovery store must already exist") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LabStage3RuntimeError("LAB-T1 recovery store must be a regular non-symlink file")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        try:
            metadata_values = dict(connection.execute("SELECT key, value FROM metadata"))
        finally:
            connection.close()
    except sqlite3.Error:
        raise LabStage3RuntimeError("LAB-T1 recovery store is not an initialized schema-v7 store") from None
    if metadata_values != {
        "schema_version": str(LAB_STAGE3_STORE_SCHEMA_VERSION),
        "store_id": LAB_STAGE3_STORE_ID,
    }:
        raise LabStage3RuntimeError("LAB-T1 recovery store metadata does not match the fixed runtime")


def _load_exact_key(path: Path, *, label: str) -> bytes:
    try:
        value = _read_secure(path)
    except Exception:
        raise LabStage3RuntimeError(f"LAB-T1 {label} could not be loaded securely") from None
    if len(value) != 32:
        raise LabStage3RuntimeError(f"LAB-T1 {label} is malformed")
    return value


def build_fixed_lab_stage3_runtime() -> _FixedLabStage3Runtime:
    """Reconstruct the one fixed sealed LAB runtime; accepts no inputs."""

    try:
        config = load_lab_config()
    except LabConfigError:
        raise LabStage3RuntimeError("Fixed LAB-T1 base configuration is invalid") from None
    if config.candidate != CANDIDATE:
        raise LabStage3RuntimeError("Fixed LAB-T1 candidate does not match the closed Stage 3 registry")

    bootstrap = _load_bootstrap()
    _require_existing_store(bootstrap.store_file)
    integrity_key = _load_exact_key(bootstrap.integrity_key_file, label="recovery integrity key")
    encryption_key = _load_exact_key(bootstrap.encryption_key_file, label="recovery encryption key")
    try:
        verifier = load_verifier(bootstrap.reconciliation_paths)
        api_key = load_lab_key_material(config.key_file)
    except Exception:
        raise LabStage3RuntimeError("Fixed LAB-T1 verifier or API credential configuration is invalid") from None

    try:
        store = SqliteRecoveryContractStore(
            bootstrap.store_file,
            integrity_key=integrity_key,
            store_id=LAB_STAGE3_STORE_ID,
            confirmation_verifier=_LabVerifier(),
            reconciliation_verifier=verifier,
        )
        # Construction verifies schema/metadata.  Reading every protected
        # record additionally proves HMAC/audit integrity before any runtime
        # object is returned; corruption never becomes an empty replacement.
        store.all_contracts()
    except Exception:
        raise LabStage3RuntimeError("LAB-T1 recovery store failed authenticated reconstruction") from None

    transport = HttpTransport(config.base_url, api_key, verify=True)
    try:
        fault_proxy = FaultProxy(transport)
        read_client = PfSenseClient(RestApiClient(transport, identity=config.identity, api_version=ApiVersion.V2))
        write_client = WriteApiClient(fault_proxy, identity=config.identity, api_version=ApiVersion.V2)
        executor = MutationExecutor(
            store=store,
            write_client=write_client,
            read_client=read_client,
            policy=MutationPolicy(
                frozenset(
                    {
                        MutationRule(
                            Capability.ALIAS_WRITE,
                            ENDPOINT_SYMBOL,
                            HTTP_METHOD,
                        )
                    }
                )
            ),
            anti_rollback_anchor=None,
            encryption_key=encryption_key,
        )
    except Exception:
        transport.close()
        raise LabStage3RuntimeError("Fixed LAB-T1 sealed runtime construction failed") from None
    return _FixedLabStage3Runtime(
        _store=store,
        _executor=executor,
        _adapter=AliasDescriptionAdapter(),
        _reconciliation_paths=bootstrap.reconciliation_paths,
        _transport=transport,
        _fault_proxy=fault_proxy,
    )
