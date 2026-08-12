from __future__ import annotations

import inspect
import os
import sqlite3
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lab.alias_evidence import AliasDescriptionAdapter, _confirm, _LabVerifier
from lab.harness import ScenarioSetup, prepare_contract
from lab.reconciliation_authority import LAB_RECONCILIATION_AUTHORITY_ID
from lab.stage3_deg import CANDIDATE
from lab.stage3_runtime_factory import (
    LAB_STAGE3_STORE_ID,
    LabStage3RuntimeError,
    build_fixed_lab_stage3_runtime,
)
from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
from pfsense_mcp.tier1.canonical import CanonicalValue
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.transport.base import TransportResponse
from pfsense_mcp.write_endpoints import WriteEndpoints

_INTEGRITY_KEY = b"i" * 32
_ENCRYPTION_KEY = b"e" * 32


class _OfflineTransport:
    instances: ClassVar[list[_OfflineTransport]] = []

    def __init__(self, base_url: str, api_key: str, verify: bool | str) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.verify = verify
        self.calls: list[tuple[str, str]] = []
        self.responses: list[TransportResponse] = []
        self.closed = False
        self.instances.append(self)

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self.calls.append((method, path))
        if body is not None or not self.responses:
            raise AssertionError("offline transport received an undeclared request")
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


def _secure(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_bytes(value)
    path.chmod(0o600)


def _bootstrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    store_dir = tmp_path / "store"
    key_dir = tmp_path / "keys"
    evidence_dir = tmp_path / "evidence"
    for directory in (store_dir, key_dir, evidence_dir):
        directory.mkdir(mode=0o700)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    paths = {
        "store": store_dir / "contracts.sqlite3",
        "integrity": key_dir / "integrity.key",
        "encryption": key_dir / "encryption.key",
        "api": key_dir / "api.key",
        "public": key_dir / "reconciliation-public.key",
        "pending": evidence_dir / "pending.json",
        "signed": evidence_dir / "signed.json",
        "attestation": evidence_dir / "attestation.json",
    }
    _secure(paths["integrity"], _INTEGRITY_KEY)
    _secure(paths["encryption"], _ENCRYPTION_KEY)
    _secure(paths["api"], b"offline-api-key\n")
    _secure(paths["public"], public)
    SqliteRecoveryContractStore(
        paths["store"],
        integrity_key=_INTEGRITY_KEY,
        store_id=LAB_STAGE3_STORE_ID,
        confirmation_verifier=_LabVerifier(),
    )
    env = {
        "PFSENSE_LAB_API_URL": "https://stage3-runtime.lab.invalid",
        "PFSENSE_LAB_IDENTITY": "stage3-runtime-test",
        "PFSENSE_LAB_API_KEY_FILE": str(paths["api"]),
        "PFSENSE_LAB_CANDIDATE": CANDIDATE,
        "PFSENSE_LAB_ATTESTATION_FILE": str(paths["attestation"]),
        "PFSENSE_LAB_RECOVERY_STORE_FILE": str(paths["store"]),
        "PFSENSE_LAB_RECOVERY_STORE_ID": LAB_STAGE3_STORE_ID,
        "PFSENSE_LAB_RECOVERY_INTEGRITY_KEY_FILE": str(paths["integrity"]),
        "PFSENSE_LAB_RECOVERY_ENCRYPTION_KEY_FILE": str(paths["encryption"]),
        "PFSENSE_LAB_RECONCILIATION_PUBLIC_KEY_FILE": str(paths["public"]),
        "PFSENSE_LAB_RECONCILIATION_PENDING_FILE": str(paths["pending"]),
        "PFSENSE_LAB_RECONCILIATION_SIGNED_FILE": str(paths["signed"]),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("lab.stage3_runtime_factory.HttpTransport", _OfflineTransport)
    _OfflineTransport.instances.clear()
    return paths


def _reconciliation_contract(paths: dict[str, Path]) -> str:
    store = SqliteRecoveryContractStore(
        paths["store"],
        integrity_key=_INTEGRITY_KEY,
        store_id=LAB_STAGE3_STORE_ID,
        confirmation_verifier=_LabVerifier(),
    )
    adapter = AliasDescriptionAdapter()
    raw: dict[str, CanonicalValue] = {
        "name": CANDIDATE,
        "id": 0,
        "type": "host",
        "descr": "Disposable LAB-T1 synthetic test alias",
        "address": ["192.0.2.10"],
        "detail": ["synthetic"],
    }
    snapshot = adapter.fingerprint(raw)
    assert isinstance(snapshot, dict)
    contract, _intent = prepare_contract(
        adapter=adapter,
        setup=ScenarioSetup(
            raw_target_hint=raw,
            intent_payload={"descr": "future-value"},
            snapshot_payload=snapshot,
            rollback_plan_version="firewall-alias-description-rollback-v1",
        ),
        encryption_key=_ENCRYPTION_KEY,
        contract_id="runtime-observation-contract",
        operation_id="runtime-observation-operation",
    )
    store.create(contract)
    confirmed = _confirm(store, contract)
    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    store.transition(
        contract.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )
    return contract.contract_id


def test_fixed_runtime_constructs_only_closed_internal_bundle(tmp_path, monkeypatch):
    paths = _bootstrap(tmp_path, monkeypatch)

    runtime = build_fixed_lab_stage3_runtime()

    assert runtime.store.all_contracts() == ()
    assert isinstance(runtime.adapter, AliasDescriptionAdapter)
    assert runtime.reconciliation_paths.public_key_file == paths["public"]
    assert runtime.reconciliation_paths.authority_id == LAB_RECONCILIATION_AUTHORITY_ID
    assert tuple(inspect.signature(build_fixed_lab_stage3_runtime).parameters) == ()
    assert not hasattr(runtime, "read_client")
    assert not hasattr(runtime, "write_client")
    assert not hasattr(runtime, "transport")
    assert not hasattr(runtime, "integrity_key")
    assert not hasattr(runtime, "encryption_key")
    assert not hasattr(runtime, "private_key")
    with pytest.raises(FrozenInstanceError):
        runtime._store = runtime.store
    assert _OfflineTransport.instances[0].calls == []
    assert WriteEndpoints.active_entries() == []
    assert Capability.ALIAS_WRITE not in SUPPORTED_CAPABILITIES_THIS_BUILD
    runtime.close()
    assert _OfflineTransport.instances[0].closed


def test_runtime_reconstruction_uses_fresh_process_objects_and_store(tmp_path, monkeypatch):
    _bootstrap(tmp_path, monkeypatch)
    first = build_fixed_lab_stage3_runtime()
    first_store = first.store
    first_executor = first.executor
    first_adapter = first.adapter
    first.close()

    second = build_fixed_lab_stage3_runtime()

    assert second.store is not first_store
    assert second.executor is not first_executor
    assert second.adapter is not first_adapter
    assert second._fault_proxy is not first._fault_proxy
    assert second._fault_proxy.send_attempts == first._fault_proxy.send_attempts == 0
    assert len(_OfflineTransport.instances) == 2
    assert _OfflineTransport.instances[1].calls == []
    assert second.store.all_contracts() == ()
    second.close()


def test_reconstructed_executor_observation_performs_one_fresh_get(tmp_path, monkeypatch):
    paths = _bootstrap(tmp_path, monkeypatch)
    contract_id = _reconciliation_contract(paths)
    runtime = build_fixed_lab_stage3_runtime()
    _OfflineTransport.instances[0].responses.append(
        TransportResponse(
            200,
            '{"data":[{"name":"LAB_ALIAS_TEST","id":0,"type":"host",'
            '"descr":"future-value","address":["192.0.2.10"],"detail":["synthetic"]}]}',
        )
    )
    contract_before = runtime.store.load(contract_id)
    events_before = runtime.store.audit_events(contract_id)

    observation = runtime.executor.observe_reconciliation_target(contract_id, adapter=runtime.adapter)

    assert observation.lifecycle_locator == 0
    assert observation.uncertainty_origin is RecoveryState.EXECUTING
    assert _OfflineTransport.instances[0].calls == [("GET", "/api/v2/firewall/aliases?limit=500")]
    assert runtime._fault_proxy.send_attempts == 0
    assert runtime.store.load(contract_id) == contract_before
    assert runtime.store.audit_events(contract_id) == events_before
    with sqlite3.connect(paths["store"]) as connection:
        persisted = connection.execute(
            "SELECT payload FROM contracts WHERE contract_id = ?", (contract_id,)
        ).fetchone()[0]
    assert b"ResolvedTransportTarget" not in persisted
    assert b"request" not in persisted
    runtime.close()


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("PFSENSE_LAB_RECOVERY_STORE_FILE", "path is missing"),
        ("PFSENSE_LAB_RECOVERY_INTEGRITY_KEY_FILE", "path is missing"),
        ("PFSENSE_LAB_RECOVERY_ENCRYPTION_KEY_FILE", "path is missing"),
        ("PFSENSE_LAB_RECONCILIATION_PUBLIC_KEY_FILE", "path is missing"),
    ],
)
def test_missing_bootstrap_paths_fail_closed(tmp_path, monkeypatch, name, message):
    _bootstrap(tmp_path, monkeypatch)
    monkeypatch.delenv(name)
    with pytest.raises(LabStage3RuntimeError, match=message):
        build_fixed_lab_stage3_runtime()
    assert _OfflineTransport.instances == []


@pytest.mark.parametrize("key_name", ["integrity", "encryption"])
def test_malformed_bootstrap_keys_fail_closed(tmp_path, monkeypatch, key_name):
    paths = _bootstrap(tmp_path, monkeypatch)
    _secure(paths[key_name], b"short")
    with pytest.raises(LabStage3RuntimeError, match="malformed"):
        build_fixed_lab_stage3_runtime()
    assert _OfflineTransport.instances == []


def test_missing_and_malformed_public_key_fail_closed(tmp_path, monkeypatch):
    paths = _bootstrap(tmp_path, monkeypatch)
    paths["public"].unlink()
    with pytest.raises(LabStage3RuntimeError, match="verifier"):
        build_fixed_lab_stage3_runtime()
    _secure(paths["public"], b"short")
    with pytest.raises(LabStage3RuntimeError, match="verifier"):
        build_fixed_lab_stage3_runtime()


@pytest.mark.parametrize("path_name", ["integrity", "encryption", "public", "api"])
def test_wrong_mode_and_symlink_key_substitution_fail_closed(tmp_path, monkeypatch, path_name):
    paths = _bootstrap(tmp_path, monkeypatch)
    paths[path_name].chmod(0o644)
    with pytest.raises(LabStage3RuntimeError):
        build_fixed_lab_stage3_runtime()
    paths[path_name].unlink()
    target = paths[path_name].with_suffix(".target")
    _secure(target, b"x" * 32 if path_name != "api" else b"offline-api-key")
    paths[path_name].symlink_to(target)
    with pytest.raises(LabStage3RuntimeError):
        build_fixed_lab_stage3_runtime()


def test_wrong_file_owner_policy_fails_closed(tmp_path, monkeypatch):
    _bootstrap(tmp_path, monkeypatch)
    actual_geteuid = os.geteuid
    monkeypatch.setattr("pfsense_mcp.secure_file.os.geteuid", lambda: actual_geteuid() + 1)
    with pytest.raises(LabStage3RuntimeError):
        build_fixed_lab_stage3_runtime()


def test_insecure_or_symlink_evidence_parent_fails_closed(tmp_path, monkeypatch):
    paths = _bootstrap(tmp_path, monkeypatch)
    paths["pending"].parent.chmod(0o755)
    with pytest.raises(LabStage3RuntimeError, match="parent directory is not secure"):
        build_fixed_lab_stage3_runtime()

    paths["pending"].parent.chmod(0o700)
    real_parent = tmp_path / "real-evidence"
    real_parent.mkdir(mode=0o700)
    link_parent = tmp_path / "linked-evidence"
    link_parent.symlink_to(real_parent, target_is_directory=True)
    monkeypatch.setenv("PFSENSE_LAB_RECONCILIATION_PENDING_FILE", str(link_parent / "pending.json"))
    with pytest.raises(LabStage3RuntimeError, match="parent directory is not secure"):
        build_fixed_lab_stage3_runtime()


def test_missing_blank_symlink_wrong_id_and_schema_store_fail_closed(tmp_path, monkeypatch):
    paths = _bootstrap(tmp_path, monkeypatch)
    paths["store"].unlink()
    with pytest.raises(LabStage3RuntimeError, match="already exist"):
        build_fixed_lab_stage3_runtime()

    paths["store"].touch(mode=0o600)
    with pytest.raises(LabStage3RuntimeError, match="initialized schema-v6"):
        build_fixed_lab_stage3_runtime()

    paths["store"].unlink()
    target = paths["store"].with_suffix(".target")
    target.touch(mode=0o600)
    paths["store"].symlink_to(target)
    with pytest.raises(LabStage3RuntimeError, match="non-symlink"):
        build_fixed_lab_stage3_runtime()

    paths["store"].unlink()
    SqliteRecoveryContractStore(paths["store"], integrity_key=_INTEGRITY_KEY, store_id="wrong-store-id")
    with pytest.raises(LabStage3RuntimeError, match="metadata"):
        build_fixed_lab_stage3_runtime()

    monkeypatch.setenv("PFSENSE_LAB_RECOVERY_STORE_ID", "wrong-store-id")
    with pytest.raises(LabStage3RuntimeError, match="fixed Stage 3 identity"):
        build_fixed_lab_stage3_runtime()


def test_hmac_corruption_is_refused_without_replacement(tmp_path, monkeypatch):
    paths = _bootstrap(tmp_path, monkeypatch)
    contract_id = _reconciliation_contract(paths)
    with sqlite3.connect(paths["store"]) as connection:
        connection.execute(
            "UPDATE contracts SET payload = ? WHERE contract_id = ?",
            (b"tampered", contract_id),
        )
    size_before = paths["store"].stat().st_size

    with pytest.raises(LabStage3RuntimeError, match="authenticated reconstruction"):
        build_fixed_lab_stage3_runtime()

    assert paths["store"].exists()
    assert paths["store"].stat().st_size == size_before
    assert _OfflineTransport.instances == []


def test_schema_corruption_is_refused_without_repair(tmp_path, monkeypatch):
    paths = _bootstrap(tmp_path, monkeypatch)
    with sqlite3.connect(paths["store"]) as connection:
        connection.execute("ALTER TABLE contracts ADD COLUMN injected TEXT")

    with pytest.raises(LabStage3RuntimeError, match="authenticated reconstruction"):
        build_fixed_lab_stage3_runtime()

    with sqlite3.connect(paths["store"]) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(contracts)")]
    assert "injected" in columns
    assert _OfflineTransport.instances == []


def test_factory_has_no_endpoint_fault_or_dependency_injection_surface():
    parameters = inspect.signature(build_fixed_lab_stage3_runtime).parameters
    assert parameters == {}
    module_text = Path("lab/stage3_runtime_factory.py").read_text(encoding="utf-8")
    assert "reconciliation_owner" not in module_text
    assert "PRIVATE_KEY" not in module_text
    assert ".install(" not in module_text
    assert "setattr(WriteEndpoints" not in module_text


def test_production_cannot_import_runtime_factory():
    offenders = []
    for path in Path("src/pfsense_mcp").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "stage3_runtime_factory" in text:
            offenders.append(path)
    assert offenders == []
