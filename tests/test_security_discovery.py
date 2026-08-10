"""Focused regression tests for `pfsense_mcp.security_discovery` --
ADR-021 Phase B's read-only capability-posture and anchor-assurance
discovery. Mirrors `tests/test_tier1_anchor_check.py`'s established
fixture style (temp store + key material + fake witness anchor via
monkeypatch) since this module reuses the exact same read-only
primitives.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from pfsense_mcp.security_discovery import (
    AnchorAssurance,
    AnchorEvidenceState,
    CapabilityPosture,
    discover_anchor_assurance,
    discover_capability_posture,
    discover_security_posture,
)
from pfsense_mcp.tier1.production_store import ProductionStoreConfig, open_production_store

_MATERIAL_HEX = "ab" * 32


def _write_key_file(path: Path, *, key_id: str = "integrity-security-discovery") -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({"key_id": key_id, "epoch": 0, "material_hex": _MATERIAL_HEX}))
    os.chmod(path, 0o600)


def _store_env(tmp_path: Path) -> dict[str, str]:
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    return {
        "PFSENSE_TIER1_STORE_PATH": str(store_path),
        "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file),
    }


def _provisioned_store_env(tmp_path: Path, *, value: int = 2, handle: str = "0x01500000") -> dict[str, str]:
    from pfsense_mcp.tier1.production_store import provision_production_anchor_baseline

    env = _store_env(tmp_path)
    config = ProductionStoreConfig(
        store_path=Path(env["PFSENSE_TIER1_STORE_PATH"]), key_file=Path(env["PFSENSE_TIER1_STORE_KEY_FILE"])
    )
    provision_production_anchor_baseline(config, value=value, handle=handle)
    return env


_WITNESS_ENV = {
    "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
    "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": "/tmp/does-not-matter-client.crt",
    "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": "/tmp/does-not-matter-client.key",
    "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": "/tmp/does-not-matter-server.crt",
}


class _FakeAnchor:
    """A read-only stand-in for TpmHostWitnessAnchor. `advance` is
    present but raises if ever called -- proof, not just an omission,
    that discovery never reaches for it."""

    def __init__(self, value: int) -> None:
        self._value = value

    def read(self) -> int:
        return self._value

    def advance(self, *, expected_current: int) -> int:
        raise AssertionError("security_discovery must never call advance() -- this is a read-only discovery tool.")


def _patch_witness_anchor(monkeypatch: pytest.MonkeyPatch, anchor: _FakeAnchor) -> None:
    import pfsense_mcp.security_discovery as module

    monkeypatch.setattr(module, "_build_read_only_witness_client", lambda config: anchor)


# ---------------------------------------------------------------------------
# 1. Default READ-only / no-anchor discovery
# ---------------------------------------------------------------------------


def test_default_environment_is_read_only_with_no_anchor(monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_TIER1_") or name == "PFSENSE_PROFILE":
            monkeypatch.delenv(name, raising=False)

    discovery = discover_security_posture({})

    assert discovery.capability_posture.value is CapabilityPosture.READ_ONLY
    assert discovery.capability_posture.configured_profile_name == "auditor"
    assert discovery.capability_posture.write_capabilities_active == 0
    assert discovery.capability_posture.allow_list_entries == ()

    assert discovery.anchor_assurance.value is AnchorAssurance.NONE
    assert discovery.anchor_assurance.evidence_state is AnchorEvidenceState.UNCONFIGURED
    assert discovery.anchor_assurance.store_configured is False


def test_capability_posture_resolves_from_evidence_not_configured_name_alone():
    """PFSENSE_PROFILE=engineer with zero active WRITE capabilities and
    an empty allow-list (this build's actual, permanent state) must
    still resolve to read_only -- the configured name is evidence, not
    the answer."""

    discovery = discover_capability_posture({"PFSENSE_PROFILE": "engineer"})

    assert discovery.value is CapabilityPosture.READ_ONLY
    assert discovery.configured_profile_name == "engineer"
    assert discovery.configured_profile_valid is True
    assert any("resolved posture is still read_only" in line for line in discovery.evidence)


def test_invalid_configured_profile_name_is_reported_not_hidden():
    discovery = discover_capability_posture({"PFSENSE_PROFILE": "not-a-real-profile"})

    assert discovery.configured_profile_valid is False
    assert any("not a recognized profile name" in line for line in discovery.evidence)
    # Still resolves a real posture value from write-capability evidence,
    # never raises just because the configured name is bad.
    assert discovery.value is CapabilityPosture.READ_ONLY


# ---------------------------------------------------------------------------
# 2. read_only + provisioned, verified hardware witness (this project's
#    own real production state) -- the combination the strict ladder
#    could not represent, per ADR-021's own revision.
# ---------------------------------------------------------------------------


def test_read_only_plus_provisioned_verified_hardware_witness(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    discovery = discover_security_posture(env)

    assert discovery.capability_posture.value is CapabilityPosture.READ_ONLY
    assert discovery.anchor_assurance.value is AnchorAssurance.HARDWARE_WITNESS
    assert discovery.anchor_assurance.evidence_state is AnchorEvidenceState.PROVISIONED_VERIFIED
    assert discovery.anchor_assurance.seeded is True
    assert discovery.anchor_assurance.complete is True
    assert discovery.anchor_assurance.handle == "0x01500000"
    assert discovery.anchor_assurance.baseline == 2
    assert discovery.anchor_assurance.witness_value == 2
    assert discovery.anchor_assurance.witness_matches_baseline is True
    # The combination itself must be representable, not a special case.
    assert (discovery.capability_posture.value, discovery.anchor_assurance.value) == (
        CapabilityPosture.READ_ONLY,
        AnchorAssurance.HARDWARE_WITNESS,
    )


def test_provisioned_store_without_witness_config_is_unverified_not_none(tmp_path):
    """Store-side evidence alone (no live witness configured) still
    justifies hardware_witness -- it must not be downgraded to none or
    unknown just because live verification was skipped."""

    env = _provisioned_store_env(tmp_path, value=2, handle="0x01500000")

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.HARDWARE_WITNESS
    assert discovery.evidence_state is AnchorEvidenceState.PROVISIONED_UNVERIFIED
    assert discovery.witness_configured is False
    assert discovery.witness_reachable is None


def test_partial_witness_config_is_distinguished_from_unconfigured(tmp_path):
    """A likely operator typo (3 of 4 witness vars set) must be
    reported as its own distinct evidence, not silently collapsed into
    the same "not configured" case as having none set at all."""

    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
        # The other three witness vars deliberately left unset.
    }

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.HARDWARE_WITNESS
    assert discovery.evidence_state is AnchorEvidenceState.PROVISIONED_UNVERIFIED
    assert discovery.witness_configured is False
    assert any("configuration is invalid" in line for line in discovery.evidence)


# ---------------------------------------------------------------------------
# 3. Unreachable hardware witness
# ---------------------------------------------------------------------------


def test_unreachable_witness_still_reports_hardware_witness_from_store_evidence(tmp_path):
    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://127.0.0.1:1",  # reserved, connection refused
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(tmp_path / "does-not-exist-client.crt"),
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(tmp_path / "does-not-exist-client.key"),
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "does-not-exist-server.crt"),
    }

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.HARDWARE_WITNESS
    assert discovery.evidence_state is AnchorEvidenceState.PROVISIONED_UNREACHABLE
    assert discovery.witness_configured is True
    assert discovery.witness_reachable is False
    assert discovery.witness_value is None
    assert any("could not be read" in line for line in discovery.evidence)


# ---------------------------------------------------------------------------
# 4. Configured but incomplete anchor state
# ---------------------------------------------------------------------------


def test_configured_but_unprovisioned_store(tmp_path):
    env = _store_env(tmp_path)  # configured, but never provisioned
    config = ProductionStoreConfig(
        store_path=Path(env["PFSENSE_TIER1_STORE_PATH"]), key_file=Path(env["PFSENSE_TIER1_STORE_KEY_FILE"])
    )
    open_production_store(config)  # creates the file/schema only, seeds nothing -- the "started but incomplete" case

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.NONE
    assert discovery.evidence_state is AnchorEvidenceState.CONFIGURED_UNPROVISIONED
    assert discovery.store_configured is True
    assert discovery.store_exists is True
    assert discovery.seeded is False
    assert discovery.complete is False


def test_configured_store_path_that_does_not_exist_yet_is_never_opened(tmp_path):
    """Critical discipline check: discovery must never call
    open_production_store() against a path that has never held a
    store, because SqliteRecoveryContractStore.__init__ would create
    it. Proven here by asserting the file still does not exist after
    discovery runs."""

    store_path = tmp_path / "store" / "anchor.sqlite3"  # parent not even created
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    env = {"PFSENSE_TIER1_STORE_PATH": str(store_path), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.NONE
    assert discovery.evidence_state is AnchorEvidenceState.CONFIGURED_NOT_CREATED
    assert discovery.store_exists is False
    assert not store_path.exists(), "discovery must never create the store file merely by looking for it"
    assert not store_path.parent.exists(), "discovery must not even create the store's parent directory"


def test_invalid_partial_store_configuration_reports_unknown_not_none():
    env = {"PFSENSE_TIER1_STORE_PATH": "/some/absolute/path"}  # key file deliberately missing

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.UNKNOWN
    assert discovery.evidence_state is AnchorEvidenceState.CONFIGURATION_INVALID


# ---------------------------------------------------------------------------
# Mismatch: security-relevant anomaly, reported not resolved
# ---------------------------------------------------------------------------


def test_witness_mismatch_is_reported_and_store_is_left_untouched(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(7))  # deliberately different from persisted baseline (2)

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.HARDWARE_WITNESS
    assert discovery.evidence_state is AnchorEvidenceState.PROVISIONED_MISMATCH
    assert discovery.witness_value == 7
    assert discovery.witness_matches_baseline is False
    assert any("does NOT match" in line for line in discovery.evidence)

    # Confirm truly read-only: re-open the store and prove the baseline
    # is still exactly what it was before discovery ran -- no
    # reconciliation, no advance(), nothing changed.
    config = ProductionStoreConfig(
        store_path=Path(env["PFSENSE_TIER1_STORE_PATH"]), key_file=Path(env["PFSENSE_TIER1_STORE_KEY_FILE"])
    )
    status = open_production_store(config).anchor_provisioning_status()
    assert status.baseline == 2
    assert status.complete is True


# ---------------------------------------------------------------------------
# 6. Proof that discovery never invokes a mutating Tier1 primitive
#    (behavioral, complementing the static AST proof in
#    test_security_discovery_isolation.py)
# ---------------------------------------------------------------------------


def test_discovery_never_calls_provision_anchor_baseline(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

    def _boom(self, *, value, handle):
        raise AssertionError("security_discovery must never call provision_anchor_baseline().")

    monkeypatch.setattr(SqliteRecoveryContractStore, "provision_anchor_baseline", _boom)

    # Must complete normally -- if discovery ever called the mutating
    # method, _boom above would raise and fail this test.
    discovery = discover_security_posture(env)
    assert discovery.anchor_assurance.value is AnchorAssurance.HARDWARE_WITNESS


def test_discovery_never_calls_advance_even_when_witness_reachable(monkeypatch, tmp_path):
    """_FakeAnchor.advance() raises AssertionError if ever called (see
    class above) -- this test's mere successful completion, returning a
    normal PROVISIONED_VERIFIED result, is the proof."""

    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    discovery = discover_anchor_assurance(env)

    assert discovery.evidence_state is AnchorEvidenceState.PROVISIONED_VERIFIED


# ---------------------------------------------------------------------------
# Determinism (grounding for the CLI's --json test, which lives in
# tests/test_security_cli.py)
# ---------------------------------------------------------------------------


def test_discovery_is_deterministic_for_identical_environment(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    first = discover_security_posture(env)
    second = discover_security_posture(env)

    assert first == second


# ---------------------------------------------------------------------------
# 7. A legacy/foreign/malformed SQLite file at the configured store path
#    must be observed as evidence (STORE_ERROR), never repaired or
#    migrated. This is the regression coverage for the pre-commit defect
#    where discover_anchor_assurance() went through open_production_store()
#    -> SqliteRecoveryContractStore.__init__() -> _initialize_schema()
#    ("CREATE TABLE IF NOT EXISTS ..."), which is capable of creating
#    missing tables in such a file as a side effect of merely looking.
#    read_only_anchor_provisioning_status() (pfsense_mcp.tier1.production_store)
#    opens the connection via SQLite's own `mode=ro` URI instead, which
#    makes the database engine itself refuse any DDL/DML.
# ---------------------------------------------------------------------------


def _foreign_sqlite_file(tmp_path: Path) -> tuple[Path, Path]:
    """A valid, pre-existing SQLite database that simply is not a Tier1
    store -- has its own unrelated table, never `anchor_state`. Models a
    legacy/foreign file an operator accidentally pointed
    PFSENSE_TIER1_STORE_PATH at."""

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    connection = sqlite3.connect(store_path)
    try:
        connection.execute("CREATE TABLE legacy_data (id INTEGER PRIMARY KEY, note TEXT)")
        connection.execute("INSERT INTO legacy_data (note) VALUES ('unrelated legacy file')")
        connection.commit()
    finally:
        connection.close()
    os.chmod(store_path, 0o600)

    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    return store_path, key_file


def _table_names(store_path: Path) -> set[str]:
    connection = sqlite3.connect(store_path)
    try:
        return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        connection.close()


def test_foreign_sqlite_file_missing_tier1_tables_is_left_byte_for_byte_unchanged(tmp_path):
    store_path, key_file = _foreign_sqlite_file(tmp_path)
    env = {"PFSENSE_TIER1_STORE_PATH": str(store_path), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}
    before_bytes = store_path.read_bytes()
    before_mtime_ns = store_path.stat().st_mtime_ns

    discovery = discover_anchor_assurance(env)

    assert discovery.evidence_state is AnchorEvidenceState.STORE_ERROR
    assert discovery.value is AnchorAssurance.UNKNOWN
    assert store_path.read_bytes() == before_bytes, "discovery must never modify an existing store file's bytes"
    assert store_path.stat().st_mtime_ns == before_mtime_ns, "discovery must never touch the store file's mtime"


def test_foreign_sqlite_file_missing_tier1_tables_gains_no_new_tables(tmp_path):
    store_path, key_file = _foreign_sqlite_file(tmp_path)
    env = {"PFSENSE_TIER1_STORE_PATH": str(store_path), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}
    before_tables = _table_names(store_path)
    assert before_tables == {"legacy_data"}

    discover_anchor_assurance(env)

    after_tables = _table_names(store_path)
    assert after_tables == before_tables, "discovery must never create anchor_state or any other table"
    assert "anchor_state" not in after_tables


def test_incomplete_anchor_state_schema_is_reported_not_repaired(tmp_path):
    """A partial/legacy anchor_state table (missing the `mac` column
    HighWaterMark/ProvisioningRecord require) must surface as STORE_ERROR,
    never silently migrated or repaired to match the current schema."""

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    connection = sqlite3.connect(store_path)
    try:
        connection.execute("CREATE TABLE anchor_state (key TEXT PRIMARY KEY, value INTEGER)")
        connection.commit()
    finally:
        connection.close()
    os.chmod(store_path, 0o600)
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    env = {"PFSENSE_TIER1_STORE_PATH": str(store_path), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}
    before_bytes = store_path.read_bytes()

    discovery = discover_anchor_assurance(env)

    assert discovery.evidence_state is AnchorEvidenceState.STORE_ERROR
    assert discovery.value is AnchorAssurance.UNKNOWN
    assert store_path.read_bytes() == before_bytes, "discovery must never repair or migrate an incomplete schema"

    connection = sqlite3.connect(store_path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(anchor_state)")}
    finally:
        connection.close()
    assert columns == {"key", "value"}, "the incomplete schema must remain exactly as it was, not gain 'mac'"


def test_healthy_provisioned_store_is_unaffected_by_the_read_only_open(tmp_path):
    """The normal, healthy case -- a fully provisioned store -- must
    still be read correctly through read_only_anchor_provisioning_status(),
    and must remain byte-for-byte unchanged (belt-and-suspenders alongside
    test_read_only_plus_provisioned_verified_hardware_witness, which
    already checks the returned values but not file immutability)."""

    env = _provisioned_store_env(tmp_path, value=2, handle="0x01500000")
    store_path = Path(env["PFSENSE_TIER1_STORE_PATH"])
    before_bytes = store_path.read_bytes()

    discovery = discover_anchor_assurance(env)

    assert discovery.value is AnchorAssurance.HARDWARE_WITNESS
    assert discovery.evidence_state is AnchorEvidenceState.PROVISIONED_UNVERIFIED
    assert discovery.seeded is True
    assert discovery.baseline == 2
    assert store_path.read_bytes() == before_bytes, "discovery must never modify a healthy store's bytes either"


# ---------------------------------------------------------------------------
# Evidence must never leak raw configured paths, URLs, or unaudited
# third-party exception text -- these strings flow directly into
# --json output, which is meant for logging/automation.
# ---------------------------------------------------------------------------


def _assert_no_path_or_url_leak(discovery, *needles: str) -> None:
    blob = " ".join(discovery.evidence)
    for needle in needles:
        assert needle not in blob, f"evidence leaked a raw configured value: {needle!r} found in {blob!r}"


def test_configured_not_created_evidence_omits_the_raw_path(tmp_path):
    store_path = tmp_path / "store" / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    env = {"PFSENSE_TIER1_STORE_PATH": str(store_path), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    discovery = discover_anchor_assurance(env)

    assert discovery.evidence_state is AnchorEvidenceState.CONFIGURED_NOT_CREATED
    _assert_no_path_or_url_leak(discovery, str(store_path), str(key_file))


def test_invalid_store_configuration_evidence_omits_the_raw_path():
    # A relative path is what actually triggers Tier1ConfigurationError's
    # "must be an absolute path (got ...)" message upstream -- exactly
    # the kind of message this module must not re-embed verbatim.
    raw_path = "relative/not/absolute"
    env = {"PFSENSE_TIER1_STORE_PATH": raw_path, "PFSENSE_TIER1_STORE_KEY_FILE": "also/relative"}

    discovery = discover_anchor_assurance(env)

    assert discovery.evidence_state is AnchorEvidenceState.CONFIGURATION_INVALID
    _assert_no_path_or_url_leak(discovery, raw_path)


def test_malformed_store_evidence_omits_the_raw_path(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed = store_dir / "anchor.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    os.chmod(malformed, 0o600)
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    env = {"PFSENSE_TIER1_STORE_PATH": str(malformed), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    discovery = discover_anchor_assurance(env)

    assert discovery.evidence_state is AnchorEvidenceState.STORE_ERROR
    _assert_no_path_or_url_leak(discovery, str(malformed), str(key_file))


def test_partial_witness_config_evidence_omits_missing_var_values(tmp_path):
    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://192.0.2.39:8443",
    }

    discovery = discover_anchor_assurance(env)

    _assert_no_path_or_url_leak(discovery, "https://192.0.2.39:8443")


def test_unreachable_witness_evidence_omits_the_raw_cert_paths(tmp_path):
    bad_cert = str(tmp_path / "does-not-exist-client.crt")
    bad_key = str(tmp_path / "does-not-exist-client.key")
    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://127.0.0.1:1",
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": bad_cert,
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": bad_key,
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "does-not-exist-server.crt"),
    }

    discovery = discover_anchor_assurance(env)

    assert discovery.evidence_state is AnchorEvidenceState.PROVISIONED_UNREACHABLE
    _assert_no_path_or_url_leak(discovery, bad_cert, bad_key, "https://127.0.0.1:1")
