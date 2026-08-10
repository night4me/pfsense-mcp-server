from __future__ import annotations

import json
import os

import pytest

from pfsense_mcp.tier1.errors import (
    AnchorAlreadyProvisionedError,
    ContractIntegrityError,
    ContractValidationError,
    KeyMaterialError,
    Tier1ConfigurationError,
)
from pfsense_mcp.tier1.production_store import (
    PRODUCTION_STORE_ID,
    ProductionStoreConfig,
    load_production_store_config,
    open_production_store,
    provision_production_anchor_baseline,
)

_MATERIAL_HEX = "cd" * 32


def _write_key_file(path, *, key_id="integrity-0001", mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({"key_id": key_id, "epoch": 0, "material_hex": _MATERIAL_HEX}))
    os.chmod(path, mode)


def _env(tmp_path, *, store_path=None, key_file=None):
    env = {}
    if store_path is not None:
        env["PFSENSE_TIER1_STORE_PATH"] = str(store_path)
    if key_file is not None:
        env["PFSENSE_TIER1_STORE_KEY_FILE"] = str(key_file)
    return env


def test_no_configuration_returns_none_and_stays_inert():
    assert load_production_store_config({}) is None


def test_partial_configuration_path_only_is_refused(tmp_path):
    with pytest.raises(Tier1ConfigurationError, match="must be set together"):
        load_production_store_config(_env(tmp_path, store_path=tmp_path / "store" / "anchor.sqlite3"))


def test_partial_configuration_key_only_is_refused(tmp_path):
    with pytest.raises(Tier1ConfigurationError, match="must be set together"):
        load_production_store_config(_env(tmp_path, key_file=tmp_path / "key" / "integrity.json"))


def test_relative_store_path_is_refused(tmp_path):
    env = {
        "PFSENSE_TIER1_STORE_PATH": "relative/anchor.sqlite3",
        "PFSENSE_TIER1_STORE_KEY_FILE": str(tmp_path / "key" / "integrity.json"),
    }
    with pytest.raises(Tier1ConfigurationError, match="absolute"):
        load_production_store_config(env)


def test_relative_key_file_is_refused(tmp_path):
    env = {
        "PFSENSE_TIER1_STORE_PATH": str(tmp_path / "store" / "anchor.sqlite3"),
        "PFSENSE_TIER1_STORE_KEY_FILE": "relative/integrity.json",
    }
    with pytest.raises(Tier1ConfigurationError, match="absolute"):
        load_production_store_config(env)


def test_store_path_and_key_file_must_not_be_the_same_file(tmp_path):
    same = tmp_path / "shared.sqlite3"
    env = _env(tmp_path, store_path=same, key_file=same)
    with pytest.raises(Tier1ConfigurationError, match="same file"):
        load_production_store_config(env)


def test_store_path_and_key_file_must_not_share_a_parent_directory(tmp_path):
    shared_dir = tmp_path / "shared"
    env = _env(tmp_path, store_path=shared_dir / "anchor.sqlite3", key_file=shared_dir / "integrity.json")
    with pytest.raises(Tier1ConfigurationError, match="Invariant I1"):
        load_production_store_config(env)


def test_valid_configuration_is_accepted_and_deterministic(tmp_path):
    store_path = tmp_path / "store" / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"

    config = load_production_store_config(_env(tmp_path, store_path=store_path, key_file=key_file))

    assert config == ProductionStoreConfig(store_path=store_path, key_file=key_file)
    assert config.store_id == PRODUCTION_STORE_ID


def test_load_production_store_config_touches_no_filesystem_state(tmp_path):
    # Neither the store path's nor the key file's parent directories
    # exist at all -- config loading must not create or require them;
    # only open_production_store()/provision_production_anchor_baseline()
    # touch the filesystem.
    store_path = tmp_path / "does-not-exist-yet" / "anchor.sqlite3"
    key_file = tmp_path / "also-does-not-exist" / "integrity.json"

    config = load_production_store_config(_env(tmp_path, store_path=store_path, key_file=key_file))

    assert config is not None
    assert not store_path.parent.exists()
    assert not key_file.parent.exists()


def test_open_production_store_creates_the_store_on_first_open(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)

    config = ProductionStoreConfig(store_path=store_path, key_file=key_file)
    assert not store_path.exists()

    store = open_production_store(config)

    assert store_path.exists()
    assert store.anchor_provisioning_status().seeded is False


def test_open_production_store_reopens_an_existing_store(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    config = ProductionStoreConfig(store_path=store_path, key_file=key_file)

    open_production_store(config)
    reopened = open_production_store(config)

    assert reopened.anchor_provisioning_status().seeded is False


def test_open_production_store_rejects_unsafe_parent_directory(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o755)  # world/group readable -- unsafe
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    config = ProductionStoreConfig(store_path=store_dir / "anchor.sqlite3", key_file=key_file)

    with pytest.raises(ContractValidationError, match="mode 0700"):
        open_production_store(config)


def test_open_production_store_rejects_symlinked_store_path(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    real = store_dir / "real.sqlite3"
    real.touch(mode=0o600)
    link = store_dir / "anchor.sqlite3"
    link.symlink_to(real)
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    config = ProductionStoreConfig(store_path=link, key_file=key_file)

    with pytest.raises(ContractValidationError, match="non-symlink"):
        open_production_store(config)


def test_open_production_store_rejects_malformed_existing_file(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    store_path.write_bytes(b"not a sqlite database")
    os.chmod(store_path, 0o600)
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    config = ProductionStoreConfig(store_path=store_path, key_file=key_file)

    with pytest.raises(ContractIntegrityError, match="opened safely"):
        open_production_store(config)


def test_open_production_store_rejects_unsafe_key_file(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file, mode=0o644)
    config = ProductionStoreConfig(store_path=store_dir / "anchor.sqlite3", key_file=key_file)

    with pytest.raises(KeyMaterialError):
        open_production_store(config)
    assert not (store_dir / "anchor.sqlite3").exists()


def test_provision_production_anchor_baseline_seeds_and_marks_complete(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    config = ProductionStoreConfig(store_path=store_path, key_file=key_file)

    provision_production_anchor_baseline(config, value=99999, handle="0xPRODTEST")

    status = open_production_store(config).anchor_provisioning_status()
    assert status.seeded is True
    assert status.baseline == 99999
    assert status.complete is True
    assert status.handle == "0xPRODTEST"


def test_provision_production_anchor_baseline_refuses_a_second_call(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "anchor.sqlite3"
    key_file = tmp_path / "key" / "integrity.json"
    _write_key_file(key_file)
    config = ProductionStoreConfig(store_path=store_path, key_file=key_file)

    provision_production_anchor_baseline(config, value=1, handle="0xFIRST")

    with pytest.raises(AnchorAlreadyProvisionedError):
        provision_production_anchor_baseline(config, value=2, handle="0xSECOND")

    status = open_production_store(config).anchor_provisioning_status()
    assert status.baseline == 1
    assert status.handle == "0xFIRST"


def test_provisioning_cannot_accidentally_target_a_different_configured_database(tmp_path):
    store_a_dir = tmp_path / "store-a"
    store_a_dir.mkdir(mode=0o700)
    key_a = tmp_path / "key-a" / "integrity.json"
    _write_key_file(key_a)
    config_a = ProductionStoreConfig(store_path=store_a_dir / "anchor.sqlite3", key_file=key_a)

    store_b_dir = tmp_path / "store-b"
    store_b_dir.mkdir(mode=0o700)
    key_b = tmp_path / "key-b" / "integrity.json"
    _write_key_file(key_b, key_id="integrity-0002")
    config_b = ProductionStoreConfig(store_path=store_b_dir / "anchor.sqlite3", key_file=key_b)

    provision_production_anchor_baseline(config_a, value=11, handle="0xA")
    provision_production_anchor_baseline(config_b, value=22, handle="0xB")

    assert open_production_store(config_a).anchor_provisioning_status().baseline == 11
    assert open_production_store(config_b).anchor_provisioning_status().baseline == 22
