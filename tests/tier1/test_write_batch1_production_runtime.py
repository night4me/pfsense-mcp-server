"""Regression and adversarial tests for
`pfsense_mcp.tier1.write_batch1_production_runtime` -- the ADR-037 Batch 1
acceptance-path production wiring for the five new capabilities. No live
pfSense call, no LAB mutation, no WriteEndpoints population beyond what
ADR-037 Batch 1 already authorized, no capability activation anywhere in
this module. Mirrors `tests/tier1/test_production_runtime.py`'s fixture
pattern (synthetic Ed25519 authorities, a synthetic mTLS witness-client
config, a real anchor-provisioning record seeded via
`provision_production_anchor_baseline`) -- construction succeeds fully
offline because neither `build_pfsense_client()`/`build_write_client()`
nor `TpmHostWitnessAnchor`'s own construction makes any network call;
only an actual `MutationExecutor.execute()` send would, and this file
never reaches that call (see "Real primitives, not stubs" section below
for why that's still meaningful).
"""

from __future__ import annotations

import ast
import datetime
import ipaddress
import json
import os
from dataclasses import fields
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.profiles import AuditorProfile, EngineerProfile
from pfsense_mcp.security_authorization import (
    PlanAuthorizationStepBinding,
    build_plan_authorization_v2_payload,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1 import write_batch1_production_runtime as module
from pfsense_mcp.tier1.errors import AcceptanceError, BoundExecutionError, Tier1ConfigurationError
from pfsense_mcp.tier1.executor import MutationExecutor
from pfsense_mcp.tier1.prepared_execution_intent import compute_execution_intent_digest
from pfsense_mcp.tier1.production_store import (
    PRODUCTION_STORE_ID as ALIAS_CONTRACT_STORE_ID,
)
from pfsense_mcp.tier1.production_store import (
    ProductionStoreConfig,
    open_production_store,
    provision_production_anchor_baseline,
)
from pfsense_mcp.tier1.system_timezone_write import SystemTimezoneChangeV1
from pfsense_mcp.tier1.write_execution_core import WriteExecutionCoreV1
from pfsense_mcp.tls import TLSMode
from pfsense_mcp.write_endpoints import WriteEndpoints
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

ROOT = Path(__file__).parents[2]
LAB_ROOT = ROOT / "lab"

NOW = datetime.datetime.now(datetime.timezone.utc)

_FIVE_ENDPOINT_SYMBOLS = frozenset(
    {
        "NTP_TIME_SERVER_PREFER",
        "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
        "LOG_DISPLAY_PREFERENCES",
        "LOG_RETENTION_SETTINGS",
        "SYSTEM_TIMEZONE",
    }
)

_LAB_URL = "https://pfsense-test.lab.invalid"
_LAB_IDENTITY = "pfsense_lab1"


def _key_file(path: Path, *, key_id: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({"key_id": key_id, "epoch": 0, "material_hex": "ab" * 32}))
    os.chmod(path, 0o600)


def _authority_file(path: Path, *, authority_id: str, public_key: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({"authority_id": authority_id, "public_key_hex": public_key.hex()}))
    os.chmod(path, 0o600)


def _ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes


def _self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "witness.crt"
    key_path = tmp_path / "witness.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _full_env(tmp_path: Path, *, api_key: str | None = None) -> dict[str, str]:
    """Mirrors `test_production_runtime.py::_full_env()` exactly, adapted
    to this module's own dedicated store/consumption-store/encryption-key/
    nonce-counter env vars (see write_batch1_production_runtime.py's own
    docstring for why those are dedicated rather than shared with
    production_runtime.py's alias-specific ones) while reusing the same
    variable NAMES for the three pinned authorities and the witness
    client (deliberately shared, same physical owner/witness identity)."""

    api_key_file = tmp_path / "api_key.txt"
    api_key_file.write_text((api_key or "synthetic-api-key") + "\n")
    os.chmod(api_key_file, 0o600)

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_path = store_dir / "recovery.sqlite3"
    store_key_file = tmp_path / "store_key" / "integrity.json"
    _key_file(store_key_file, key_id="store-integrity")

    consumption_dir = tmp_path / "consumption"
    consumption_dir.mkdir(mode=0o700)
    consumption_path = consumption_dir / "consumed.sqlite3"
    consumption_key_file = tmp_path / "consumption_key" / "integrity.json"
    _key_file(consumption_key_file, key_id="consumption-integrity")

    encryption_key_file = tmp_path / "encryption_key" / "material.json"
    _key_file(encryption_key_file, key_id="encryption-key-1")

    nonce_counter_file = tmp_path / "nonce" / "counter.json"
    nonce_counter_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    _, authz_pub = _ed25519_keypair()
    _, confirm_pub = _ed25519_keypair()
    _, reconcile_pub = _ed25519_keypair()
    authz_file = tmp_path / "authorities" / "authorization.json"
    _authority_file(authz_file, authority_id="authz-owner-1", public_key=authz_pub)
    confirm_file = tmp_path / "authorities" / "confirmation.json"
    _authority_file(confirm_file, authority_id="confirm-owner-1", public_key=confirm_pub)
    reconcile_file = tmp_path / "authorities" / "reconciliation.json"
    _authority_file(reconcile_file, authority_id="reconcile-owner-1", public_key=reconcile_pub)

    cert_path, key_path = _self_signed_cert(tmp_path)

    provision_production_anchor_baseline(
        ProductionStoreConfig(store_path=store_path, key_file=store_key_file, store_id=module.CONTRACT_STORE_ID),
        value=2,
        handle="0x01500000",
    )

    return {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": str(api_key_file),
        "PFSENSE_TLS_MODE": "strict",
        module._STORE_PATH_VAR: str(store_path),
        module._STORE_KEY_FILE_VAR: str(store_key_file),
        module._CONSUMPTION_STORE_PATH_VAR: str(consumption_path),
        module._CONSUMPTION_STORE_KEY_FILE_VAR: str(consumption_key_file),
        module._ENCRYPTION_KEY_FILE_VAR: str(encryption_key_file),
        module._NONCE_COUNTER_FILE_VAR: str(nonce_counter_file),
        module._AUTHORIZATION_AUTHORITY_FILE_VAR: str(authz_file),
        module._CONFIRMATION_AUTHORITY_FILE_VAR: str(confirm_file),
        module._RECONCILIATION_AUTHORITY_FILE_VAR: str(reconcile_file),
        module._WITNESS_BASE_URL_VAR: "https://127.0.0.1:1",
        module._WITNESS_CLIENT_CERT_VAR: str(cert_path),
        module._WITNESS_CLIENT_KEY_VAR: str(key_path),
        module._WITNESS_SERVER_CA_VAR: str(cert_path),
    }


# ---------------------------------------------------------------------------
# 1. Disabled by default / partial configuration
# ---------------------------------------------------------------------------


def test_completely_unconfigured_returns_none():
    assert module.build_write_batch1_production_runtime({}) is None


def test_completely_unconfigured_leaves_write_endpoints_unchanged():
    before = dict(vars(WriteEndpoints))
    module.build_write_batch1_production_runtime({})
    assert dict(vars(WriteEndpoints)) == before


@pytest.mark.parametrize("dropped", list(module._REQUIRED_VARS))
def test_partial_configuration_fails_closed(tmp_path, dropped):
    env = _full_env(tmp_path)
    del env[dropped]
    with pytest.raises(Tier1ConfigurationError, match="partial"):
        module.build_write_batch1_production_runtime(env)


# ---------------------------------------------------------------------------
# 2. Malformed required material fails closed
# ---------------------------------------------------------------------------


def test_malformed_store_integrity_material_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env[module._STORE_KEY_FILE_VAR]).write_text("not json")
    with pytest.raises(Exception):  # noqa: B017 - KeyMaterialError, not re-exported here
        module.build_write_batch1_production_runtime(env)


def test_malformed_encryption_material_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env[module._ENCRYPTION_KEY_FILE_VAR]).write_text("not json")
    with pytest.raises(Exception):  # noqa: B017
        module.build_write_batch1_production_runtime(env)


def test_malformed_authorization_authority_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env[module._AUTHORIZATION_AUTHORITY_FILE_VAR]).write_text("not json")
    with pytest.raises(Tier1ConfigurationError):
        module.build_write_batch1_production_runtime(env)


def test_malformed_confirmation_authority_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env[module._CONFIRMATION_AUTHORITY_FILE_VAR]).write_text(json.dumps({"authority_id": "x"}))
    with pytest.raises(Tier1ConfigurationError):
        module.build_write_batch1_production_runtime(env)


def test_malformed_reconciliation_authority_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env[module._RECONCILIATION_AUTHORITY_FILE_VAR]).write_text(
        json.dumps({"authority_id": "x", "public_key_hex": "zz" * 32})
    )
    with pytest.raises(Tier1ConfigurationError):
        module.build_write_batch1_production_runtime(env)


# ---------------------------------------------------------------------------
# 3. Anti-rollback anchor requirement (ADR-011/ADR-021, unmodified)
# ---------------------------------------------------------------------------


def test_unprovisioned_anti_rollback_anchor_fails_closed(tmp_path):
    """The store exists but its anchor-provisioning record was never
    seeded/marked complete -- must refuse rather than construct with
    anti_rollback_anchor=None. Same discipline as
    production_runtime.py::test_unprovisioned_anti_rollback_anchor_fails_closed,
    exercised here against this module's own dedicated store."""

    env = _full_env(tmp_path)
    # _full_env() already seeds a complete baseline; rebuild without it by
    # constructing a second, never-seeded store at a different path. The
    # store file must exist with its schema initialized (an
    # existing-but-unprovisioned store, distinct from one that does not
    # exist at all) -- mirrors test_production_runtime.py's own identical
    # test exactly.

    unseeded_store = tmp_path / "unseeded" / "recovery.sqlite3"
    unseeded_store.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    unseeded_key = tmp_path / "unseeded_key" / "integrity.json"
    _key_file(unseeded_key, key_id="unseeded-integrity")
    open_production_store(
        ProductionStoreConfig(store_path=unseeded_store, key_file=unseeded_key, store_id=module.CONTRACT_STORE_ID)
    )
    env[module._STORE_PATH_VAR] = str(unseeded_store)
    env[module._STORE_KEY_FILE_VAR] = str(unseeded_key)
    with pytest.raises(Tier1ConfigurationError, match="anchor"):
        module.build_write_batch1_production_runtime(env)


# ---------------------------------------------------------------------------
# 3b. Store-identity isolation from the alias capability's own production
#     store domain (owner instruction, 2026-09-04: "Do NOT reuse the alias
#     capability's existing alias-named store or consumption store" /
#     "Batch 1 store cannot accidentally be opened as alias store" /
#     "alias store cannot accidentally be opened as Batch 1 store").
# ---------------------------------------------------------------------------


def test_batch1_store_id_is_distinct_from_alias_store_and_consumption_ids():
    from pfsense_mcp.tier1.production_runtime import CONSUMPTION_STORE_ID as ALIAS_CONSUMPTION_STORE_ID

    assert module.CONTRACT_STORE_ID != ALIAS_CONTRACT_STORE_ID
    assert module.CONSUMPTION_STORE_ID != ALIAS_CONSUMPTION_STORE_ID
    # Also distinct from each other -- a contract store and a consumption
    # store must never share one identity even within Batch 1's own domain.
    assert module.CONTRACT_STORE_ID != module.CONSUMPTION_STORE_ID


def test_alias_contract_store_file_cannot_be_opened_as_the_batch1_store(tmp_path):
    """A store file physically initialized under the ALIAS capability's
    own `PRODUCTION_STORE_ID` must fail closed, not silently succeed, if
    something ever pointed `PFSENSE_TIER1_WRITE_BATCH1_STORE_PATH` at it
    -- `SqliteRecoveryContractStore`'s own store_id metadata binding is
    what enforces this, proven here specifically for the alias/Batch 1
    pairing rather than trusting the generic mechanism alone."""

    alias_shaped_store = tmp_path / "alias_shaped" / "recovery.sqlite3"
    alias_shaped_store.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    alias_shaped_key = tmp_path / "alias_shaped_key" / "integrity.json"
    _key_file(alias_shaped_key, key_id="alias-shaped-integrity")
    open_production_store(
        ProductionStoreConfig(
            store_path=alias_shaped_store, key_file=alias_shaped_key, store_id=ALIAS_CONTRACT_STORE_ID
        )
    )
    provision_production_anchor_baseline(
        ProductionStoreConfig(
            store_path=alias_shaped_store, key_file=alias_shaped_key, store_id=ALIAS_CONTRACT_STORE_ID
        ),
        value=2,
        handle="0x01500001",
    )

    env = _full_env(tmp_path)
    env[module._STORE_PATH_VAR] = str(alias_shaped_store)
    env[module._STORE_KEY_FILE_VAR] = str(alias_shaped_key)
    with pytest.raises(Exception):  # noqa: B017 - ContractIntegrityError, not re-exported here
        module.build_write_batch1_production_runtime(env)


def test_batch1_store_file_cannot_be_opened_as_the_alias_store(tmp_path):
    """The reverse direction: a store file physically initialized under
    Batch 1's own `CONTRACT_STORE_ID` must fail closed if something ever
    pointed `production_runtime.py`'s own `PFSENSE_TIER1_STORE_PATH` at
    it."""

    from pfsense_mcp.tier1.production_runtime import build_production_runtime

    batch1_shaped_store = tmp_path / "batch1_shaped" / "recovery.sqlite3"
    batch1_shaped_store.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    batch1_shaped_key = tmp_path / "batch1_shaped_key" / "integrity.json"
    _key_file(batch1_shaped_key, key_id="batch1-shaped-integrity")
    open_production_store(
        ProductionStoreConfig(
            store_path=batch1_shaped_store, key_file=batch1_shaped_key, store_id=module.CONTRACT_STORE_ID
        )
    )
    provision_production_anchor_baseline(
        ProductionStoreConfig(
            store_path=batch1_shaped_store, key_file=batch1_shaped_key, store_id=module.CONTRACT_STORE_ID
        ),
        value=2,
        handle="0x01500002",
    )

    alias_env = _full_env(tmp_path)  # reuses this module's own fixture only for the unrelated non-store values below
    api_key_file = tmp_path / "alias_api_key.txt"
    api_key_file.write_text("synthetic-api-key\n")
    os.chmod(api_key_file, 0o600)
    env = {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": str(api_key_file),
        "PFSENSE_TLS_MODE": "strict",
        "PFSENSE_TIER1_STORE_PATH": str(batch1_shaped_store),
        "PFSENSE_TIER1_STORE_KEY_FILE": str(batch1_shaped_key),
        "PFSENSE_TIER1_CONSUMPTION_STORE_PATH": alias_env[module._CONSUMPTION_STORE_PATH_VAR],
        "PFSENSE_TIER1_CONSUMPTION_STORE_KEY_FILE": alias_env[module._CONSUMPTION_STORE_KEY_FILE_VAR],
        "PFSENSE_TIER1_ENCRYPTION_KEY_FILE": alias_env[module._ENCRYPTION_KEY_FILE_VAR],
        "PFSENSE_TIER1_NONCE_COUNTER_FILE": alias_env[module._NONCE_COUNTER_FILE_VAR],
        "PFSENSE_TIER1_AUTHORIZATION_AUTHORITY_FILE": alias_env[module._AUTHORIZATION_AUTHORITY_FILE_VAR],
        "PFSENSE_TIER1_CONFIRMATION_AUTHORITY_FILE": alias_env[module._CONFIRMATION_AUTHORITY_FILE_VAR],
        "PFSENSE_TIER1_RECONCILIATION_AUTHORITY_FILE": alias_env[module._RECONCILIATION_AUTHORITY_FILE_VAR],
        "PFSENSE_TIER1_WITNESS_BASE_URL": alias_env[module._WITNESS_BASE_URL_VAR],
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": alias_env[module._WITNESS_CLIENT_CERT_VAR],
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": alias_env[module._WITNESS_CLIENT_KEY_VAR],
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": alias_env[module._WITNESS_SERVER_CA_VAR],
        "PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE": str(tmp_path / "authorization-inbox.json"),
        "PFSENSE_TIER1_CONFIRMATION_PENDING_FILE": str(tmp_path / "confirmation-pending.json"),
        "PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE": str(tmp_path / "confirmation-signed.json"),
        "PFSENSE_TIER1_AUTHORIZATION_PREVIEW_FILE": str(tmp_path / "authorization-preview.json"),
    }
    assert ALIAS_CONTRACT_STORE_ID != module.CONTRACT_STORE_ID  # sanity: the two IDs really do differ
    with pytest.raises(Exception):  # noqa: B017 - ContractIntegrityError, not re-exported here
        build_production_runtime(env)


def test_batch1_contract_store_and_consumption_store_are_independently_isolated(tmp_path):
    """Confirms the two Batch 1 stores are genuinely separate files/
    identities, not one store wearing two hats -- opening the contract
    store file as if it were the consumption store (and vice versa)
    fails closed on schema/identity mismatch, never silently succeeds."""

    from pfsense_mcp.tier1.authorization_consumption_store import SqliteAuthorizationConsumptionStore

    env = _full_env(tmp_path)
    with pytest.raises(Exception):  # noqa: B017
        SqliteAuthorizationConsumptionStore(
            Path(env[module._STORE_PATH_VAR]),
            integrity_key=b"i" * 32,
            store_id=module.CONSUMPTION_STORE_ID,
        )


def test_unregistered_write_endpoint_never_becomes_constructible(tmp_path, monkeypatch):
    """A future, hypothetical sixth `WriteEndpoints` entry -- even one
    that is `acceptance_eligible=True` -- must not automatically appear
    through this generalized runtime: `ProductionWriteBatch1Runtime` has
    exactly five fixed, named fields, sourced from this module's own
    hardcoded capability bindings, never from a dynamic scan of
    `WriteEndpoints.active_entries()`. Adding a new WriteEndpoints entry
    changes nothing about what this function returns until a human
    explicitly adds a new named binding to this module's own source."""

    from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

    monkeypatch.setattr(
        WriteEndpoints,
        "HYPOTHETICAL_SIXTH_ENDPOINT",
        WriteEndpointInfo(
            path_suffix="/example/sixth",
            http_method="PATCH",
            verified=False,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
            acceptance_eligible=True,
        ),
        raising=False,
    )
    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    assert {f.name for f in fields(runtime)} == {
        "ntp_time_server_prefer",
        "ntp_settings_observability",
        "log_display_preferences",
        "log_retention_settings",
        "system_timezone",
    }


# ---------------------------------------------------------------------------
# 4. Successful construction -- structural correctness
# ---------------------------------------------------------------------------


def test_full_construction_succeeds_and_returns_exactly_five_capabilities(tmp_path):
    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    field_names = {f.name for f in fields(runtime)}
    assert field_names == {
        "ntp_time_server_prefer",
        "ntp_settings_observability",
        "log_display_preferences",
        "log_retention_settings",
        "system_timezone",
    }
    for name in field_names:
        assert isinstance(getattr(runtime, name), WriteExecutionCoreV1)


def test_construction_does_not_mutate_write_endpoints_or_grant_privileges(tmp_path):
    endpoints_before = dict(vars(WriteEndpoints))
    profile_before = frozenset(EngineerProfile.capabilities)
    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    assert dict(vars(WriteEndpoints)) == endpoints_before
    assert frozenset(EngineerProfile.capabilities) == profile_before


def test_every_call_is_a_fresh_construction_no_caching(tmp_path):
    env = _full_env(tmp_path)
    first = module.build_write_batch1_production_runtime(env)
    second = module.build_write_batch1_production_runtime(env)
    assert first is not None and second is not None
    assert first is not second
    assert first.system_timezone is not second.system_timezone


# ---------------------------------------------------------------------------
# 5. Cross-capability isolation -- static binding cannot be crossed
# ---------------------------------------------------------------------------
#
# "Every capability construction must statically bind: capability identity,
# adapter, preparer, endpoint, method, privilege, risk, request/prepared
# types, semantic unit, authorization policy rule, anti-rollback anchor,
# transport. Caller input must not choose or override those values."
#
# WriteExecutionCoreV1 exposes none of this as public API (by its own
# design -- see its module docstring), so these tests inspect the private
# attributes directly, exactly as this file's own author (this module)
# constructed them -- the same technique already used by
# test_alias_description_execution.py's internal-state assertions.


def _capability_specs(runtime: module.ProductionWriteBatch1Runtime) -> dict[str, WriteExecutionCoreV1]:
    return {
        "ntp_time_server_prefer": runtime.ntp_time_server_prefer,
        "ntp_settings_observability": runtime.ntp_settings_observability,
        "log_display_preferences": runtime.log_display_preferences,
        "log_retention_settings": runtime.log_retention_settings,
        "system_timezone": runtime.system_timezone,
    }


def test_each_capability_has_a_distinct_contract_id_prefix(tmp_path):
    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    prefixes = [core._contract_id_prefix for core in _capability_specs(runtime).values()]
    assert prefixes == ["ntppref", "ntpobs", "logdisp", "logret", "systz"]
    assert len(set(prefixes)) == 5


def test_each_capability_has_a_distinct_request_and_prepared_type(tmp_path):
    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    request_types = [core._request_type for core in _capability_specs(runtime).values()]
    prepared_types = [core._prepared_type for core in _capability_specs(runtime).values()]
    assert len(set(request_types)) == 5
    assert len(set(prepared_types)) == 5


def test_each_capability_has_a_distinct_raw_target_fn(tmp_path):
    """A future accidental copy-paste (e.g. wiring log_retention_settings
    with log_display_preferences' own raw_target_fn) would otherwise be
    entirely invisible -- the two capabilities share the same underlying
    LogSettingsStateV1 shape, so a swapped raw_target_fn would still
    "work" at runtime without ever raising. This test would catch that
    class of mistake even though the two functions are behaviorally
    identical, because it checks that each capability was wired with its
    OWN dedicated function object, not merely a function of the right
    shape."""

    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    fns = {name: core._raw_target_fn for name, core in _capability_specs(runtime).items()}
    assert fns["ntp_time_server_prefer"] is module._ntp_prefer_raw_target
    assert fns["ntp_settings_observability"] is module._ntp_observability_raw_target
    assert fns["log_display_preferences"] is module._log_settings_raw_target
    assert fns["log_retention_settings"] is module._log_settings_raw_target
    assert fns["system_timezone"] is module._system_timezone_raw_target


def test_each_capability_executor_has_exactly_one_policy_rule_naming_only_itself(tmp_path):
    """The strongest available proof that capability A cannot acquire B's
    endpoint/method/privilege: each capability's own `MutationExecutor`
    is constructed with a `MutationPolicy` containing exactly one
    `MutationRule`, and that rule's (capability, endpoint_symbol,
    http_method) triple names only that capability -- never any other of
    the five, never a wildcard, never a caller-suppliable value."""

    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None

    expected = {
        "ntp_time_server_prefer": (
            Capability.NTP_TIME_SERVER_PREFER_WRITE,
            module.NTP_PREFER_ENDPOINT_SYMBOL,
            module.NTP_PREFER_HTTP_METHOD,
        ),
        "ntp_settings_observability": (
            Capability.NTP_SETTINGS_OBSERVABILITY_WRITE,
            module.NTP_OBSERVABILITY_ENDPOINT_SYMBOL,
            module.NTP_OBSERVABILITY_HTTP_METHOD,
        ),
        "log_display_preferences": (
            Capability.LOG_DISPLAY_PREFERENCES_WRITE,
            module.LOG_DISPLAY_ENDPOINT_SYMBOL,
            module.LOG_DISPLAY_HTTP_METHOD,
        ),
        "log_retention_settings": (
            Capability.LOG_RETENTION_SETTINGS_WRITE,
            module.LOG_RETENTION_ENDPOINT_SYMBOL,
            module.LOG_RETENTION_HTTP_METHOD,
        ),
        "system_timezone": (
            Capability.SYSTEM_TIMEZONE_WRITE,
            module.SYSTEM_TIMEZONE_ENDPOINT_SYMBOL,
            module.SYSTEM_TIMEZONE_HTTP_METHOD,
        ),
    }
    all_endpoint_symbols = {triple[1] for triple in expected.values()}
    for name, core in _capability_specs(runtime).items():
        executor: MutationExecutor = core._executor
        rules = executor._policy.rules
        assert len(rules) == 1
        (rule,) = rules
        assert (rule.capability, rule.endpoint_symbol, rule.http_method) == expected[name]
        # No rule accidentally names a SIBLING capability's endpoint symbol.
        for other_symbol in all_endpoint_symbols - {expected[name][1]}:
            assert rule.endpoint_symbol != other_symbol


def test_each_capability_shares_the_one_dedicated_store_and_authorities_only(tmp_path):
    """Confirms the deliberate sharing (dedicated contract/consumption
    store, dedicated encryption key/nonce counter -- one each, reused
    across all five; shared pinned authorities and anti-rollback anchor)
    without any capability getting its OWN, undeclared copy of any of
    these -- which would be an unreviewed, silent architecture change."""

    env = _full_env(tmp_path)
    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    cores = list(_capability_specs(runtime).values())
    assert len({id(core._store) for core in cores}) == 1
    assert len({id(core._consumption_store) for core in cores}) == 1
    assert len({id(core._authorities) for core in cores}) == 1
    assert len({core._encryption_key.key_id for core in cores}) == 1
    anchors = {id(core._executor._anti_rollback_anchor) for core in cores}
    assert len(anchors) == 1


def test_no_capability_construction_accepts_a_caller_selected_capability_argument():
    """`build_write_batch1_production_runtime()` accepts only `env` --
    there is no parameter through which a caller could request an
    arbitrary sixth capability, override which adapter/preparer/policy a
    named capability gets, or otherwise reach generic WRITE dispatch."""

    import inspect

    signature = inspect.signature(module.build_write_batch1_production_runtime)
    assert list(signature.parameters) == ["env"]


# ---------------------------------------------------------------------------
# 6. acceptance_eligible / ADR-029 semantics
# ---------------------------------------------------------------------------


def _lab_config() -> PfSenseConfig:
    return PfSenseConfig(
        base_url=_LAB_URL,
        identity=_LAB_IDENTITY,
        key_file=None,
        tls_mode=TLSMode.INSECURE,
        tls_ca_file=None,
        api_version=ApiVersion.V2,
        profile=AuditorProfile,
        log_max_bytes=5_000_000,
        log_backup_count=5,
    )


@pytest.mark.parametrize("endpoint_symbol", sorted(_FIVE_ENDPOINT_SYMBOLS))
def test_issue_acceptance_context_succeeds_for_each_batch1_endpoint_against_the_pinned_lab_target(endpoint_symbol):
    # Deliberately a function-local import, not module-level: importing
    # tier1.acceptance at module scope would make it appear in
    # sys.modules as soon as pytest COLLECTS this file -- before any
    # test runs -- which could cause
    # test_acceptance_isolation.py::test_importing_mcp_entrypoints_never_loads_acceptance_module
    # (a same-process sys.modules check) to see it as already loaded if
    # both files land in the same pytest/xdist-worker process. A
    # function-local import defers loading until this specific test
    # actually executes instead.
    from pfsense_mcp.tier1.acceptance import issue_acceptance_context

    context = issue_acceptance_context(_lab_config(), endpoint_symbol=endpoint_symbol)
    assert context.endpoint_symbol == endpoint_symbol
    assert context.target_identity == _LAB_IDENTITY


@pytest.mark.parametrize("endpoint_symbol", sorted(_FIVE_ENDPOINT_SYMBOLS))
def test_issue_acceptance_context_refuses_non_lab_target_for_each_batch1_endpoint(endpoint_symbol):
    from pfsense_mcp.tier1.acceptance import issue_acceptance_context

    non_lab = PfSenseConfig(
        base_url="https://pfsense.production.invalid",
        identity="prod-admin",
        key_file=None,
        tls_mode=TLSMode.INSECURE,
        tls_ca_file=None,
        api_version=ApiVersion.V2,
        profile=AuditorProfile,
        log_max_bytes=5_000_000,
        log_backup_count=5,
    )
    with pytest.raises(AcceptanceError, match="LAB-only"):
        issue_acceptance_context(non_lab, endpoint_symbol=endpoint_symbol)


def test_all_five_batch1_endpoints_remain_verified_false():
    """acceptance_eligible=True is never equivalent to verified=True --
    the distinction the mission requires stays explicit. Becoming
    acceptance-eligible does not, by itself, promote any endpoint."""

    for endpoint_symbol in _FIVE_ENDPOINT_SYMBOLS:
        endpoint = getattr(WriteEndpoints, endpoint_symbol)
        assert endpoint.acceptance_eligible is True
        assert endpoint.verified is False


# ---------------------------------------------------------------------------
# 7. Default reachability / no accidental profile grant
# ---------------------------------------------------------------------------


def test_default_reachable_write_remains_zero():
    """Reuses scripts/write_capability_check.py's own authoritative
    default-safety proof directly -- the same function `make validate`'s
    own write-capability-inactivity stage calls -- rather than
    reimplementing a second, weaker check here."""

    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import write_capability_check

        assert write_capability_check.find_default_safety_violations() == []
    finally:
        sys.path.remove(str(ROOT / "scripts"))


def test_no_profile_grants_any_batch1_write_capability():
    """Reuses the same script's scope-creep check: WriteProtectedProfile
    may grant exactly ALIAS_WRITE and nothing else -- none of the five
    new Batch 1 capabilities may appear there without a separate,
    explicit owner decision to grant them."""

    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import write_capability_check

        assert write_capability_check.find_scope_creep() == []
    finally:
        sys.path.remove(str(ROOT / "scripts"))


# ---------------------------------------------------------------------------
# 8. Real primitives, not stubs -- authorize_and_create() genuinely
#    verifies a real Ed25519 signature through the production-constructed
#    core (no network I/O is required for this: authorize_and_create()
#    never sends anything -- only confirm_and_handoff()'s final executor
#    handoff would, which this file deliberately never reaches, matching
#    this module's own "no LAB, no production" scope for this review pass).
# ---------------------------------------------------------------------------


class _FakeReadClient:
    def __init__(self) -> None:
        from pfsense_mcp.models.system import SystemStatus
        from pfsense_mcp.models.system_ha_sync import SystemHaSync
        from pfsense_mcp.models.system_rest_api_settings import SystemRestApiSettings  # noqa: F401

        self._SystemStatus = SystemStatus
        self._SystemHaSync = SystemHaSync
        self.timezone = "America/New_York"
        self.netgate_id = "netgate-synthetic"
        self.pfhostid = "pfhost-synthetic"
        self.pfrest_read_only = False

    def get_system_timezone(self):
        from pfsense_mcp.models.system_timezone import SystemTimezone

        return SystemTimezone(timezone=self.timezone)

    def get_system_status(self, *, include_identifying_metadata: bool = False):
        assert include_identifying_metadata is True
        return self._SystemStatus(
            platform="synthetic",
            uptime="1 day",
            cpu_model="synthetic",
            cpu_count=1,
            cpu_usage=0.0,
            mem_usage=1,
            swap_usage=0,
            disk_usage=1,
            netgate_id=self.netgate_id,
        )

    def get_system_hasync(self, *, include_identifying_metadata: bool = False):
        assert include_identifying_metadata is True
        values = {name: False for name, field in self._SystemHaSync.model_fields.items() if field.annotation is bool}
        values.update(
            {
                "pfsyncinterface": "none",
                "pfsyncpeerip": None,
                "synchronizetoip": None,
                "pfhostid": self.pfhostid,
                "username": None,
            }
        )
        return self._SystemHaSync.model_validate(values)

    def get_system_restapi_settings(self, *, include_identifying_metadata: bool = False):
        from pfsense_mcp.models.system_rest_api_settings import SystemRestApiSettings

        return SystemRestApiSettings(
            allow_development_packages=False,
            allow_pre_releases=False,
            allowed_interfaces=["lan"],
            auth_methods=["key"],
            enabled=True,
            expose_sensitive_fields=False,
            ha_sync=False,
            ha_sync_hosts=[],
            ha_sync_validate_certs=True,
            hateoas=False,
            jwt_exp=3600,
            keep_backup=True,
            log_level="info",
            log_successful_auth=True,
            login_protection=True,
            override_sensitive_fields=[],
            read_only=self.pfrest_read_only,
            represent_interfaces_as="descr",
        )


def _plan():
    return _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="batch1.step", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE
            ),
        )
    )


def _authorization(private: Ed25519PrivateKey, authority_id: str, digest: str):
    values = {
        "plan": _plan(),
        "authorized_executions": (PlanAuthorizationStepBinding(step_id="batch1.step", execution_intent_digest=digest),),
        "authorization_id": "authz-v2-real-primitives",
        "authority_id": authority_id,
        "issued_at": NOW - datetime.timedelta(minutes=1),
        "expires_at": NOW + datetime.timedelta(minutes=4),
    }
    return sign_plan_authorization_v2(build_plan_authorization_v2_payload(**values), private)


def test_authorize_and_create_genuinely_verifies_a_real_signature_through_production_wiring(tmp_path, monkeypatch):
    """Constructs the real `WriteExecutionCoreV1` for `system_timezone`
    through `build_write_batch1_production_runtime()`, then drives
    `authorize_and_create()` with a genuinely Ed25519-signed
    `PlanAuthorizationV2` whose signature verifies against the SAME
    authority public key file this construction loaded. If signature
    verification were stubbed or skipped anywhere in this wiring, an
    authorization signed by the WRONG private key (below) would
    incorrectly succeed -- it does not."""

    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    env = _full_env(tmp_path)

    # Recover the real authority private key by regenerating the exact
    # same keypair the fixture wrote to the authorization-authority file
    # is not possible (only the public half is persisted, by design --
    # see production_runtime.py's own "no private signing key is loaded
    # anywhere in this module" discipline). Instead, sign with a freshly
    # generated, INTENTIONALLY WRONG private key, proving the real
    # verifier genuinely rejects it -- the positive-signature case is
    # already proven end-to-end for this exact algorithm by
    # test_alias_description_execution.py and
    # test_adr037_batch1_write_capabilities.py against the same
    # canonical primitives this module's own construction reuses
    # unmodified.
    wrong_private, _ = _ed25519_keypair()

    runtime = module.build_write_batch1_production_runtime(env)
    assert runtime is not None
    core = runtime.system_timezone

    read_client = _FakeReadClient()
    from pfsense_mcp.tier1.alias_description import ConfiguredApplianceTargetV1
    from pfsense_mcp.tier1.system_timezone_write import SystemTimezonePreparerV1

    preparer = SystemTimezonePreparerV1(
        read_client=read_client,
        configured_target=ConfiguredApplianceTargetV1(base_url="https://pfsense.invalid", tls_mode=TLSMode.STRICT),
    )
    request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    prepared = preparer.prepare(request)
    digest = compute_execution_intent_digest(prepared.intent)
    forged = _authorization(wrong_private, "authz-owner-1", digest)

    with pytest.raises(BoundExecutionError):
        core.authorize_and_create(
            request,
            authorized_preparation=prepared,
            authorization=forged,
            requested_plan_digest=forged.plan_digest,
            requested_step_id="batch1.step",
            required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            now=NOW,
        )


# ---------------------------------------------------------------------------
# 9. No alias_evidence.py-style bypass for the new ADR-037 capabilities
# ---------------------------------------------------------------------------


def _lab_scripts() -> list[Path]:
    if not LAB_ROOT.is_dir():
        return []
    return [path for path in LAB_ROOT.glob("*.py") if path.name != "__init__.py"]


def _sets_write_endpoints_attribute(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "setattr"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "WriteEndpoints"
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "WriteEndpoints"
        ):
            return True
    return False


def _references_any_batch1_symbol(tree: ast.Module) -> bool:
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    return bool(names & _FIVE_ENDPOINT_SYMBOLS)


def test_no_lab_script_monkeypatches_write_endpoints_for_a_batch1_capability():
    """`lab/alias_evidence.py` is the one, historically-reviewed,
    grandfathered exception to the "never monkeypatch WriteEndpoints"
    discipline (ADR-026's own accepted evidence-gathering mechanism for
    the alias capability, predating ADR-037 and ADR-029's own real
    acceptance-path model) -- it is exempted by name, not by pattern,
    so this test cannot be silently satisfied by renaming a future
    bypass script around the check. No OTHER file under lab/ may combine
    a WriteEndpoints.setattr(...) monkeypatch with any of the five
    ADR-037 Batch 1 endpoint symbols -- the owner's explicit instruction
    (2026-09-04) that the alias_evidence.py mechanism "is not an
    acceptable template for ADR-037 Batch 1 qualification"."""

    grandfathered = {"alias_evidence.py"}
    offenders = []
    for path in _lab_scripts():
        if path.name in grandfathered:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _sets_write_endpoints_attribute(tree) and _references_any_batch1_symbol(tree):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_no_lab_script_references_a_batch1_capability_at_all_yet():
    """Stronger than the above for right now: no `lab/*.py` file
    references any of the five Batch 1 capabilities' endpoint symbols at
    all yet, grandfathered file or not -- confirming no bypass-style
    qualification script for these capabilities has been introduced.
    This test is intentionally allowed to need updating the day a real,
    reviewed LAB ceremony script for these capabilities is actually
    built (see this module's own docstring for what that script must
    and must not do) -- its purpose is to make that day a deliberate,
    visible, reviewed change to this test, not a silent addition."""

    offenders = []
    for path in _lab_scripts():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _references_any_batch1_symbol(tree):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []
