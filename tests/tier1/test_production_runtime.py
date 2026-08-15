"""Regression and adversarial tests for
`pfsense_mcp.tier1.production_runtime` -- W2, the fixed production
runtime for the alias-description first-WRITE path. No live pfSense
call, no LAB mutation, no WriteEndpoints population, no capability
activation anywhere in this module.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.errors import ConfigurationError
from pfsense_mcp.profiles import EngineerProfile
from pfsense_mcp.tier1 import production_runtime as module
from pfsense_mcp.tier1.alias_description import ENDPOINT_SYMBOL, HTTP_METHOD, AliasDescriptionAdapterV1
from pfsense_mcp.tier1.alias_description_execution import AliasDescriptionExecutionCoreV1
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import ConfirmationError, Tier1ConfigurationError
from pfsense_mcp.tier1.executor import MutationExecutor
from pfsense_mcp.tier1.production_runtime import ProductionAliasDescriptionRuntime, build_production_runtime
from pfsense_mcp.tier1.production_store import (
    ProductionStoreConfig,
    open_production_store,
    provision_production_anchor_baseline,
)
from pfsense_mcp.tier1.reconciliation import ReconciliationEvidence, ReconciliationOutcome
from pfsense_mcp.tier1.reconciliation_providers import signing_payload as reconciliation_signing_payload
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.write_endpoints import WriteEndpoints

# NOTE: every pfsense_mcp.tier1 import this file needs is collected here,
# at module top level -- never deferred inside a test/helper function
# body. tests/api_surface/test_catalogue_isolation.py deliberately
# deletes pfsense_mcp.tier1.* from sys.modules and re-imports it fresh,
# elsewhere in the same pytest session, to prove production bootstrap
# never imports it; a name captured here before that point and one
# captured via a function-local import afterward would silently become
# two distinct (structurally identical, isinstance()-incompatible)
# class objects for the same enum. Keeping every reference here, at
# collection time, keeps this file internally consistent regardless of
# what any other test file does to sys.modules later in the session.

_MATERIAL_HEX = "ab" * 32


def _key_file(path: Path, *, key_id: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({"key_id": key_id, "epoch": 0, "material_hex": _MATERIAL_HEX}))
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
    """Mirrors tests/test_tier1_anchor_check.py's exact cert-generation
    pattern -- a real RSA key and self-signed certificate, used only to
    prove the mTLS SSLContext loads successfully offline; no network
    connection is ever made against it in these tests."""

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


def _full_env(tmp_path: Path, *, tls_mode: str = "strict") -> dict[str, str]:
    api_key_file = tmp_path / "api_key.txt"
    api_key_file.write_text("synthetic-api-key\n")
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

    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(mode=0o700, exist_ok=True)
    authorization_inbox_file = artifacts_dir / "authorization-inbox.json"
    confirmation_pending_file = artifacts_dir / "confirmation-pending.json"
    confirmation_signed_file = artifacts_dir / "confirmation-signed.json"
    authorization_preview_file = artifacts_dir / "authorization-preview.json"

    provision_production_anchor_baseline(
        ProductionStoreConfig(store_path=store_path, key_file=store_key_file), value=2, handle="0x01500000"
    )

    return {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": str(api_key_file),
        "PFSENSE_TLS_MODE": tls_mode,
        "PFSENSE_TIER1_STORE_PATH": str(store_path),
        "PFSENSE_TIER1_STORE_KEY_FILE": str(store_key_file),
        "PFSENSE_TIER1_CONSUMPTION_STORE_PATH": str(consumption_path),
        "PFSENSE_TIER1_CONSUMPTION_STORE_KEY_FILE": str(consumption_key_file),
        "PFSENSE_TIER1_ENCRYPTION_KEY_FILE": str(encryption_key_file),
        "PFSENSE_TIER1_NONCE_COUNTER_FILE": str(nonce_counter_file),
        "PFSENSE_TIER1_AUTHORIZATION_AUTHORITY_FILE": str(authz_file),
        "PFSENSE_TIER1_CONFIRMATION_AUTHORITY_FILE": str(confirm_file),
        "PFSENSE_TIER1_RECONCILIATION_AUTHORITY_FILE": str(reconcile_file),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://127.0.0.1:1",
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(cert_path),
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(key_path),
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(cert_path),
        "PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE": str(authorization_inbox_file),
        "PFSENSE_TIER1_CONFIRMATION_PENDING_FILE": str(confirmation_pending_file),
        "PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE": str(confirmation_signed_file),
        "PFSENSE_TIER1_AUTHORIZATION_PREVIEW_FILE": str(authorization_preview_file),
    }


# ---------------------------------------------------------------------------
# 1. Disabled by default / partial configuration
# ---------------------------------------------------------------------------


def test_completely_unconfigured_returns_none():
    assert build_production_runtime({}) is None


def test_completely_unconfigured_leaves_public_state_unchanged():
    # "Unchanged" means construction does not itself alter WriteEndpoints
    # -- not that WriteEndpoints must be empty (W3 Slice 4 added its one
    # accepted entry as a fixed, non-caller-selectable source-code fact,
    # unrelated to whether a runtime happens to construct).
    before = dict(vars(WriteEndpoints))
    build_production_runtime({})
    assert dict(vars(WriteEndpoints)) == before


@pytest.mark.parametrize("dropped", list(module._REQUIRED_VARS))
def test_partial_configuration_fails_closed(tmp_path, dropped):
    env = _full_env(tmp_path)
    del env[dropped]
    with pytest.raises(Tier1ConfigurationError, match="partial"):
        build_production_runtime(env)


# ---------------------------------------------------------------------------
# 2. Missing/malformed required material fails closed
# ---------------------------------------------------------------------------


def test_malformed_store_integrity_material_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env["PFSENSE_TIER1_STORE_KEY_FILE"]).write_text("not json")
    with pytest.raises(Exception):  # noqa: B017 - KeyMaterialError, deliberately not re-exported here
        build_production_runtime(env)


def test_malformed_encryption_material_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env["PFSENSE_TIER1_ENCRYPTION_KEY_FILE"]).write_text("not json")
    with pytest.raises(Exception):  # noqa: B017
        build_production_runtime(env)


def test_malformed_authorization_authority_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env["PFSENSE_TIER1_AUTHORIZATION_AUTHORITY_FILE"]).write_text("not json")
    with pytest.raises(Tier1ConfigurationError):
        build_production_runtime(env)


def test_malformed_confirmation_authority_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env["PFSENSE_TIER1_CONFIRMATION_AUTHORITY_FILE"]).write_text(json.dumps({"authority_id": "x"}))
    with pytest.raises(Tier1ConfigurationError):
        build_production_runtime(env)


def test_malformed_reconciliation_authority_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env["PFSENSE_TIER1_RECONCILIATION_AUTHORITY_FILE"]).write_text(
        json.dumps({"authority_id": "x", "public_key_hex": "zz" * 32})
    )
    with pytest.raises(Tier1ConfigurationError):
        build_production_runtime(env)


def test_unprovisioned_anti_rollback_anchor_fails_closed(tmp_path):
    """The store exists but was never seeded/marked complete -- the
    production runtime must refuse to enable, never construct with
    anti_rollback_anchor=None."""

    api_key_file = tmp_path / "api_key.txt"
    api_key_file.write_text("synthetic-api-key\n")
    os.chmod(api_key_file, 0o600)
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    store_key_file = tmp_path / "store_key" / "integrity.json"
    _key_file(store_key_file, key_id="store-integrity")
    consumption_dir = tmp_path / "consumption"
    consumption_dir.mkdir(mode=0o700)
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
    _authority_file(authz_file, authority_id="a", public_key=authz_pub)
    confirm_file = tmp_path / "authorities" / "confirmation.json"
    _authority_file(confirm_file, authority_id="b", public_key=confirm_pub)
    reconcile_file = tmp_path / "authorities" / "reconciliation.json"
    _authority_file(reconcile_file, authority_id="c", public_key=reconcile_pub)
    cert_path, key_path = _self_signed_cert(tmp_path)
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(mode=0o700, exist_ok=True)

    store_path = store_dir / "recovery.sqlite3"
    # Creates the store file/schema without seeding or completing anchor
    # provisioning -- an existing-but-unprovisioned store, distinct from
    # a store file that does not exist at all.
    open_production_store(ProductionStoreConfig(store_path=store_path, key_file=store_key_file))

    env = {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": str(api_key_file),
        "PFSENSE_TIER1_STORE_PATH": str(store_path),
        "PFSENSE_TIER1_STORE_KEY_FILE": str(store_key_file),
        "PFSENSE_TIER1_CONSUMPTION_STORE_PATH": str(consumption_dir / "consumed.sqlite3"),
        "PFSENSE_TIER1_CONSUMPTION_STORE_KEY_FILE": str(consumption_key_file),
        "PFSENSE_TIER1_ENCRYPTION_KEY_FILE": str(encryption_key_file),
        "PFSENSE_TIER1_NONCE_COUNTER_FILE": str(nonce_counter_file),
        "PFSENSE_TIER1_AUTHORIZATION_AUTHORITY_FILE": str(authz_file),
        "PFSENSE_TIER1_CONFIRMATION_AUTHORITY_FILE": str(confirm_file),
        "PFSENSE_TIER1_RECONCILIATION_AUTHORITY_FILE": str(reconcile_file),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://127.0.0.1:1",
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(cert_path),
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(key_path),
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(cert_path),
        "PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE": str(artifacts_dir / "authorization-inbox.json"),
        "PFSENSE_TIER1_CONFIRMATION_PENDING_FILE": str(artifacts_dir / "confirmation-pending.json"),
        "PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE": str(artifacts_dir / "confirmation-signed.json"),
        "PFSENSE_TIER1_AUTHORIZATION_PREVIEW_FILE": str(artifacts_dir / "authorization-preview.json"),
    }
    # Deliberately no provision_production_anchor_baseline() call.
    with pytest.raises(Tier1ConfigurationError, match="not fully provisioned"):
        build_production_runtime(env)


def test_missing_witness_tls_material_fails_closed(tmp_path):
    env = _full_env(tmp_path)
    Path(env["PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE"]).unlink()
    with pytest.raises(Tier1ConfigurationError):
        build_production_runtime(env)


def test_insecure_tls_mode_cannot_enable_runtime(tmp_path):
    env = _full_env(tmp_path, tls_mode="insecure")
    with pytest.raises(Tier1ConfigurationError, match="not eligible for production WRITE"):
        build_production_runtime(env)


def test_missing_appliance_config_fails_closed(tmp_path):
    """Base pfSense config (unconditionally required for any deployment)
    absent entirely -- the runtime must not degrade into constructing
    itself against a phantom appliance."""

    env = _full_env(tmp_path)
    del env["PFSENSE_API_URL"]
    with pytest.raises(ConfigurationError):
        build_production_runtime(env)


# ---------------------------------------------------------------------------
# 3. No caller-selected component; no private signing key
# ---------------------------------------------------------------------------


def test_public_factory_accepts_only_an_environment_mapping():
    import inspect

    signature = inspect.signature(build_production_runtime)
    assert set(signature.parameters) == {"env"}


def test_module_loads_no_private_signing_key_material():
    """Structural: this module never imports Ed25519PrivateKey or any
    other private-key-shaped type -- only PinnedAuthority (public key
    verification material)."""

    import inspect

    source = inspect.getsource(module)
    assert "PrivateKey" not in source
    assert "private_key" not in source


def test_runtime_exposes_no_lower_level_component():
    """The only public attribute is execution_core -- no store, executor,
    write client, transport, preparer, or artifact-exchange path is
    reachable from outside construction. New W3 Slice 3 implementation
    details are expected to grow this slot list over time; the invariant
    this test enforces is that every one of them stays private."""

    slots = set(ProductionAliasDescriptionRuntime.__slots__)
    assert "execution_core" in slots
    public = {name for name in slots if not name.startswith("_")}
    assert public == {"execution_core"}


# ---------------------------------------------------------------------------
# 4. Successful construction composes exactly the fixed, expected pieces
# ---------------------------------------------------------------------------


def test_successful_construction_composes_fixed_pieces(tmp_path):
    env = _full_env(tmp_path)
    runtime = build_production_runtime(env)
    assert isinstance(runtime, ProductionAliasDescriptionRuntime)
    core = runtime.execution_core
    assert isinstance(core, AliasDescriptionExecutionCoreV1)
    assert isinstance(core._preparer.adapter, AliasDescriptionAdapterV1)
    assert isinstance(core._executor, MutationExecutor)
    assert core._executor._anti_rollback_anchor is not None
    policy = core._executor._policy
    assert len(policy.rules) == 1
    (rule,) = policy.rules
    assert rule.capability is Capability.ALIAS_WRITE
    assert rule.endpoint_symbol == ENDPOINT_SYMBOL
    assert rule.http_method == HTTP_METHOD
    assert runtime._store._confirmation_verifier is not None
    assert runtime._store._reconciliation_verifier is not None
    assert runtime._store._anti_rollback_anchor is not None


def test_second_construction_call_builds_entirely_fresh_components(tmp_path):
    """No caching/memoization across calls -- two calls against the same
    configuration produce two independent object graphs."""

    env = _full_env(tmp_path)
    first = build_production_runtime(env)
    second = build_production_runtime(env)
    assert first is not None and second is not None
    assert first is not second
    assert first.execution_core is not second.execution_core
    assert first._store is not second._store


# ---------------------------------------------------------------------------
# 5. Restart / reconciliation: no automatic resend
# ---------------------------------------------------------------------------


class _AcceptingVerifier:
    """A permissive stand-in confirmation verifier used only to drive a
    contract into EXECUTING quickly in test setup -- mirrors
    tests/tier1/test_store_reconciliation.py's own established
    synthetic-verifier convention. What is actually under test in this
    module is the *production runtime's own* pinned reconciliation
    verifier (see the section below), never this setup helper."""

    def verify(self, evidence: object) -> bool:
        return True


def _setup_store_same_file(env: dict[str, str]):
    """A second `SqliteRecoveryContractStore` instance pointed at the
    exact same file/integrity key `build_production_runtime()` uses,
    with a permissive confirmation verifier -- for driving a contract to
    a specific state in test setup without needing a real Ed25519
    signature. Must use the identical integrity key material the real
    key file carries (`_MATERIAL_HEX`), or record-level HMAC
    verification would fail when the production runtime's own store
    later reads a row this helper wrote."""

    return SqliteRecoveryContractStore(
        Path(env["PFSENSE_TIER1_STORE_PATH"]),
        integrity_key=bytes.fromhex(_MATERIAL_HEX),
        store_id="tier1-production-anchor",
        confirmation_verifier=_AcceptingVerifier(),
    )


def _confirm_via_setup_store(setup_store, contract, *, expected_version: int):
    return setup_store.confirm(
        contract.contract_id,
        evidence=ConfirmationEvidence(
            authority_id="setup",
            algorithm="setup",
            nonce="setup-nonce",
            contract_id=contract.contract_id,
            operation_id=contract.operation_id,
            target_identity_digest=contract.target_identity_digest,
            target_fingerprint=contract.target_fingerprint,
            intent_digest=contract.intent_digest,
            expires_at=contract.expires_at,
            issued_at=contract.created_at,
            proof=b"setup-proof-never-cryptographically-verified",
        ),
        expected_version=expected_version,
    )


def test_restart_reconciles_interrupted_executing_contract(tmp_path, contract_factory):
    """Simulates a crash mid-EXECUTING: constructs a runtime, drives a
    contract directly into EXECUTING via a second store instance
    pointed at the same file (bypassing the executor entirely -- no
    send ever occurs), then calls build_production_runtime() again -- a
    fresh "restart" -- and proves the contract is moved to
    RECONCILIATION, never resent."""

    env = _full_env(tmp_path)
    first = build_production_runtime(env)
    assert first is not None

    contract = contract_factory(state=RecoveryState.PREPARING)
    setup_store = _setup_store_same_file(env)
    setup_store.create(contract)
    prepared = setup_store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    confirmed = _confirm_via_setup_store(setup_store, contract, expected_version=prepared.state_version)
    executing = setup_store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    assert executing.state is RecoveryState.EXECUTING

    second = build_production_runtime(env)
    assert second is not None
    reconciled = second._store.load(contract.contract_id)
    assert reconciled.state is RecoveryState.RECONCILIATION


# ---------------------------------------------------------------------------
# 6. Signed reconciliation uses the fixed pinned authority
# ---------------------------------------------------------------------------


def _drive_to_reconciliation(setup_store, contract):
    """Drives a contract from PREPARING all the way to RECONCILIATION
    using the permissive setup store (see `_setup_store_same_file`) --
    mirrors tests/tier1/test_store_reconciliation.py's own
    `_to_reconciliation` helper. Confirmation is deliberately not
    cryptographically real here; only the *reconciliation* signature is
    under test in the calling test below."""

    setup_store.create(contract)
    prepared = setup_store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    confirmed = _confirm_via_setup_store(setup_store, contract, expected_version=prepared.state_version)
    executing = setup_store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    return setup_store.transition(
        contract.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )


def test_reconciliation_requires_pinned_authority_and_wrong_signature_fails_closed(tmp_path, contract_factory):
    reconcile_key, reconcile_pub = _ed25519_keypair()
    env = _full_env(tmp_path)
    reconcile_file = Path(env["PFSENSE_TIER1_RECONCILIATION_AUTHORITY_FILE"])
    _authority_file(reconcile_file, authority_id="reconcile-owner-1", public_key=reconcile_pub)

    runtime = build_production_runtime(env)
    assert runtime is not None

    contract = contract_factory(state=RecoveryState.PREPARING)
    setup_store = _setup_store_same_file(env)
    in_reconciliation = _drive_to_reconciliation(setup_store, contract)
    assert in_reconciliation.state is RecoveryState.RECONCILIATION

    forged_evidence = ReconciliationEvidence(
        authority_id="reconcile-owner-1",
        algorithm="ed25519-reconciliation-v2",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        observed_state_version=in_reconciliation.state_version,
        outcome=ReconciliationOutcome.CONFIRMED_NOT_APPLIED,
        issued_at=datetime.datetime.now(datetime.timezone.utc),
        proof=b"not-a-real-ed25519-signature-of-the-right-length-for-post-init",
    )

    with pytest.raises(ConfirmationError):
        runtime.resolve_reconciliation(contract.contract_id, evidence=forged_evidence)
    # Not consumed by the failed attempt -- still in RECONCILIATION.
    assert runtime._store.load(contract.contract_id).state is RecoveryState.RECONCILIATION

    # A correctly-signed evidence, using the exact pinned authority's own
    # key, succeeds -- proving the failure above was specifically about
    # the wrong/forged signature, not evidence shape.
    real_evidence_unsigned = ReconciliationEvidence(
        authority_id="reconcile-owner-1",
        algorithm="ed25519-reconciliation-v2",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        observed_state_version=in_reconciliation.state_version,
        outcome=ReconciliationOutcome.CONFIRMED_NOT_APPLIED,
        issued_at=datetime.datetime.now(datetime.timezone.utc),
        proof=b"\x00" * 64,
    )
    signature = reconcile_key.sign(reconciliation_signing_payload(real_evidence_unsigned))
    signed_evidence = ReconciliationEvidence(
        authority_id=real_evidence_unsigned.authority_id,
        algorithm=real_evidence_unsigned.algorithm,
        contract_id=real_evidence_unsigned.contract_id,
        operation_id=real_evidence_unsigned.operation_id,
        observed_state_version=real_evidence_unsigned.observed_state_version,
        outcome=real_evidence_unsigned.outcome,
        issued_at=real_evidence_unsigned.issued_at,
        proof=signature,
    )
    resolved = runtime.resolve_reconciliation(contract.contract_id, evidence=signed_evidence)
    assert resolved.state is RecoveryState.FAILED


# ---------------------------------------------------------------------------
# 7. Public invariants unaffected
# ---------------------------------------------------------------------------


def test_public_mcp_contract_unaffected_by_construction(tmp_path):
    env = _full_env(tmp_path)
    before = dict(vars(WriteEndpoints))
    build_production_runtime(env)
    assert dict(vars(WriteEndpoints)) == before
    assert EngineerProfile.capabilities == frozenset()


def test_no_production_module_imports_production_runtime():
    import ast
    from pathlib import Path as _Path

    root = _Path(__file__).parents[2]
    production_root = root / "src/pfsense_mcp"
    module_path = production_root / "tier1/production_runtime.py"
    importers = []
    for path in production_root.rglob("*.py"):
        if path == module_path:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level and (node.module or "") == "production_runtime":
                importers.append(path.relative_to(root).as_posix())
            if (
                isinstance(node, ast.ImportFrom)
                and not node.level
                and (node.module or "") in {"pfsense_mcp.tier1.production_runtime", "tier1.production_runtime"}
            ):
                importers.append(path.relative_to(root).as_posix())
    assert importers == []
