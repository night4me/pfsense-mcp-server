"""ADR-037 Batch 1: adversarial + round-trip tests for the five new WRITE
capabilities (`NTP_TIME_SERVER_PREFER`, `NTP_SETTINGS_OBSERVABILITY_TOGGLES`,
`LOG_DISPLAY_PREFERENCES`, `LOG_RETENTION_SETTINGS`, `SYSTEM_TIMEZONE`) and
the shared `write_execution_core.py`/`write_adapter_support.py`
infrastructure they use.

Mirrors `test_alias_description_execution.py`'s fixture-construction
pattern (synthetic Ed25519 keypair, in-memory-on-disk SQLite contract
store, fake read/write clients, real `MutationExecutor`) rather than
mocking the executor -- every VERIFIED outcome below is produced by the
actual sealed executor, not a stand-in.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.log_settings import LogSettings
from pfsense_mcp.models.ntp_settings import NtpSettings
from pfsense_mcp.models.ntp_time_server import NtpTimeServer
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync
from pfsense_mcp.models.system_rest_api_settings import SystemRestApiSettings
from pfsense_mcp.models.system_timezone import SystemTimezone
from pfsense_mcp.security_authorization import (
    PlanAuthorizationStepBinding,
    build_plan_authorization_v2_payload,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import (
    ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS,
    ALIAS_DESCRIPTION_WRITE_STEP_ID,
    ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
    ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
    MILESTONE_9_WRITE_REQUIRED_RISK_CLASS,
    MILESTONE_9_WRITE_STEP_ID,
    MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
    MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
    AuthorizationLevel,
)
from pfsense_mcp.tier1.alias_description import ConfiguredApplianceTargetV1
from pfsense_mcp.tier1.authorization_consumption_store import AuthorizationConsumptionStore
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import BoundExecutionError, PreparedExecutionIntentError
from pfsense_mcp.tier1.executor import MutationExecutor
from pfsense_mcp.tier1.key_lifecycle import KeyPurpose, KeyRecord, NonceCounter
from pfsense_mcp.tier1.log_display_preferences import (
    ENDPOINT_SYMBOL as DISPLAY_ENDPOINT_SYMBOL,
)
from pfsense_mcp.tier1.log_display_preferences import (
    HTTP_METHOD as DISPLAY_HTTP_METHOD,
)
from pfsense_mcp.tier1.log_display_preferences import (
    LogDisplayPreferencesAdapterV1,
    LogDisplayPreferencesChangeV1,
    LogDisplayPreferencesPreparerV1,
    LogSettingsStateV1,
    PreparedLogDisplayPreferencesExecutionV1,
)
from pfsense_mcp.tier1.log_retention_settings import (
    ENDPOINT_SYMBOL as RETENTION_ENDPOINT_SYMBOL,
)
from pfsense_mcp.tier1.log_retention_settings import (
    HTTP_METHOD as RETENTION_HTTP_METHOD,
)
from pfsense_mcp.tier1.log_retention_settings import (
    LogRetentionSettingsAdapterV1,
    LogRetentionSettingsChangeV1,
    LogRetentionSettingsPreparerV1,
    PreparedLogRetentionSettingsExecutionV1,
)
from pfsense_mcp.tier1.ntp_settings_observability import (
    ENDPOINT_SYMBOL as OBS_ENDPOINT_SYMBOL,
)
from pfsense_mcp.tier1.ntp_settings_observability import (
    HTTP_METHOD as OBS_HTTP_METHOD,
)
from pfsense_mcp.tier1.ntp_settings_observability import (
    NtpSettingsObservabilityAdapterV1,
    NtpSettingsObservabilityChangeV1,
    NtpSettingsObservabilityPatchV1,
    NtpSettingsObservabilityPreparerV1,
    NtpSettingsStateV1,
    PreparedNtpSettingsObservabilityExecutionV1,
)
from pfsense_mcp.tier1.ntp_time_server_prefer import (
    ENDPOINT_SYMBOL as PREFER_ENDPOINT_SYMBOL,
)
from pfsense_mcp.tier1.ntp_time_server_prefer import (
    HTTP_METHOD as PREFER_HTTP_METHOD,
)
from pfsense_mcp.tier1.ntp_time_server_prefer import (
    NtpTimeServerPreferAdapterV1,
    NtpTimeServerPreferChangeV1,
    NtpTimeServerPreferPatchV1,
    NtpTimeServerPreferPreparerV1,
    NtpTimeServerStateV1,
    PreparedNtpTimeServerPreferExecutionV1,
)
from pfsense_mcp.tier1.policy import MutationPolicy, MutationRule
from pfsense_mcp.tier1.prepared_execution_intent import compute_execution_intent_digest
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.tier1.system_timezone_write import (
    ENDPOINT_SYMBOL as TZ_ENDPOINT_SYMBOL,
)
from pfsense_mcp.tier1.system_timezone_write import (
    HTTP_METHOD as TZ_HTTP_METHOD,
)
from pfsense_mcp.tier1.system_timezone_write import (
    PreparedSystemTimezoneExecutionV1,
    SystemTimezoneAdapterV1,
    SystemTimezoneChangeV1,
    SystemTimezonePatchV1,
    SystemTimezonePreparerV1,
)
from pfsense_mcp.tier1.transport_target import ResolvedTransportTarget
from pfsense_mcp.tier1.write_adapter_support import (
    SINGLETON_LOCATOR,
    fields_equal,
    fields_match,
    read_appliance_target_digest,
)
from pfsense_mcp.tier1.write_execution_core import WriteExecutionCoreV1
from pfsense_mcp.tls import TLSMode
from pfsense_mcp.transport.base import TransportResponse, TransportTimeoutError
from pfsense_mcp.write_endpoints import WriteEndpoints
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

NOW = datetime.now(timezone.utc).replace(microsecond=0)

FULL_LOG_SETTINGS: dict[str, Any] = {
    "format": "rfc3164",
    "reverseorder": False,
    "nentries": 50,
    "nologdefaultblock": False,
    "nologdefaultpass": False,
    "nologbogons": False,
    "nologprivatenets": False,
    "nolognginx": False,
    "rawfilter": False,
    "disablelocallogging": False,
    "logconfigchanges": True,
    "filterdescriptions": 1,
    "logfilesize": 500000,
    "rotatecount": 7,
    "logcompressiontype": "none",
    "enableremotelogging": False,
    "ipprotocol": None,
    "sourceip": None,
    "remoteserver": None,
    "remoteserver2": None,
    "remoteserver3": None,
    "logall": None,
    "filter": None,
    "dhcp": None,
    "auth": None,
    "portalauth": None,
    "vpn": None,
    "dpinger": None,
    "hostapd": None,
    "system": None,
    "resolver": None,
    "ppp": None,
    "routing": None,
    "ntpd": None,
}
FULL_NTP_SETTINGS: dict[str, Any] = {
    "clockstats": False,
    "dnsresolv": "auto",
    "enable": True,
    "interface": None,
    "leapsec": None,
    "logpeer": False,
    "logsys": False,
    "loopstats": False,
    "ntpmaxpeers": 10,
    "ntpmaxpoll": None,
    "ntpminpoll": None,
    "orphan": 12,
    "peerstats": False,
    "serverauth": False,
    "serverauthalgo": "md5",
    "statsgraph": False,
}


class _FakeClient:
    """One fake read/write client backing all five capabilities' state,
    plus pfSense's own global REST API Read Only setting -- mirrors
    `test_alias_description_execution.py::_ReadClient`'s shape."""

    def __init__(self) -> None:
        self.timezone = "America/New_York"
        self.log_settings = LogSettings(**FULL_LOG_SETTINGS)
        self.ntp_settings = NtpSettings(**FULL_NTP_SETTINGS)
        self.ntp_time_servers = [
            NtpTimeServer(id=0, noselect=False, prefer=False, timeserver="0.pool.ntp.org", type="server"),
            NtpTimeServer(id=1, noselect=False, prefer=False, timeserver="1.pool.ntp.org", type="server"),
        ]
        self.netgate_id: str | None = "netgate-synthetic"
        self.pfhostid: str | None = "pfhost-synthetic"
        self.pfrest_read_only = False

    def get_system_timezone(self) -> SystemTimezone:
        return SystemTimezone(timezone=self.timezone)

    def get_status_logs_settings(self) -> LogSettings:
        return self.log_settings

    def get_ntp_settings(self) -> NtpSettings:
        return self.ntp_settings

    def get_ntp_time_servers(self, *, limit: int = 100) -> list[NtpTimeServer]:
        return list(self.ntp_time_servers)

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus:
        assert include_identifying_metadata is True
        return SystemStatus(
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

    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync:
        assert include_identifying_metadata is True
        values = {name: False for name, field in SystemHaSync.model_fields.items() if field.annotation is bool}
        values.update(
            {
                "pfsyncinterface": "none",
                "pfsyncpeerip": None,
                "synchronizetoip": None,
                "pfhostid": self.pfhostid,
                "username": None,
            }
        )
        return SystemHaSync.model_validate(values)

    def get_system_restapi_settings(self, *, include_identifying_metadata: bool = False) -> SystemRestApiSettings:
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


class _FakeWriteClient:
    def __init__(self, client: _FakeClient, *, endpoint_symbol: str, http_method: str, applier) -> None:
        self.client = client
        self.endpoint_symbol = endpoint_symbol
        self.http_method = http_method
        self.applier = applier
        self.calls = 0
        self.fail_with: Exception | None = None

    def send_for_tier1(self, *, endpoint_symbol: str, http_method: str, body: bytes) -> TransportResponse:
        assert endpoint_symbol == self.endpoint_symbol
        assert http_method == self.http_method
        self.calls += 1
        if self.fail_with is not None:
            raise self.fail_with
        import json

        payload = json.loads(body)
        self.applier(self.client, payload)
        return TransportResponse(status_code=200, text="synthetic")


class _ConsumptionStore(AuthorizationConsumptionStore):
    def __init__(self) -> None:
        self.consumed: set[str] = set()

    def try_consume(self, authorization_id: str) -> bool:
        if authorization_id in self.consumed:
            return False
        self.consumed.add(authorization_id)
        return True


class _ConfirmationVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.algorithm == "synthetic-confirmation-v1" and evidence.proof == b"valid"


def _target() -> ConfiguredApplianceTargetV1:
    return ConfiguredApplianceTargetV1(base_url="https://pfsense.invalid", tls_mode=TLSMode.STRICT)


def _keypair() -> tuple[Ed25519PrivateKey, PinnedAuthoritySet]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, PinnedAuthoritySet((PinnedAuthority(authority_id="owner-v2", public_key=public),))


def _plan():
    return _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="batch1.step", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE
            ),
        )
    )


def _authorization(private: Ed25519PrivateKey, digest: str, **changes: object):
    values: dict[str, object] = {
        "plan": _plan(),
        "authorized_executions": (PlanAuthorizationStepBinding(step_id="batch1.step", execution_intent_digest=digest),),
        "authorization_id": "authz-v2-one",
        "authority_id": "owner-v2",
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=4),
    }
    values.update(changes)
    return sign_plan_authorization_v2(build_plan_authorization_v2_payload(**values), private)  # type: ignore[arg-type]


def _store(tmp_path: Path, name: str) -> SqliteRecoveryContractStore:
    tmp_path.mkdir(exist_ok=True)
    tmp_path.chmod(0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=b"i" * 32,
        store_id=name,
        clock=lambda: NOW,
        confirmation_verifier=_ConfirmationVerifier(),
    )


def _confirmation(contract) -> ConfirmationEvidence:
    return ConfirmationEvidence(
        authority_id="confirmation-owner",
        algorithm="synthetic-confirmation-v1",
        nonce="nonce-w1",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=NOW,
        proof=b"valid",
    )


def _core(
    tmp_path: Path,
    *,
    store: SqliteRecoveryContractStore,
    preparer,
    prepared_type: type,
    request_type: type,
    contract_id_prefix: str,
    raw_target_fn,
    executor,
) -> tuple[WriteExecutionCoreV1, Ed25519PrivateKey, SqliteRecoveryContractStore]:
    """`store` must be the SAME `SqliteRecoveryContractStore` instance
    `executor` was constructed with -- the execution core persists
    contracts into it via `authorize_and_create()`, and `MutationExecutor.
    execute()` loads them back out by contract_id; two independently
    constructed stores (even pointed at different on-disk files) would
    make every contract invisible to the executor, silently manifesting
    as a generic `BoundExecutionError` from `confirm_and_handoff()`'s own
    catch-all (never a confusing partial success)."""

    private, authorities = _keypair()
    counter = NonceCounter(tmp_path / "nonce.json", key_id="enc-w1")
    core = WriteExecutionCoreV1(
        request_type=request_type,
        prepared_type=prepared_type,
        contract_id_prefix=contract_id_prefix,
        raw_target_fn=raw_target_fn,
        preparer=preparer,
        authorities=authorities,
        consumption_store=_ConsumptionStore(),
        contract_store=store,
        executor=executor,
        encryption_key=KeyRecord("enc-w1", 0, b"e" * 32, KeyPurpose.ENCRYPTION),
        nonce_counter=counter,
    )
    return core, private, store


def _sealed_executor(
    store, client, write_client, capability: Capability, endpoint_symbol: str, http_method: str
) -> MutationExecutor:
    return MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=client,
        policy=MutationPolicy(frozenset({MutationRule(capability, endpoint_symbol, http_method)})),
        anti_rollback_anchor=None,
        encryption_key=b"e" * 32,
        clock=lambda: NOW,
    )


def _round_trip(core, private, request, prepared, executor, *, step_id: str = "batch1.step"):
    digest = compute_execution_intent_digest(prepared.intent)
    authorization = _authorization(private, digest)
    handle = core.authorize_and_create(
        request,
        authorized_preparation=prepared,
        authorization=authorization,
        requested_plan_digest=authorization.plan_digest,
        requested_step_id=step_id,
        required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        now=NOW,
    )
    return handle


# ---------------------------------------------------------------------------
# Generic aliases (security_plan.py additive constants)
# ---------------------------------------------------------------------------


def test_milestone_9_write_aliases_match_alias_description_originals():
    assert MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE is ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE
    assert MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE is ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE
    assert MILESTONE_9_WRITE_STEP_ID == ALIAS_DESCRIPTION_WRITE_STEP_ID
    assert MILESTONE_9_WRITE_REQUIRED_RISK_CLASS is ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS


# ---------------------------------------------------------------------------
# WriteEndpoints / allow-list
# ---------------------------------------------------------------------------


def test_write_endpoints_has_exactly_six_entries_all_new_ones_unverified():
    entries = set(WriteEndpoints.active_entries())
    assert entries == {
        "FIREWALL_ALIAS_DESCRIPTION",
        "NTP_TIME_SERVER_PREFER",
        "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
        "LOG_DISPLAY_PREFERENCES",
        "LOG_RETENTION_SETTINGS",
        "SYSTEM_TIMEZONE",
    }
    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified is True
    for name in (
        "NTP_TIME_SERVER_PREFER",
        "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
        "LOG_DISPLAY_PREFERENCES",
        "LOG_RETENTION_SETTINGS",
        "SYSTEM_TIMEZONE",
    ):
        info = getattr(WriteEndpoints, name)
        assert info.verified is False, f"{name} must not be verified=True without live LAB evidence"
        assert info.http_method == "PATCH"
        assert info.reversible is True
        assert info.dry_run_supported is True


def test_write_allow_list_check_reports_no_violations():
    # scripts/ is on sys.path for tests (see tests/test_write_allow_list_check.py,
    # which already exercises this module's own fail-closed behavior in
    # detail); this is a narrow additional check that the real WriteEndpoints
    # state produces zero violations after the Batch 1 expansion.
    import write_allow_list_check

    assert write_allow_list_check.find_allow_list_violations() == []


def test_write_allow_list_check_fails_closed_on_a_real_seventh_entry(monkeypatch):
    import write_allow_list_check

    from pfsense_mcp.api_version import ApiVersion
    from pfsense_mcp.write_endpoints import WriteEndpointInfo

    bogus = WriteEndpointInfo(
        path_suffix="/example",
        http_method="PATCH",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
    )
    monkeypatch.setattr(WriteEndpoints, "SEVENTH_BOGUS_ENTRY", bogus, raising=False)
    violations = write_allow_list_check.find_allow_list_violations()
    assert any("unexpected" in v and "SEVENTH_BOGUS_ENTRY" in v for v in violations)


# ---------------------------------------------------------------------------
# write_adapter_support.py
# ---------------------------------------------------------------------------


def test_singleton_locator_is_zero_and_valid_transport_locator():
    assert SINGLETON_LOCATOR == 0
    ResolvedTransportTarget(numeric_locator=SINGLETON_LOCATOR, target_identity_digest="a" * 64)


def test_fields_equal_and_fields_match():
    before = {"a": 1, "b": 2, "c": 3}
    after = {"a": 1, "b": 99, "c": 3}
    assert fields_equal(before, after, fields=("a", "c")) is True
    assert fields_equal(before, after, fields=("a", "b")) is False
    assert fields_match(after, {"b": 99}) is True
    assert fields_match(after, {"b": 2}) is False
    assert fields_match(after, {"missing": 1}) is False


def test_read_appliance_target_digest_matches_alias_algorithm():
    client = _FakeClient()
    target = _target()
    digest = read_appliance_target_digest(client, target)
    assert isinstance(digest, str) and len(digest) == 64
    client.netgate_id = None
    digest2 = read_appliance_target_digest(client, target)
    assert digest2 != digest
    client.pfhostid = None
    with pytest.raises(PreparedExecutionIntentError, match="unavailable"):
        read_appliance_target_digest(client, target)


# ---------------------------------------------------------------------------
# NTP_TIME_SERVER_PREFER
# ---------------------------------------------------------------------------


def test_ntp_prefer_request_is_exactly_two_fields():
    request = NtpTimeServerPreferChangeV1(timeserver="0.pool.ntp.org", prefer=True)
    assert request.model_dump() == {"timeserver": "0.pool.ntp.org", "prefer": True}
    with pytest.raises(ValidationError):
        NtpTimeServerPreferChangeV1(timeserver="0.pool.ntp.org", prefer=True, id=0)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        NtpTimeServerPreferChangeV1(timeserver="", prefer=True)


@pytest.mark.parametrize("mode", ["missing", "duplicate", "malformed"])
def test_ntp_prefer_refuses_ambiguous_or_malformed_target(mode: str):
    client = _FakeClient()
    if mode == "missing":
        client.ntp_time_servers = []
    elif mode == "duplicate":
        client.ntp_time_servers.append(client.ntp_time_servers[0].model_copy())
    else:
        client.ntp_time_servers[0] = client.ntp_time_servers[0].model_copy(update={"type": "bogus"})
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_target())
    with pytest.raises(PreparedExecutionIntentError):
        preparer.prepare(NtpTimeServerPreferChangeV1(timeserver="0.pool.ntp.org", prefer=True))


def test_ntp_prefer_no_op_rejected():
    client = _FakeClient()
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_target())
    with pytest.raises(PreparedExecutionIntentError, match="no-op"):
        preparer.prepare(NtpTimeServerPreferChangeV1(timeserver="0.pool.ntp.org", prefer=False))


def test_ntp_prefer_build_request_is_exact_projection():
    client = _FakeClient()
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_target())
    prepared = preparer.prepare(NtpTimeServerPreferChangeV1(timeserver="1.pool.ntp.org", prefer=True))
    patch = NtpTimeServerPreferAdapterV1().build_request(
        prepared.intent.normalized_mutation_intent,
        ResolvedTransportTarget(numeric_locator=1, target_identity_digest="a" * 64),
    )
    assert patch == NtpTimeServerPreferPatchV1(id=1, prefer=True)
    assert set(patch.model_dump()) == {"id", "prefer"}


def test_ntp_prefer_semantic_verification_detects_unrelated_field_drift():
    adapter = NtpTimeServerPreferAdapterV1()
    before = NtpTimeServerStateV1(1, "1.pool.ntp.org", "server", False, False)
    after_ok = NtpTimeServerStateV1(1, "1.pool.ntp.org", "server", True, False)
    after_drift = NtpTimeServerStateV1(1, "1.pool.ntp.org", "server", True, True)  # noselect drifted
    intent = {
        "operation": "set_ntp_time_server_prefer_v1",
        "raw_target_hint": {"timeserver": "1.pool.ntp.org"},
        "prefer": True,
        "appliance_target_digest": "a" * 64,
    }
    assert adapter.is_semantically_verified(before, after_ok, intent) is True
    assert adapter.is_semantically_verified(before, after_drift, intent) is False


def test_ntp_prefer_full_round_trip_via_real_executor(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()

    def apply(c: _FakeClient, payload: dict) -> None:
        for i, s in enumerate(c.ntp_time_servers):
            if s.id == payload["id"]:
                c.ntp_time_servers[i] = s.model_copy(update={"prefer": payload["prefer"]})

    write_client = _FakeWriteClient(
        client, endpoint_symbol=PREFER_ENDPOINT_SYMBOL, http_method=PREFER_HTTP_METHOD, applier=apply
    )
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "ntp-prefer")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.NTP_TIME_SERVER_PREFER_WRITE,
        PREFER_ENDPOINT_SYMBOL,
        PREFER_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedNtpTimeServerPreferExecutionV1,
        request_type=NtpTimeServerPreferChangeV1,
        contract_id_prefix="ntppref",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = NtpTimeServerPreferChangeV1(timeserver="1.pool.ntp.org", prefer=True)
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    outcome = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert outcome.state is RecoveryState.VERIFIED
    assert client.ntp_time_servers[1].prefer is True
    assert client.ntp_time_servers[0].prefer is False


def test_ntp_prefer_pfrest_read_only_blocks_execution(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()
    client.pfrest_read_only = True

    def apply(c, payload):
        raise AssertionError("must never be called while pfREST Read Only is true")

    write_client = _FakeWriteClient(
        client, endpoint_symbol=PREFER_ENDPOINT_SYMBOL, http_method=PREFER_HTTP_METHOD, applier=apply
    )
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "ntp-prefer-ro")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.NTP_TIME_SERVER_PREFER_WRITE,
        PREFER_ENDPOINT_SYMBOL,
        PREFER_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedNtpTimeServerPreferExecutionV1,
        request_type=NtpTimeServerPreferChangeV1,
        contract_id_prefix="ntppref",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = NtpTimeServerPreferChangeV1(timeserver="0.pool.ntp.org", prefer=True)
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    # confirm_and_handoff() wraps executor.execute() in a catch-all that
    # converts every exception -- including the real GlobalReadOnlyBlockedError
    # MutationExecutor._require_pfrest_writable() raises -- into the same
    # uniform BoundExecutionError every other denial produces (the
    # "never leaked which check failed" discipline
    # AliasDescriptionExecutionCoreV1.confirm_and_handoff() already
    # establishes and this generic core reproduces verbatim). The write
    # applier's own AssertionError-if-called guard is what actually proves
    # no send reached pfSense.
    with pytest.raises(BoundExecutionError):
        core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)


def test_ntp_prefer_ambiguous_transport_outcome_on_timeout(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()
    write_client = _FakeWriteClient(
        client, endpoint_symbol=PREFER_ENDPOINT_SYMBOL, http_method=PREFER_HTTP_METHOD, applier=lambda c, p: None
    )
    write_client.fail_with = TransportTimeoutError("synthetic timeout")
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "ntp-prefer-to")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.NTP_TIME_SERVER_PREFER_WRITE,
        PREFER_ENDPOINT_SYMBOL,
        PREFER_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedNtpTimeServerPreferExecutionV1,
        request_type=NtpTimeServerPreferChangeV1,
        contract_id_prefix="ntppref",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = NtpTimeServerPreferChangeV1(timeserver="0.pool.ntp.org", prefer=True)
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    outcome = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert outcome.state is RecoveryState.RECONCILIATION


def test_ntp_prefer_success_response_but_no_actual_state_change_is_not_verified(tmp_path: Path, monkeypatch):
    """HTTP success with semantic postcondition failure: the write client
    reports 200 but never actually mutates the backing state -- proves the
    executor never trusts HTTP status alone."""

    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()
    write_client = _FakeWriteClient(
        client, endpoint_symbol=PREFER_ENDPOINT_SYMBOL, http_method=PREFER_HTTP_METHOD, applier=lambda c, p: None
    )
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "ntp-prefer-noop-response")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.NTP_TIME_SERVER_PREFER_WRITE,
        PREFER_ENDPOINT_SYMBOL,
        PREFER_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedNtpTimeServerPreferExecutionV1,
        request_type=NtpTimeServerPreferChangeV1,
        contract_id_prefix="ntppref",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = NtpTimeServerPreferChangeV1(timeserver="0.pool.ntp.org", prefer=True)
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    outcome = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert outcome.state is not RecoveryState.VERIFIED


# ---------------------------------------------------------------------------
# NTP_SETTINGS_OBSERVABILITY_TOGGLES
# ---------------------------------------------------------------------------


def test_ntp_observability_request_rejects_extra_fields():
    with pytest.raises(ValidationError):
        NtpSettingsObservabilityChangeV1(
            logpeer=True,
            logsys=True,
            clockstats=True,
            loopstats=True,
            peerstats=True,
            statsgraph=True,
            enable=True,  # type: ignore[call-arg]
        )


def test_ntp_observability_no_op_rejected():
    client = _FakeClient()
    preparer = NtpSettingsObservabilityPreparerV1(read_client=client, configured_target=_target())
    current = client.ntp_settings
    request = NtpSettingsObservabilityChangeV1(
        logpeer=current.logpeer,
        logsys=current.logsys,
        clockstats=current.clockstats,
        loopstats=current.loopstats,
        peerstats=current.peerstats,
        statsgraph=current.statsgraph,
    )
    with pytest.raises(PreparedExecutionIntentError, match="no-op"):
        preparer.prepare(request)


def test_ntp_observability_build_request_excludes_secret_and_service_fields():
    client = _FakeClient()
    preparer = NtpSettingsObservabilityPreparerV1(read_client=client, configured_target=_target())
    request = NtpSettingsObservabilityChangeV1(
        logpeer=True, logsys=True, clockstats=False, loopstats=False, peerstats=True, statsgraph=False
    )
    prepared = preparer.prepare(request)
    patch = NtpSettingsObservabilityAdapterV1().build_request(
        prepared.intent.normalized_mutation_intent,
        ResolvedTransportTarget(numeric_locator=SINGLETON_LOCATOR, target_identity_digest="a" * 64),
    )
    assert isinstance(patch, NtpSettingsObservabilityPatchV1)
    dumped = patch.model_dump()
    assert set(dumped) == {"logpeer", "logsys", "clockstats", "loopstats", "peerstats", "statsgraph"}
    assert "enable" not in dumped and "serverauth" not in dumped and "serverauthkey" not in dumped


def test_ntp_observability_verification_detects_forbidden_field_drift():
    adapter = NtpSettingsObservabilityAdapterV1()
    pre = NtpSettingsStateV1.from_model(NtpSettings(**FULL_NTP_SETTINGS))
    post_ok = NtpSettingsStateV1.from_model(NtpSettings(**{**FULL_NTP_SETTINGS, "logpeer": True}))
    post_drift = NtpSettingsStateV1.from_model(NtpSettings(**{**FULL_NTP_SETTINGS, "logpeer": True, "enable": False}))
    intent = {
        "operation": "set_ntp_settings_observability_v1",
        "raw_target_hint": {"resource": "ntp_settings"},
        "appliance_target_digest": "a" * 64,
        "logpeer": True,
        "logsys": False,
        "clockstats": False,
        "loopstats": False,
        "peerstats": False,
        "statsgraph": False,
    }
    assert adapter.is_semantically_verified(pre, post_ok, intent) is True
    assert adapter.is_semantically_verified(pre, post_drift, intent) is False


def test_ntp_observability_full_round_trip_via_real_executor(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()

    def apply(c: _FakeClient, payload: dict) -> None:
        c.ntp_settings = c.ntp_settings.model_copy(update=payload)

    write_client = _FakeWriteClient(
        client, endpoint_symbol=OBS_ENDPOINT_SYMBOL, http_method=OBS_HTTP_METHOD, applier=apply
    )
    preparer = NtpSettingsObservabilityPreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "ntp-obs")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.NTP_SETTINGS_OBSERVABILITY_WRITE,
        OBS_ENDPOINT_SYMBOL,
        OBS_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedNtpSettingsObservabilityExecutionV1,
        request_type=NtpSettingsObservabilityChangeV1,
        contract_id_prefix="ntpobs",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = NtpSettingsObservabilityChangeV1(
        logpeer=True, logsys=True, clockstats=False, loopstats=False, peerstats=True, statsgraph=False
    )
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    outcome = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert outcome.state is RecoveryState.VERIFIED
    assert client.ntp_settings.logpeer is True
    assert client.ntp_settings.peerstats is True
    assert client.ntp_settings.enable is True  # untouched
    assert client.ntp_settings.ntpmaxpeers == 10  # untouched


# ---------------------------------------------------------------------------
# LOG_DISPLAY_PREFERENCES / LOG_RETENTION_SETTINGS (shared endpoint)
# ---------------------------------------------------------------------------


def test_log_display_and_retention_field_projections_are_disjoint():
    from pfsense_mcp.tier1.log_display_preferences import _ALLOWED_FIELDS as DISPLAY_FIELDS
    from pfsense_mcp.tier1.log_retention_settings import _ALLOWED_FIELDS as RETENTION_FIELDS

    assert set(DISPLAY_FIELDS).isdisjoint(RETENTION_FIELDS)


def test_log_display_no_op_rejected():
    client = _FakeClient()
    preparer = LogDisplayPreferencesPreparerV1(read_client=client, configured_target=_target())
    current = client.log_settings
    request = LogDisplayPreferencesChangeV1(
        format=current.format,
        reverseorder=current.reverseorder,
        nentries=current.nentries,
        filterdescriptions=current.filterdescriptions,
        rawfilter=current.rawfilter,
    )
    with pytest.raises(PreparedExecutionIntentError, match="no-op"):
        preparer.prepare(request)


def test_log_retention_no_op_rejected():
    client = _FakeClient()
    preparer = LogRetentionSettingsPreparerV1(read_client=client, configured_target=_target())
    current = client.log_settings
    request = LogRetentionSettingsChangeV1(
        logfilesize=current.logfilesize, rotatecount=current.rotatecount, logcompressiontype=current.logcompressiontype
    )
    with pytest.raises(PreparedExecutionIntentError, match="no-op"):
        preparer.prepare(request)


def test_log_display_cannot_mutate_retention_fields_and_vice_versa():
    """Cross-capability isolation: proves neither adapter's
    `is_semantically_verified()` can be satisfied by a change to the
    OTHER capability's fields."""

    display_adapter = LogDisplayPreferencesAdapterV1()
    retention_adapter = LogRetentionSettingsAdapterV1()
    pre = LogSettingsStateV1.from_model(LogSettings(**FULL_LOG_SETTINGS))
    # Only a retention field changed -- the display capability's intent
    # (requesting no display-field change beyond current values) must
    # fail because fields_match requires the exact requested values, and
    # more importantly this proves retention drift alone doesn't
    # satisfy a display-intent postcondition path either way: build an
    # explicit display intent and confirm a retention-only mutation
    # does not verify it.
    post_retention_only = LogSettingsStateV1.from_model(LogSettings(**{**FULL_LOG_SETTINGS, "logfilesize": 999999}))
    display_intent = {
        "operation": "set_log_display_preferences_v1",
        "raw_target_hint": {"resource": "status_logs_settings"},
        "appliance_target_digest": "a" * 64,
        "format": "rfc5424",
        "reverseorder": True,
        "nentries": 100,
        "filterdescriptions": 2,
        "rawfilter": True,
    }
    assert display_adapter.is_semantically_verified(pre, post_retention_only, display_intent) is False

    post_display_only = LogSettingsStateV1.from_model(LogSettings(**{**FULL_LOG_SETTINGS, "format": "rfc5424"}))
    retention_intent = {
        "operation": "set_log_retention_settings_v1",
        "raw_target_hint": {"resource": "status_logs_settings"},
        "appliance_target_digest": "a" * 64,
        "logfilesize": 999999,
        "rotatecount": 14,
        "logcompressiontype": "gzip",
    }
    assert retention_adapter.is_semantically_verified(pre, post_display_only, retention_intent) is False


def test_log_display_full_round_trip_leaves_retention_fields_untouched(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()

    def apply(c: _FakeClient, payload: dict) -> None:
        c.log_settings = c.log_settings.model_copy(update=payload)

    write_client = _FakeWriteClient(
        client, endpoint_symbol=DISPLAY_ENDPOINT_SYMBOL, http_method=DISPLAY_HTTP_METHOD, applier=apply
    )
    preparer = LogDisplayPreferencesPreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "log-disp")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.LOG_DISPLAY_PREFERENCES_WRITE,
        DISPLAY_ENDPOINT_SYMBOL,
        DISPLAY_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedLogDisplayPreferencesExecutionV1,
        request_type=LogDisplayPreferencesChangeV1,
        contract_id_prefix="logdisp",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = LogDisplayPreferencesChangeV1(
        format="rfc5424", reverseorder=True, nentries=100, filterdescriptions=2, rawfilter=True
    )
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    outcome = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert outcome.state is RecoveryState.VERIFIED
    assert client.log_settings.format == "rfc5424"
    assert client.log_settings.logfilesize == FULL_LOG_SETTINGS["logfilesize"]
    assert client.log_settings.rotatecount == FULL_LOG_SETTINGS["rotatecount"]
    assert client.log_settings.logconfigchanges == FULL_LOG_SETTINGS["logconfigchanges"]


def test_log_retention_full_round_trip_leaves_display_fields_untouched(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()

    def apply(c: _FakeClient, payload: dict) -> None:
        c.log_settings = c.log_settings.model_copy(update=payload)

    write_client = _FakeWriteClient(
        client, endpoint_symbol=RETENTION_ENDPOINT_SYMBOL, http_method=RETENTION_HTTP_METHOD, applier=apply
    )
    preparer = LogRetentionSettingsPreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "log-ret")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.LOG_RETENTION_SETTINGS_WRITE,
        RETENTION_ENDPOINT_SYMBOL,
        RETENTION_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedLogRetentionSettingsExecutionV1,
        request_type=LogRetentionSettingsChangeV1,
        contract_id_prefix="logret",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = LogRetentionSettingsChangeV1(logfilesize=999999, rotatecount=14, logcompressiontype="gzip")
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    outcome = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert outcome.state is RecoveryState.VERIFIED
    assert client.log_settings.logfilesize == 999999
    assert client.log_settings.format == FULL_LOG_SETTINGS["format"]
    assert client.log_settings.nologdefaultblock == FULL_LOG_SETTINGS["nologdefaultblock"]


# ---------------------------------------------------------------------------
# SYSTEM_TIMEZONE
# ---------------------------------------------------------------------------


def test_system_timezone_request_rejects_extra_fields_and_bad_values():
    SystemTimezoneChangeV1(timezone="Europe/Berlin")
    with pytest.raises(ValidationError):
        SystemTimezoneChangeV1(timezone="Europe/Berlin", id=0)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        SystemTimezoneChangeV1(timezone="bad tz with spaces!")


def test_system_timezone_no_op_rejected():
    client = _FakeClient()
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_target())
    with pytest.raises(PreparedExecutionIntentError, match="no-op"):
        preparer.prepare(SystemTimezoneChangeV1(timezone=client.timezone))


def test_system_timezone_build_request_exact_projection():
    client = _FakeClient()
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_target())
    prepared = preparer.prepare(SystemTimezoneChangeV1(timezone="Europe/Berlin"))
    patch = SystemTimezoneAdapterV1().build_request(
        prepared.intent.normalized_mutation_intent,
        ResolvedTransportTarget(numeric_locator=SINGLETON_LOCATOR, target_identity_digest="a" * 64),
    )
    assert patch == SystemTimezonePatchV1(timezone="Europe/Berlin")
    assert set(patch.model_dump()) == {"timezone"}


def test_system_timezone_full_round_trip_via_real_executor(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()

    def apply(c: _FakeClient, payload: dict) -> None:
        c.timezone = payload["timezone"]

    write_client = _FakeWriteClient(
        client, endpoint_symbol=TZ_ENDPOINT_SYMBOL, http_method=TZ_HTTP_METHOD, applier=apply
    )
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "tz")
    executor = _sealed_executor(
        store, client, write_client, Capability.SYSTEM_TIMEZONE_WRITE, TZ_ENDPOINT_SYMBOL, TZ_HTTP_METHOD
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="systz",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    outcome = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert outcome.state is RecoveryState.VERIFIED
    assert client.timezone == "Europe/Berlin"


def test_system_timezone_pfrest_read_only_unreadable_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()

    def broken_restapi_settings(*, include_identifying_metadata: bool = False):
        raise RuntimeError("synthetic read failure")

    client.get_system_restapi_settings = broken_restapi_settings  # type: ignore[method-assign]
    write_client = _FakeWriteClient(
        client, endpoint_symbol=TZ_ENDPOINT_SYMBOL, http_method=TZ_HTTP_METHOD, applier=lambda c, p: None
    )
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "tz-ro-unreadable")
    executor = _sealed_executor(
        store,
        client,
        write_client,
        Capability.SYSTEM_TIMEZONE_WRITE,
        TZ_ENDPOINT_SYMBOL,
        TZ_HTTP_METHOD,
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="systz",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    # Read the timezone BEFORE breaking get_system_restapi_settings would
    # have been needed for prepare() too, but prepare() never calls that
    # method -- only execute() does, right before the EXECUTING
    # transition -- so preparation itself must still succeed here.
    request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    # See test_ntp_prefer_pfrest_read_only_blocks_execution's comment: the
    # real GlobalReadOnlyBlockedError is converted to the uniform
    # BoundExecutionError by confirm_and_handoff()'s own catch-all.
    with pytest.raises(BoundExecutionError):
        core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert write_client.calls == 0


# ---------------------------------------------------------------------------
# Authorization / confirmation failure paths (generic gate, proven once
# against a representative capability -- the gate logic itself is shared,
# identical code for all five; see write_execution_core.py's own docstring
# for why this is safe to prove once rather than five times).
# ---------------------------------------------------------------------------


def test_wrong_authority_signature_is_refused(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()
    write_client = _FakeWriteClient(
        client, endpoint_symbol=TZ_ENDPOINT_SYMBOL, http_method=TZ_HTTP_METHOD, applier=lambda c, p: None
    )
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "tz-badauth")
    executor = _sealed_executor(
        store, client, write_client, Capability.SYSTEM_TIMEZONE_WRITE, TZ_ENDPOINT_SYMBOL, TZ_HTTP_METHOD
    )
    core, _private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="systz",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    prepared = preparer.prepare(request)
    digest = compute_execution_intent_digest(prepared.intent)
    other_private = Ed25519PrivateKey.generate()
    forged = _authorization(other_private, digest)
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


def test_wrong_confirmation_authority_is_refused(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()
    write_client = _FakeWriteClient(
        client, endpoint_symbol=TZ_ENDPOINT_SYMBOL, http_method=TZ_HTTP_METHOD, applier=lambda c, p: None
    )
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "tz-badconf")
    executor = _sealed_executor(
        store, client, write_client, Capability.SYSTEM_TIMEZONE_WRITE, TZ_ENDPOINT_SYMBOL, TZ_HTTP_METHOD
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="systz",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    prepared = preparer.prepare(request)
    handle = _round_trip(core, private, request, prepared, executor)
    contract = store.load(handle.contract_id)
    bad_confirmation = ConfirmationEvidence(
        authority_id="confirmation-owner",
        algorithm="synthetic-confirmation-v1",
        nonce="nonce-w1",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=NOW,
        proof=b"WRONG",
    )
    with pytest.raises(BoundExecutionError):
        core.confirm_and_handoff(handle, confirmation=bad_confirmation, now=NOW)


def test_precondition_drift_between_prepare_and_authorize_is_refused(tmp_path: Path, monkeypatch):
    """Fresh re-preparation inside `authorize_and_create()` must catch a
    target that changed after the caller's own `prepare()` call but
    before authorization completes."""

    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()
    write_client = _FakeWriteClient(
        client, endpoint_symbol=TZ_ENDPOINT_SYMBOL, http_method=TZ_HTTP_METHOD, applier=lambda c, p: None
    )
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_target())
    store = _store(tmp_path, "tz-drift")
    executor = _sealed_executor(
        store, client, write_client, Capability.SYSTEM_TIMEZONE_WRITE, TZ_ENDPOINT_SYMBOL, TZ_HTTP_METHOD
    )
    core, private, store = _core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="systz",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    prepared = preparer.prepare(request)
    digest = compute_execution_intent_digest(prepared.intent)
    authorization = _authorization(private, digest)
    client.timezone = "Asia/Tokyo"  # drift: someone else changed it out-of-band
    with pytest.raises(BoundExecutionError):
        core.authorize_and_create(
            request,
            authorized_preparation=prepared,
            authorization=authorization,
            requested_plan_digest=authorization.plan_digest,
            requested_step_id="batch1.step",
            required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            now=NOW,
        )


# ---------------------------------------------------------------------------
# Default reachability
# ---------------------------------------------------------------------------


def test_no_new_capability_module_is_imported_outside_tier1():
    """Default-reachable WRITE must remain 0: none of the five new
    capability modules are imported by any tool/registry/production-runtime
    module -- mirrors the same static-reachability property the alias
    capability's own W1 phase had before W2/W3 wired it up."""

    import pathlib
    import re

    new_modules = (
        "ntp_time_server_prefer",
        "ntp_settings_observability",
        "log_display_preferences",
        "log_retention_settings",
        "system_timezone_write",
        "write_execution_core",
        "write_adapter_support",
    )
    src_root = pathlib.Path(__file__).resolve().parents[2] / "src" / "pfsense_mcp"
    pattern = re.compile("|".join(re.escape(m) for m in new_modules))
    offenders = []
    for path in src_root.rglob("*.py"):
        if "tier1" in path.parts:
            continue
        text = path.read_text()
        if pattern.search(text):
            offenders.append(str(path))
    assert offenders == [], f"new tier1 modules must not be imported outside tier1/: {offenders}"
