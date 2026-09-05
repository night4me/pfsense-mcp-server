"""2026-09-05 owner-directed retry/idempotency redesign -- Slice 2
(execution-core wiring). Proves `WriteExecutionCoreV1`/
`AliasDescriptionExecutionCoreV1.authorize_and_create()`'s new
pre-consumption active-idempotency preflight and the retry rule it
enables:

    A terminal historical contract does NOT itself authorize a retry.
    A retry is permitted only when (1) no currently blocking contract
    exists for the semantic idempotency_key, (2) the historical attempt is
    in a state permitting coexistence (FAILED/ROLLED_BACK/EXPIRED), and
    (3) the caller presents a genuinely fresh, unconsumed, valid
    authorization for the identical semantic intent.

Every store here is a fresh `tmp_path` fixture reusing
`test_alias_description_execution.py`'s own established fixtures
(`_core`, `_authorize`, `_authorization`, `_preparer`, `_ReadClient`) --
nothing in this file ever opens a real alias/Batch1 production store, and
no signer ceremony, live LAB, or pfSense contact is ever involved.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.alias_description import AliasDescriptionChangeV1
from pfsense_mcp.tier1.alias_description_execution import AliasDescriptionExecutionCoreV1
from pfsense_mcp.tier1.errors import BoundExecutionError
from pfsense_mcp.tier1.prepared_execution_intent import compute_execution_intent_digest
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.write_execution_core import WriteExecutionCoreV1
from tests.tier1.test_adr037_batch1_write_capabilities import (
    NOW as TZ_NOW,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    PREFER_ENDPOINT_SYMBOL,
    PREFER_HTTP_METHOD,
    NtpTimeServerPreferChangeV1,
    NtpTimeServerPreferPreparerV1,
    PreparedNtpTimeServerPreferExecutionV1,
    _FakeClient,
    _FakeWriteClient,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _authorization as _tz_authorization,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _core as _tz_core,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _sealed_executor as _tz_sealed_executor,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _store as _tz_store,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _target as _tz_target,
)
from tests.tier1.test_alias_description_execution import (
    NOW,
    _authorization,
    _authorize,
    _core,
    _preparer,
    _ReadClient,
)


@pytest.fixture(autouse=True)
def _fresh_plan_always(monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))


def _fail_prepared(store, contract_id):
    """PREPARED -> FAILED needs no confirmation (see state_machine.py's
    own LEGAL_TRANSITIONS) -- the same technique
    test_alias_description_execution.py's own
    test_resume_prepared_negative_cases_refuse_closed already uses to
    manufacture a non-PREPARED historical contract for test setup."""

    return store.transition(
        contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=store.load(contract_id).state_version,
        target_state=RecoveryState.FAILED,
    )


def _request() -> AliasDescriptionChangeV1:
    return AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")


# ---------------------------------------------------------------------------
# Positive path: historical terminal attempt + no blocking attempt + fresh
# authorization -> fresh RecoveryContract
# ---------------------------------------------------------------------------


def test_fresh_authorization_creates_new_contract_after_historical_failure(tmp_path, monkeypatch):
    client = _ReadClient()
    core, private, store, consumption, _executor = _core(tmp_path, client)
    request = _request()
    prepared = _preparer(client).prepare(request)

    first_authz = _authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-first"
    )
    first = _authorize(core, private, request, prepared, authz=first_authz)
    _fail_prepared(store, first.contract_id)

    second_authz = _authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-second"
    )
    second = _authorize(core, private, request, prepared, authz=second_authz)

    assert second.contract_id != first.contract_id
    first_contract = store.load(first.contract_id)
    second_contract = store.load(second.contract_id)

    assert first_contract.state is RecoveryState.FAILED
    assert second_contract.state is RecoveryState.PREPARED
    assert first_contract.idempotency_key == second_contract.idempotency_key
    assert first_contract.operation_id != second_contract.operation_id
    assert first_contract.authorization_provenance.authorization_id == "authz-first"
    assert second_contract.authorization_provenance.authorization_id == "authz-second"

    # the historical contract's own row and audit trail are untouched
    assert store.load(first.contract_id) == first_contract
    assert len(store.audit_events(first.contract_id)) >= 1

    # both authorizations were consumed exactly once, each on its own attempt
    assert "authz-first" in consumption.consumed
    assert "authz-second" in consumption.consumed

    assert store.find_by_idempotency_key(first_contract.idempotency_key).contract_id == second.contract_id
    history = store.find_historical_by_idempotency_key(first_contract.idempotency_key)
    assert {c.contract_id for c in history} == {first.contract_id, second.contract_id}


# ---------------------------------------------------------------------------
# Negative 1: terminal history + stale (already-consumed) authorization
# ---------------------------------------------------------------------------


def test_stale_authorization_reused_after_historical_failure_is_refused(tmp_path, monkeypatch):
    client = _ReadClient()
    core, private, store, consumption, _executor = _core(tmp_path, client)
    request = _request()
    prepared = _preparer(client).prepare(request)

    authz = _authorization(private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-stale")
    first = _authorize(core, private, request, prepared, authz=authz)
    _fail_prepared(store, first.contract_id)

    calls_before = consumption.calls
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=authz)  # the SAME, already-consumed artifact
    # find_by_idempotency_key() alone would not have refused this (FAILED
    # is permitted history) -- the pre-existing one-shot consumption
    # store is what still catches it here, exactly as the owner's design
    # says it must ("the durable consumption store remains the
    # authoritative one-shot guard").
    assert consumption.calls == calls_before + 1
    assert tuple(c.contract_id for c in store.all_contracts()) == (first.contract_id,)


# ---------------------------------------------------------------------------
# Negative 2: terminal history + expired (but never-before-seen) authorization
# ---------------------------------------------------------------------------


def test_expired_fresh_authorization_after_historical_failure_is_refused_before_consumption(tmp_path, monkeypatch):
    client = _ReadClient()
    core, private, store, consumption, _executor = _core(tmp_path, client)
    request = _request()
    prepared = _preparer(client).prepare(request)

    first_authz = _authorization(private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-a")
    first = _authorize(core, private, request, prepared, authz=first_authz)
    _fail_prepared(store, first.contract_id)

    expired_authz = _authorization(
        private,
        compute_execution_intent_digest(prepared.intent),
        authorization_id="authz-expired-fresh",
        issued_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=5),
    )
    calls_before = consumption.calls
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=expired_authz)
    # refused by the pre-existing issued_at/expires_at window check, before
    # ever reaching try_consume() -- unrelated to and unaffected by the new
    # preflight (which only looks at blocking contracts, not authorization
    # freshness).
    assert consumption.calls == calls_before
    assert "authz-expired-fresh" not in consumption.consumed
    assert tuple(c.contract_id for c in store.all_contracts()) == (first.contract_id,)


# ---------------------------------------------------------------------------
# Negative 3: blocking history (still PREPARED) + fresh authorization
# ---------------------------------------------------------------------------


def test_fresh_authorization_is_refused_while_a_blocking_contract_exists(tmp_path, monkeypatch):
    client = _ReadClient()
    core, private, store, consumption, _executor = _core(tmp_path, client)
    request = _request()
    prepared = _preparer(client).prepare(request)

    first_authz = _authorization(private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-a")
    first = _authorize(core, private, request, prepared, authz=first_authz)
    assert store.load(first.contract_id).state is RecoveryState.PREPARED  # still blocking -- never failed/expired

    second_authz = _authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-b"
    )
    calls_before = consumption.calls
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=second_authz)
    # the new preflight refuses this BEFORE try_consume() is ever reached
    assert consumption.calls == calls_before
    assert "authz-b" not in consumption.consumed
    assert tuple(c.contract_id for c in store.all_contracts()) == (first.contract_id,)


# ---------------------------------------------------------------------------
# Negative 4: concurrent fresh retry race -- preflight cannot see an
# in-flight sibling attempt; the DB partial unique index remains the
# authoritative guard, and a valid fresh authorization can be burned by a
# losing race (documented, not eliminated, per the owner's explicit
# instruction not to pretend otherwise).
# ---------------------------------------------------------------------------


def test_concurrent_fresh_retries_race_at_the_store_not_the_preflight(tmp_path, monkeypatch):
    client = _ReadClient()
    core, private, store, consumption, _executor = _core(tmp_path, client)
    request = _request()
    prepared = _preparer(client).prepare(request)

    first_authz = _authorization(private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-a")
    first = _authorize(core, private, request, prepared, authz=first_authz)
    _fail_prepared(store, first.contract_id)

    # Simulate the race window: both racing callers' preflight reads
    # observe "no blocking contract" (true at the instant each checks),
    # so neither is refused by find_by_idempotency_key() -- only the
    # store's own INSERT-time partial unique index can still tell them
    # apart.
    monkeypatch.setattr(store, "find_by_idempotency_key", lambda _key: None)

    racer_1 = _authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-racer-1"
    )
    racer_2 = _authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-racer-2"
    )

    winner = _authorize(core, private, request, prepared, authz=racer_1)
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=racer_2)

    # the losing racer's authorization is burned uselessly -- a known,
    # documented reliability gap (try_consume() precedes create_authorized()
    # in authorize_and_create()'s own gate ordering), not silently fixed here
    assert "authz-racer-1" in consumption.consumed
    assert "authz-racer-2" in consumption.consumed
    assert {c.contract_id for c in store.all_contracts()} == {first.contract_id, winner.contract_id}


# ---------------------------------------------------------------------------
# Negative/positive 5: multiple terminal historical rows + one fresh
# authorization -> still exactly one fresh retry succeeds
# ---------------------------------------------------------------------------


def test_multiple_terminal_historical_attempts_still_allow_exactly_one_fresh_retry(tmp_path, monkeypatch):
    client = _ReadClient()
    core, private, store, consumption, _executor = _core(tmp_path, client)
    request = _request()
    prepared = _preparer(client).prepare(request)

    first_authz = _authorization(private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-1")
    first = _authorize(core, private, request, prepared, authz=first_authz)
    _fail_prepared(store, first.contract_id)

    second_authz = _authorization(private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-2")
    second = _authorize(core, private, request, prepared, authz=second_authz)
    _fail_prepared(store, second.contract_id)

    third_authz = _authorization(private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-3")
    third = _authorize(core, private, request, prepared, authz=third_authz)

    assert len({first.contract_id, second.contract_id, third.contract_id}) == 3
    assert store.load(first.contract_id).state is RecoveryState.FAILED
    assert store.load(second.contract_id).state is RecoveryState.FAILED
    assert store.load(third.contract_id).state is RecoveryState.PREPARED

    idempotency_key = store.load(first.contract_id).idempotency_key
    history = store.find_historical_by_idempotency_key(idempotency_key)
    assert {c.contract_id for c in history} == {first.contract_id, second.contract_id, third.contract_id}
    assert store.find_by_idempotency_key(idempotency_key).contract_id == third.contract_id

    # a fourth, equally fresh authorization is refused while the third
    # (blocking, PREPARED) contract still stands
    fourth_authz = _authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="authz-4"
    )
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=fourth_authz)
    assert "authz-4" not in consumption.consumed


# ---------------------------------------------------------------------------
# Batch1 parity: WriteExecutionCoreV1 gets the identical preflight (verbatim
# insertion, see write_execution_core.py's own comment) -- proven once here
# against one real Batch1 capability (NTP_TIME_SERVER_PREFER) rather than
# duplicated per capability, matching this module's own stated philosophy
# ("any change made here for one capability is automatically reviewed for
# every capability that shares this file").
# ---------------------------------------------------------------------------


def _tz_ntp_prefer_core(tmp_path):
    client = _FakeClient()

    def apply(c, payload):
        for i, s in enumerate(c.ntp_time_servers):
            if s.id == payload["id"]:
                c.ntp_time_servers[i] = s.model_copy(update={"prefer": payload["prefer"]})

    write_client = _FakeWriteClient(
        client, endpoint_symbol=PREFER_ENDPOINT_SYMBOL, http_method=PREFER_HTTP_METHOD, applier=apply
    )
    preparer = NtpTimeServerPreferPreparerV1(read_client=client, configured_target=_tz_target())
    store = _tz_store(tmp_path, "ntp-prefer-retry")
    executor = _tz_sealed_executor(
        store, client, write_client, Capability.NTP_TIME_SERVER_PREFER_WRITE, PREFER_ENDPOINT_SYMBOL, PREFER_HTTP_METHOD
    )
    core, private, store = _tz_core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedNtpTimeServerPreferExecutionV1,
        request_type=NtpTimeServerPreferChangeV1,
        contract_id_prefix="ntppref",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    return core, private, store


def _tz_authorize(core, private, request, prepared, authz):
    return core.authorize_and_create(
        request,
        authorized_preparation=prepared,
        authorization=authz,
        requested_plan_digest=authz.plan_digest,
        requested_step_id="batch1.step",
        required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        now=TZ_NOW,
    )


def test_batch1_write_execution_core_allows_fresh_retry_after_historical_failure(tmp_path):
    core, private, store = _tz_ntp_prefer_core(tmp_path)
    request = NtpTimeServerPreferChangeV1(timeserver="1.pool.ntp.org", prefer=True)
    prepared = _preparer_prepare(core, request)

    first_authz = _tz_authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="tz-authz-1"
    )
    first = _tz_authorize(core, private, request, prepared, first_authz)
    _fail_prepared(store, first.contract_id)

    second_authz = _tz_authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="tz-authz-2"
    )
    second = _tz_authorize(core, private, request, prepared, second_authz)

    assert second.contract_id != first.contract_id
    assert store.load(first.contract_id).state is RecoveryState.FAILED
    assert store.load(second.contract_id).state is RecoveryState.PREPARED
    assert store.load(first.contract_id).idempotency_key == store.load(second.contract_id).idempotency_key


def test_batch1_write_execution_core_refuses_fresh_authorization_while_blocking(tmp_path):
    core, private, store = _tz_ntp_prefer_core(tmp_path)
    request = NtpTimeServerPreferChangeV1(timeserver="1.pool.ntp.org", prefer=True)
    prepared = _preparer_prepare(core, request)

    first_authz = _tz_authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="tz-authz-a"
    )
    first = _tz_authorize(core, private, request, prepared, first_authz)
    assert store.load(first.contract_id).state is RecoveryState.PREPARED  # still blocking

    second_authz = _tz_authorization(
        private, compute_execution_intent_digest(prepared.intent), authorization_id="tz-authz-b"
    )
    with pytest.raises(BoundExecutionError):
        _tz_authorize(core, private, request, prepared, second_authz)
    assert {c.contract_id for c in store.all_contracts()} == {first.contract_id}


def _preparer_prepare(core, request):
    return core._preparer.prepare(request)
