"""Regression and adversarial tests for
`pfsense_mcp.tier1.authorization_consumption_store` -- ADR-022 Phase D's
durable, authenticated, one-time consumption tracking for a
`PlanAuthorization`'s `authorization_id`. No signature verification, no
plan/step binding, no execution anywhere in this module or these tests.
"""

from __future__ import annotations

import os
import sqlite3
import threading

import pytest

from pfsense_mcp.tier1.authorization_consumption_store import SqliteAuthorizationConsumptionStore
from pfsense_mcp.tier1.errors import AuthorizationConsumptionError

_KEY = b"synthetic-test-integrity-key-32bytes!"


def _store(tmp_path, *, clock=None):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    options = {}
    if clock is not None:
        options["clock"] = clock
    return SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_KEY, store_id="synthetic-consumption-store", **options
    )


# ---------------------------------------------------------------------------
# Construction safety
# ---------------------------------------------------------------------------


def test_rejects_short_integrity_key(tmp_path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    with pytest.raises(AuthorizationConsumptionError):
        SqliteAuthorizationConsumptionStore(tmp_path / "c.sqlite3", integrity_key=b"too-short", store_id="s")


def test_rejects_invalid_store_id(tmp_path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    with pytest.raises(AuthorizationConsumptionError):
        SqliteAuthorizationConsumptionStore(tmp_path / "c.sqlite3", integrity_key=_KEY, store_id="not an id!")


def test_rejects_non_utc_clock(tmp_path):
    from datetime import datetime

    store = _store(tmp_path, clock=lambda: datetime(2026, 8, 11, 12, 0, 0))
    with pytest.raises(AuthorizationConsumptionError):
        store.try_consume("authz-1")


def test_creates_owner_only_file(tmp_path):
    _store(tmp_path)
    info = (tmp_path / "consumed.sqlite3").stat()
    assert info.st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Core one-time consumption semantics
# ---------------------------------------------------------------------------


def test_first_consumption_succeeds(tmp_path):
    store = _store(tmp_path)
    assert store.try_consume("authz-1") is True


def test_second_consumption_of_the_same_id_fails(tmp_path):
    store = _store(tmp_path)
    assert store.try_consume("authz-1") is True
    assert store.try_consume("authz-1") is False


def test_different_ids_are_independently_consumable(tmp_path):
    store = _store(tmp_path)
    assert store.try_consume("authz-1") is True
    assert store.try_consume("authz-2") is True


def test_repeated_replay_attempts_all_return_false(tmp_path):
    store = _store(tmp_path)
    assert store.try_consume("authz-1") is True
    for _ in range(5):
        assert store.try_consume("authz-1") is False


# ---------------------------------------------------------------------------
# Crash / restart -- process/store reopen preserves consumed state
# ---------------------------------------------------------------------------


def test_reopened_store_still_refuses_a_previously_consumed_id(tmp_path):
    first = _store(tmp_path)
    assert first.try_consume("authz-1") is True

    reopened = SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_KEY, store_id="synthetic-consumption-store"
    )
    assert reopened.try_consume("authz-1") is False


def test_reopened_store_still_accepts_a_fresh_id(tmp_path):
    first = _store(tmp_path)
    first.try_consume("authz-1")

    reopened = SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_KEY, store_id="synthetic-consumption-store"
    )
    assert reopened.try_consume("authz-2") is True


def test_reopening_with_a_different_store_id_is_refused(tmp_path):
    _store(tmp_path)
    with pytest.raises(AuthorizationConsumptionError):
        SqliteAuthorizationConsumptionStore(
            tmp_path / "consumed.sqlite3", integrity_key=_KEY, store_id="a-different-store-id"
        )


# ---------------------------------------------------------------------------
# Concurrency -- atomic replay prevention
# ---------------------------------------------------------------------------


def test_concurrent_double_consumption_yields_exactly_one_success(tmp_path):
    store = _store(tmp_path)
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        outcome = store.try_consume("race-id")
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 8
    assert sum(1 for outcome in results if outcome) == 1


def test_concurrent_consumption_of_different_ids_all_succeed(tmp_path):
    store = _store(tmp_path)
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker(index: int):
        barrier.wait()
        outcome = store.try_consume(f"distinct-id-{index}")
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert all(results)


# ---------------------------------------------------------------------------
# Fail-closed behavior
# ---------------------------------------------------------------------------


def test_malformed_authorization_id_is_rejected(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(AuthorizationConsumptionError):
        store.try_consume("not a valid identifier!!")


def test_empty_authorization_id_is_rejected(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(AuthorizationConsumptionError):
        store.try_consume("")


def test_non_string_authorization_id_is_rejected(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(AuthorizationConsumptionError):
        store.try_consume(12345)  # type: ignore[arg-type]


def test_tampered_stored_row_fails_closed_on_replay_attempt(tmp_path):
    store = _store(tmp_path)
    store.try_consume("authz-1")

    connection = sqlite3.connect(tmp_path / "consumed.sqlite3")
    connection.execute("UPDATE consumed_authorizations SET mac = 'deadbeef' WHERE authorization_id = 'authz-1'")
    connection.commit()
    connection.close()

    with pytest.raises(AuthorizationConsumptionError):
        store.try_consume("authz-1")


def test_tampered_consumed_at_fails_closed_on_replay_attempt(tmp_path):
    """Changing consumed_at without recomputing the MAC must also be
    caught -- the MAC binds both fields together, not just one."""

    store = _store(tmp_path)
    store.try_consume("authz-1")

    connection = sqlite3.connect(tmp_path / "consumed.sqlite3")
    connection.execute(
        "UPDATE consumed_authorizations SET consumed_at = ? WHERE authorization_id = 'authz-1'",
        ("2099-01-01T00:00:00+00:00",),
    )
    connection.commit()
    connection.close()

    with pytest.raises(AuthorizationConsumptionError):
        store.try_consume("authz-1")


def test_database_failure_fails_closed(tmp_path, monkeypatch):
    store = _store(tmp_path)

    def _boom(*args, **kwargs):
        raise sqlite3.OperationalError("simulated failure")

    monkeypatch.setattr(sqlite3, "connect", _boom)
    with pytest.raises(AuthorizationConsumptionError):
        store.try_consume("authz-1")


def test_malformed_schema_on_reopen_fails_closed(tmp_path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    db_path = tmp_path / "consumed.sqlite3"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE consumed_authorizations (authorization_id TEXT PRIMARY KEY)")
    connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.commit()
    connection.close()
    os.chmod(db_path, 0o600)

    with pytest.raises(AuthorizationConsumptionError):
        SqliteAuthorizationConsumptionStore(db_path, integrity_key=_KEY, store_id="synthetic-consumption-store")


# ---------------------------------------------------------------------------
# Isolation from verification/execution
# ---------------------------------------------------------------------------


def test_store_has_no_verification_or_execution_shaped_method(tmp_path):
    store = _store(tmp_path)
    forbidden = {"execute", "apply", "verify", "consume_and_execute", "authorize"}
    assert forbidden.isdisjoint(dir(store))
