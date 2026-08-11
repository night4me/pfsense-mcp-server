"""ADR-022 Phase D: durable, authenticated, one-time consumption
tracking for a `PlanAuthorization`'s `authorization_id`.

Not constructed by production. This module is deliberately narrower
than `store.py`'s `SqliteRecoveryContractStore` and does not extend or
share its schema/file, per the owner's explicit Phase D scope decision
(2026-08-11, recorded in `docs/adr/ADR-023-authorization-verification-boundary.md`):
"Use a dedicated authorization-consumption persistence structure/table
rather than extending or overloading the existing Recovery Contract
'contracts' table. Authorization consumption is a separate security
domain with its own lifecycle and invariants."

**What this module records**: only whether a given `authorization_id`
has ever been consumed, and when. Nothing else -- no `plan_digest`, no
`authorized_step_ids`, no `risk_class`, no signature, no plan content.
Those all already live, immutably, inside the `PlanAuthorization`
artifact itself (`security_authorization.py`); duplicating them here
would be exactly the "generalized authorization database" the owner's
scope decision explicitly forbids building.

**What this module does not do**: verify a signature (see
`security_authorization_verifier.py`), check expiry, check
`plan_digest`/step-membership, or connect to `MutationExecutor`,
`WriteApiClient`, `WriteEndpoints`, the Tier 1 state machine, pfSense,
Proxmox, or TPM/witness state in any way. `try_consume()` mutates only
this module's own, narrowly-defined consumption table -- nothing else.
There is no `execute()`, `apply()`, or `consume_and_execute()`-shaped
method anywhere in this module; consuming an authorization_id record is
not, and must never become, a bearer-token-shaped runtime API.

## Atomicity

`try_consume()` is a single, atomic insert-once operation: a fresh
`authorization_id` is durably recorded and the call returns `True`; an
already-consumed `authorization_id` leaves the store unchanged and the
call returns `False` -- never raises for this ordinary, expected
outcome. Two concurrent callers racing to consume the same
`authorization_id` are serialized by SQLite's own `BEGIN IMMEDIATE`
write-lock acquisition (the identical discipline
`SqliteRecoveryContractStore.create()` already uses for its own
`idempotency_key`/`operation_id` uniqueness) plus the `PRIMARY KEY`
constraint on `authorization_id` itself: at most one of them can ever
observe `True`.

## Integrity

Each row is HMAC-authenticated (`consumed_at` framed with
`tier1.canonical.frame_str`/`frame_bytes`, the same domain-separated
framing discipline `store.py`'s own `_mac()` uses), keyed by a
caller-supplied `integrity_key` -- reused, not reinvented. A stored row
that fails MAC verification when re-read (an already-consumed
`authorization_id` being re-attempted) raises
`AuthorizationConsumptionError` rather than being silently trusted or
silently treated as "not yet consumed" -- fails closed, per the owner's
explicit "malformed stored consumption state fails closed" requirement.

## File safety

Path validation (`_prepare_path()`) mirrors `store.py`'s own discipline
exactly: owner-only parent directory (mode 0700), no symlinks
(`os.O_NOFOLLOW`), owner-only file (mode 0600). Duplicated rather than
extracted into a shared helper, deliberately: this module must not
require touching `store.py` (an already-reviewed, Accepted class) to
exist, per the owner's "prefer narrow new types/functions over
expanding existing execution classes" instruction.
"""

from __future__ import annotations

import hmac
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .canonical import frame_bytes, frame_str
from .errors import AuthorizationConsumptionError

__all__ = [
    "AuthorizationConsumptionStore",
    "Clock",
    "SqliteAuthorizationConsumptionStore",
]

_AUTHORIZATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SCHEMA_VERSION = 1
_STORE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuthorizationConsumptionStore(Protocol):
    """The small interface `security_authorization_verifier.py` (or any
    future Phase D caller) depends on -- deliberately just this one
    method, so replay semantics can be exercised against a test double
    without ever touching SQLite, and so a future backend swap would
    never require changing verifier code."""

    def try_consume(self, authorization_id: str) -> bool:
        """Atomically records `authorization_id` as consumed if, and
        only if, it has never been consumed before by this store.
        Returns `True` on first consumption, `False` if it was already
        consumed (an ordinary, expected replay-attempt outcome, never
        an exception). Raises `AuthorizationConsumptionError` only for
        a malformed `authorization_id`, a stored row that fails
        integrity verification, or a database/transaction failure --
        every one of those fails closed (the caller must treat a raised
        exception as "not safely consumed," never as "was consumed" or
        "was not consumed")."""
        ...


class SqliteAuthorizationConsumptionStore:
    """The concrete, file-backed `AuthorizationConsumptionStore`."""

    def __init__(
        self,
        path: Path,
        *,
        integrity_key: bytes,
        store_id: str,
        clock: Clock = _utc_now,
    ) -> None:
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise AuthorizationConsumptionError("Authorization consumption store integrity key must be >= 32 bytes.")
        if not isinstance(store_id, str) or not _STORE_ID.fullmatch(store_id):
            raise AuthorizationConsumptionError("Authorization consumption store identifier is invalid.")
        if not callable(clock):
            raise AuthorizationConsumptionError("Authorization consumption store clock is invalid.")
        self._path = path
        self._integrity_key = bytes(integrity_key)
        self._store_id = store_id
        self._clock = clock
        self._prepare_path()
        self._initialize_schema()

    def _prepare_path(self) -> None:
        if not hasattr(os, "O_NOFOLLOW"):
            raise AuthorizationConsumptionError("Authorization consumption store requires Linux O_NOFOLLOW support.")
        parent = self._path.parent
        try:
            parent_info = parent.lstat()
        except OSError:
            raise AuthorizationConsumptionError(
                f"Authorization consumption store parent directory does not exist: {parent}"
            ) from None
        if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
            raise AuthorizationConsumptionError("Authorization consumption store parent must be a real directory.")
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise AuthorizationConsumptionError(
                "Authorization consumption store parent must be owned by the effective user with mode 0700."
            )
        if self._path.exists() or self._path.is_symlink():
            info = self._path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise AuthorizationConsumptionError(
                    "Authorization consumption store must be a regular non-symlink file."
                )
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise AuthorizationConsumptionError("Authorization consumption store must be owner-only.")
            return
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
        fd = os.open(self._path, flags, 0o600)
        os.close(fd)

    def _now(self) -> datetime:
        instant = self._clock()
        if (
            not isinstance(instant, datetime)
            or instant.tzinfo is None
            or instant.utcoffset() != timezone.utc.utcoffset(instant)
        ):
            raise AuthorizationConsumptionError("Authorization consumption store clock must return UTC.")
        return instant

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.DatabaseError:
            if connection is not None:
                connection.close()
            raise AuthorizationConsumptionError(
                "Authorization consumption store database could not be opened safely."
            ) from None

    def _mac(self, *components: bytes) -> str:
        framed = frame_str(self._store_id)
        for component in components:
            framed += frame_bytes(component)
        return hmac.new(self._integrity_key, framed, "sha256").hexdigest()

    def _row_mac(self, authorization_id: str, consumed_at: str) -> str:
        return self._mac(
            b"consumed-authorization",
            frame_str(authorization_id) + frame_str(consumed_at),
        )

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        expected_columns = {
            "metadata": (("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0)),
            "consumed_authorizations": (
                ("authorization_id", "TEXT", 0, 1),
                ("consumed_at", "TEXT", 1, 0),
                ("mac", "TEXT", 1, 0),
            ),
        }
        actual_columns = {
            table: tuple((row[1], row[2], row[3], row[5]) for row in connection.execute(f"PRAGMA table_info({table})"))
            for table in expected_columns
        }
        if actual_columns != expected_columns:
            raise AuthorizationConsumptionError("Authorization consumption store schema does not match this build.")

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consumed_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    consumed_at TEXT NOT NULL,
                    mac TEXT NOT NULL
                );
                """
            )
            self._verify_schema(connection)
            existing = dict(connection.execute("SELECT key, value FROM metadata"))
            expected = {"schema_version": str(_SCHEMA_VERSION), "store_id": self._store_id}
            if existing and existing != expected:
                raise AuthorizationConsumptionError(
                    "Authorization consumption store metadata does not match this build or store identity."
                )
            if not existing:
                has_state = connection.execute("SELECT EXISTS(SELECT 1 FROM consumed_authorizations)").fetchone()[0]
                if has_state:
                    raise AuthorizationConsumptionError(
                        "Authorization consumption store metadata is missing from a non-empty store."
                    )
                connection.executemany("INSERT INTO metadata(key, value) VALUES (?, ?)", expected.items())
        os.chmod(self._path, 0o600)

    def try_consume(self, authorization_id: str) -> bool:
        if not isinstance(authorization_id, str) or not _AUTHORIZATION_ID.fullmatch(authorization_id):
            raise AuthorizationConsumptionError("authorization_id is invalid.")
        consumed_at = self._now().isoformat()
        row_mac = self._row_mac(authorization_id, consumed_at)
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO consumed_authorizations(authorization_id, consumed_at, mac) VALUES (?, ?, ?)",
                    (authorization_id, consumed_at, row_mac),
                )
                connection.commit()
                return True
            except sqlite3.IntegrityError:
                connection.rollback()
            except Exception:
                connection.rollback()
                raise
        # Already consumed (by this or a prior call) -- verify the
        # existing row's integrity before confidently reporting replay,
        # rather than trusting an unauthenticated read. A corrupted row
        # fails closed (raises), never silently treated as either
        # "consumed" or "not consumed."
        with self._connect() as connection:
            row = connection.execute(
                "SELECT consumed_at, mac FROM consumed_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        if row is None:
            # Lost the race in a way that left no row at all -- treat as
            # a store integrity failure, never as "not yet consumed."
            raise AuthorizationConsumptionError("Authorization consumption store is in an inconsistent state.")
        stored_consumed_at, stored_mac = str(row[0]), str(row[1])
        expected_mac = self._row_mac(authorization_id, stored_consumed_at)
        if not hmac.compare_digest(stored_mac, expected_mac):
            raise AuthorizationConsumptionError(
                "Stored authorization consumption record failed integrity verification."
            )
        return False
