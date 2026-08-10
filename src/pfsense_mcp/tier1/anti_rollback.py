"""Whole-store anti-rollback protocol and store-side bookkeeping.

Not constructed by production. Closes the one gap the store's own
record-level HMAC and audit chain cannot close by construction: an
attacker who restores an older, internally self-consistent, correctly
authenticated copy of the whole SQLite file. `AntiRollbackAnchor` is a
backend-agnostic protocol. ADR-011's backend is decided (TPM2 NV counter
via a host-side witness service, see `anti_rollback_tpm_witness.py`) and
its NV index is provisioned on the real hardware (2026-08-10, Slice A) --
but the guest-side store has not yet been seeded with that anchor's real
baseline, and no witness daemon exists yet. See
docs/tier1/specs/whole_store_anti_rollback.md for the generic protocol
specification and
docs/tier1/specs/anti_rollback_tpm_host_witness.md for the concrete
backend's provisioning state machine this module's `HighWaterMark.seed()`/
`ProvisioningRecord` implement primitives for (S7/S9).
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from typing import Protocol

from .canonical import canonical_json, frame_bytes, frame_str
from .errors import (
    AnchorAlreadyProvisionedError,
    ContractIntegrityError,
    ContractValidationError,
    WholeStoreRollbackDetected,
)


class AntiRollbackAnchor(Protocol):
    def read(self) -> int:
        """Return the anchor's current monotonic value. Raises
        AnchorUnavailableError if the anchor cannot be reached/read."""
        ...

    def advance(self, *, expected_current: int) -> int:
        """Atomically advance the anchor past expected_current and return
        the new value. Raises AnchorConflictError if the anchor's actual
        current value does not match expected_current. Raises
        AnchorUnavailableError if unreachable."""
        ...


class HighWaterMark:
    """Store-side bookkeeping: what value the store believes the
    configured AntiRollbackAnchor was last confirmed at. Authenticated
    with the store's own external integrity key (independent of
    `SqliteRecoveryContractStore`'s internals -- this class only needs
    the key and store ID, not the store object) so a local attacker
    cannot lower the recorded mark without also forging the same HMAC
    every other authenticated row in this store requires."""

    _KEY = "high_water_mark"

    def __init__(self, *, integrity_key: bytes, store_id: str) -> None:
        self._integrity_key = integrity_key
        self._store_id = store_id

    def _mac(self, value: int) -> str:
        framed = (
            frame_str(self._store_id) + frame_str("anchor-high-water-mark") + frame_bytes(str(value).encode("utf-8"))
        )
        return hmac.new(self._integrity_key, framed, hashlib.sha256).hexdigest()

    def read(self, connection: sqlite3.Connection) -> int:
        """Return the persisted mark, defaulting to 0 if this store has
        never recorded one. This default is deliberately not treated as
        "nothing to compare yet" -- a store restored to a point *before*
        its first-ever EXECUTING attempt looks identical to a genuinely
        fresh store (no row present either way), so skipping the
        comparison on "no row" would silently reopen exactly the
        rollback gap this class exists to close. The configured anchor
        must therefore be dedicated to this store and start at 0 (or be
        explicitly provisioned to the correct baseline by whoever sets up
        the concrete backend) -- see docs/tier1/specs/whole_store_anti_rollback.md."""

        row = connection.execute("SELECT value, mac FROM anchor_state WHERE key = ?", (self._KEY,)).fetchone()
        if row is None:
            return 0
        value_text, supplied_mac = str(row[0]), str(row[1])
        try:
            value = int(value_text)
        except ValueError:
            raise ContractIntegrityError("Anchor high-water mark is corrupted.") from None
        if value < 0 or not hmac.compare_digest(supplied_mac, self._mac(value)):
            raise ContractIntegrityError("Anchor high-water mark failed integrity verification.")
        return value

    def is_seeded(self, connection: sqlite3.Connection) -> bool:
        """True if a high-water-mark row exists for this store at all,
        regardless of its value -- distinct from `read()`'s own 0-default
        for "no row present", which callers that need to tell "genuinely
        unseeded" apart from "seeded with value 0" (e.g. `seed()` itself,
        and `ProvisioningRecord.mark_complete()`'s ordering check) cannot
        get from `read()` alone."""

        row = connection.execute("SELECT 1 FROM anchor_state WHERE key = ?", (self._KEY,)).fetchone()
        return row is not None

    def seed(self, connection: sqlite3.Connection, *, value: int) -> None:
        """One-time, insert-only provisioning primitive (Slice B): durably
        records an externally-observed anchor value -- e.g. a TPM
        counter's real, just-read initial value, per
        docs/tier1/specs/anti_rollback_tpm_host_witness.md's provisioning
        state machine (S7) -- as this store's high-water-mark baseline,
        before any real EXECUTING transition is ever attempted against
        this store.

        Deliberately NOT `_persist()`: `_persist()`'s
        `INSERT ... ON CONFLICT DO UPDATE` upsert semantics are correct
        for normal operational advancement
        (`before_executing_transition()`) but wrong here -- a
        provisioning seed must never silently overwrite an existing
        baseline. Raises `AnchorAlreadyProvisionedError` if a row already
        exists for this store, whether valid or corrupted -- the
        corrupted case is not distinguished from the valid one, since
        either way a value is already recorded and must not be silently
        replaced (this is what makes seeding fail closed against
        malformed existing state, not merely against valid existing
        state).

        Checked twice, deliberately redundant, matching this module's own
        existing double-check discipline elsewhere
        (`before_executing_transition()`'s own read-then-compare): first
        via `is_seeded()` for an immediate, clean rejection without
        attempting any write; then the `INSERT` statement's own PRIMARY
        KEY constraint as the race-proof, authoritative final guard (a
        concurrent seed attempt cannot both succeed).

        Does not itself contact any anchor backend (TPM, remote witness)
        -- `value` must already have been obtained from the real,
        authoritative anchor by the caller; this primitive only performs
        the store-side half of provisioning."""

        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ContractValidationError("Anchor baseline value must be a non-negative integer.")
        if self.is_seeded(connection):
            raise AnchorAlreadyProvisionedError(
                "A high-water-mark baseline is already recorded for this store; refusing to overwrite."
            )
        try:
            connection.execute(
                "INSERT INTO anchor_state(key, value, mac) VALUES (?, ?, ?)",
                (self._KEY, str(value), self._mac(value)),
            )
        except sqlite3.IntegrityError:
            raise AnchorAlreadyProvisionedError(
                "A high-water-mark baseline was concurrently recorded for this store; refusing to overwrite."
            ) from None

    def _persist(self, connection: sqlite3.Connection, value: int) -> None:
        connection.execute(
            "INSERT INTO anchor_state(key, value, mac) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, mac = excluded.mac",
            (self._KEY, str(value), self._mac(value)),
        )

    def before_executing_transition(self, anchor: AntiRollbackAnchor, connection: sqlite3.Connection) -> None:
        """Raises WholeStoreRollbackDetected if the anchor's current
        value does not exactly match the persisted high-water mark.

        Under normal single-writer operation these two values are always
        equal immediately before a new EXECUTING attempt: the previous
        attempt advanced the anchor by exactly one and persisted that
        same new value. A *restored older store file* remembers a
        smaller mark than the (untouched, externally durable) anchor now
        reports -- `anchor > persisted`. A *tampered or reset anchor*
        reports a smaller value than the (unaffected) file remembers --
        `anchor < persisted`. Both directions are real anomalies and both
        must refuse; only exact equality proceeds. Raises
        AnchorUnavailableError/AnchorConflictError (propagated from the
        anchor implementation) if the anchor cannot be read or advanced.
        On success, durably advances the persisted mark within the same
        connection/transaction the caller is already using for the
        EXECUTING transition."""

        persisted = self.read(connection)
        current = anchor.read()
        if current != persisted:
            raise WholeStoreRollbackDetected(
                "Anti-rollback anchor does not match the store's recorded high-water mark."
            )
        advanced = anchor.advance(expected_current=current)
        self._persist(connection, advanced)


class ProvisioningRecord:
    """Durable, HMAC-authenticated marker recording that this store's
    anti-rollback anchor has been fully provisioned and verified -- the
    explicit S9 gate
    docs/tier1/specs/anti_rollback_tpm_host_witness.md's provisioning
    state machine requires before normal witness operation may begin.
    Lives in the same `anchor_state` table as `HighWaterMark`, under a
    different key, with a domain-separated MAC label
    (`"anchor-provisioning-complete"` vs. `HighWaterMark`'s
    `"anchor-high-water-mark"`) so a marker row's authentication tag can
    never be substituted for, or confused with, a high-water-mark row's
    tag even though both share one table."""

    _KEY = "anchor_provisioning_complete"

    def __init__(self, *, integrity_key: bytes, store_id: str) -> None:
        self._integrity_key = integrity_key
        self._store_id = store_id

    def _mac(self, payload: str) -> str:
        framed = (
            frame_str(self._store_id) + frame_str("anchor-provisioning-complete") + frame_bytes(payload.encode("utf-8"))
        )
        return hmac.new(self._integrity_key, framed, hashlib.sha256).hexdigest()

    def is_complete(self, connection: sqlite3.Connection) -> bool:
        """True only if a valid, HMAC-verified marker is present. Raises
        `ContractIntegrityError` if a marker row exists but fails
        integrity verification -- a corrupted marker is never silently
        treated as "not yet provisioned" (which could let provisioning
        logic re-run over an already-real completion record); fail
        closed, not fail open."""

        row = connection.execute("SELECT value, mac FROM anchor_state WHERE key = ?", (self._KEY,)).fetchone()
        if row is None:
            return False
        payload, supplied_mac = str(row[0]), str(row[1])
        if not hmac.compare_digest(supplied_mac, self._mac(payload)):
            raise ContractIntegrityError("Anchor provisioning-complete marker failed integrity verification.")
        return True

    def mark_complete(
        self,
        connection: sqlite3.Connection,
        *,
        handle: str,
        verified_value: int,
        provisioned_at: str,
        high_water_mark: HighWaterMark,
    ) -> None:
        """One-time, insert-only (S9). Enforces real provisioning
        ordering, not merely documented ordering: raises
        `ContractValidationError` if no high-water-mark baseline has been
        seeded yet (`high_water_mark.is_seeded()` false), or if the
        seeded value does not exactly equal `verified_value` -- this
        marker can only ever be written immediately after a verified,
        matching seed (S7 -> S8 -> S9), never speculatively or out of
        order. `handle` is opaque, stored-and-verified metadata (e.g. the
        TPM NV index handle) identifying which physical anchor this
        baseline corresponds to, for future audit/cross-check -- this
        method performs no TPM I/O itself.

        Raises `AnchorAlreadyProvisionedError` if a marker already
        exists, whether valid or corrupted -- mirrors `HighWaterMark.
        seed()`'s exact insert-only discipline and its exact reasoning
        for not distinguishing the corrupted case."""

        if not high_water_mark.is_seeded(connection):
            raise ContractValidationError(
                "Cannot mark anchor provisioning complete: no high-water-mark baseline has been seeded yet."
            )
        current = high_water_mark.read(connection)
        if current != verified_value:
            raise ContractValidationError(
                "Cannot mark anchor provisioning complete: recorded baseline does not match the verified value."
            )
        if not isinstance(handle, str) or not handle:
            raise ContractValidationError("Anchor handle must be a non-empty string.")
        if self.is_complete(connection):
            raise AnchorAlreadyProvisionedError(
                "Anchor provisioning was already marked complete for this store; refusing to overwrite."
            )
        payload = canonical_json(
            {"handle": handle, "verified_value": verified_value, "provisioned_at": provisioned_at}
        ).decode("utf-8")
        try:
            connection.execute(
                "INSERT INTO anchor_state(key, value, mac) VALUES (?, ?, ?)",
                (self._KEY, payload, self._mac(payload)),
            )
        except sqlite3.IntegrityError:
            raise AnchorAlreadyProvisionedError(
                "Anchor provisioning was concurrently marked complete for this store; refusing to overwrite."
            ) from None
