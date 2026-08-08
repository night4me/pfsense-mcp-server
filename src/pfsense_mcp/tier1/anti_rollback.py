"""Whole-store anti-rollback protocol and store-side bookkeeping.

Not constructed by production. Closes the one gap the store's own
record-level HMAC and audit chain cannot close by construction: an
attacker who restores an older, internally self-consistent, correctly
authenticated copy of the whole SQLite file. `AntiRollbackAnchor` is a
backend-agnostic protocol; no concrete backend (TPM2 NV counter, remote
append-only witness) is selected or implemented here -- that selection
is docs/adr/ADR-011-whole-store-anti-rollback-anchor.md, pending owner
confirmation of the actual production host's hardware. See
docs/tier1/specs/whole_store_anti_rollback.md for the full specification.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from typing import Protocol

from .canonical import frame_bytes, frame_str
from .errors import ContractIntegrityError, WholeStoreRollbackDetected


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
