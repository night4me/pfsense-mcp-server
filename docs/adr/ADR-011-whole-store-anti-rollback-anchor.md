# ADR-011: Whole-store anti-rollback anchor

- **Status:** Recommended — pending owner decision (requires confirming
  TPM availability on the actual production host)
- **Date:** 2026-08-08

## Context

`tests/tier1/test_store.py::test_whole_store_rollback_remains_an_
explicit_external_anchor_blocker` proves, executably, that restoring an
older, internally self-consistent, correctly-HMAC-authenticated copy of
the SQLite store is currently undetectable — every record-level check
passes because the HMAC key and logic were identical when the old copy
was genuinely written. No anchor internal to the database file can fix
this; the fix must live outside the file's own blast radius.

## Options considered

| Option | Detects rollback? | Cost/tradeoff |
|---|---:|---|
| Git-like internal hash chain | No, by itself | Useful tamper evidence, already effectively present via the audit chain; does not solve this problem |
| Signed checkpoint in a second ordinary file | Only if that file itself has independent rollback protection | A second file in the same trust domain is not independent — explicitly rejected by the prior architecture review and this ADR agrees |
| **TPM2 NV counter (recommended primary)** | Yes, hardware-backed | Requires TPM presence; write-endurance and provisioning complexity, but well-understood and tooled (`tpm2-tools`) on Linux |
| **Remote append-only witness (recommended fallback)** | Yes, if the witness credential is independent of the local account | Requires new infrastructure (a remote endpoint/credential); availability failure must block mutation, which is an intentional cost, not a bug |

## Recommendation

TPM2 NV counter where the production host has one; a remote append-only
witness (separate credential, separate host) as the **mandatory**
fallback where it does not. If neither is available, mutation must stay
blocked — a same-directory or same-disk anchor is explicitly rejected as
insufficient, matching the existing red-team finding
("a second ordinary file alone is insufficient"). Full specification:
[whole_store_anti_rollback.md](../tier1/specs/whole_store_anti_rollback.md).

### Self-challenge

*"Isn't refusing to mutate when no anchor is available too strict —
wouldn't a best-effort local anchor (e.g., a file on a different disk
partition) be better than no protection at all?"* — Considered and
rejected. A different partition under the same operating-system account
is still within the same attacker capability the store's own filesystem
protections already assume as in-scope (`THREAT_MODEL.md` A3/A4) — an
attacker who can write to the store's directory can, in the general case,
also write to another local partition they have access to. "Better than
nothing" local mitigations create a false sense of coverage that is worse
than an explicit, honest "mutation is blocked until a real anchor exists"
— which is exactly the posture the existing red-team report already took,
and this ADR does not weaken it under implementation pressure.

*"Why not build the remote witness as the primary default, since it works
identically across all hosts regardless of TPM presence?"* — TPM is
preferred as primary specifically because it requires no new network
service, no new credential, and no new availability dependency — a local,
offline mutation attempt should not become unavailable merely because a
remote witness endpoint is unreachable, if a strictly-local, genuinely
independent (hardware-backed) alternative exists. The remote witness
remains mandatory only where TPM is absent.

## Consequences

### Positive

- Closes the one gap the architecture review confirmed cannot be fixed
  from inside the database.
- The `AntiRollbackAnchor` protocol keeps both backends interchangeable —
  the decision here does not lock in an implementation detail beyond the
  interface.

### Negative

- Adds a hard operational dependency (TPM or remote witness) to
  production mutation — by design; this is the correct cost for closing
  a real detection gap, not an accident.
- Requires new tooling/infrastructure for whichever backend is chosen,
  which is real implementation work beyond what any other subsystem in
  this set requires.

## Future migration path

The `AntiRollbackAnchor` protocol (see `whole_store_anti_rollback.md`)
is designed so a future migration between TPM and remote-witness (or a
combination — TPM primary with remote witness as redundant secondary
confirmation) requires no change to `store.py`'s call site. Revisit this
decision once the actual production host's hardware/infrastructure is
known with certainty — this ADR's recommendation is conditional on that
confirmation and is explicitly not final until it happens (see Status).

## References

- [whole_store_anti_rollback.md](../tier1/specs/whole_store_anti_rollback.md)
- `tests/tier1/test_store.py::test_whole_store_rollback_remains_an_explicit_external_anchor_blocker`
- `reports-ai/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`
