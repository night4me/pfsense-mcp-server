# ADR-011: Whole-store anti-rollback anchor

- **Status:** Backend decided (2026-08-10) — design-ready, not yet
  provisioned. See "Backend decision" below.
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

## Backend decision (2026-08-10)

Owner confirmed the actual production topology: the `pfsense-mcp-server`
process runs in an Ubuntu KVM guest ("VM 106," `192.0.2.27`) on a
Proxmox host (Dell OptiPlex 3000, `192.0.2.39`) with a genuine physical
TPM 2.0 (`TPM2_PT_NV_COUNTERS = 3`, `TPM2_PT_NV_COUNTERS_AVAIL = 10`, 14
total NV indices, capacity confirmed for one dedicated project counter).
A dedicated topology review
(`reports-ai/reviews/ADR_011_TOPOLOGY_REVIEW_2026-08-10.md`) evaluated
four options against this exact topology and the accepted rollback-
independence property, grounded in primary sources (QEMU's own TPM
documentation, Proxmox's own `qm` manual page), not assumption:

- **Physical TPM passthrough to the guest — rejected.** Not supported by
  Proxmox's own tooling at all; QEMU's own documentation independently
  discourages it (PCR-sharing conflicts between host and guest, guest
  firmware `TPM_Startup()` failure, migration disabled) even where
  achievable outside Proxmox's management.
- **Proxmox/QEMU software vTPM (swtpm) — rejected, does not satisfy the
  property.** Proxmox's own `qm` manual page documents `tpmstate0`
  explicitly as an ordinary **disk** volume, provisioned with the
  identical mechanism as any other VM disk. Its persistent state is
  therefore included in the same snapshot/backup/restore/clone lifecycle
  as the rest of the VM — structurally the same failure this ADR already
  rejected for a same-directory anchor file, TPM2 protocol semantics
  inside the guest notwithstanding.
- **Chosen: a narrowly-scoped host-side TPM-backed witness service** on
  the Proxmox host, exposing only the semantic equivalent of
  `AntiRollbackAnchor.read()`/`.advance()` to the guest — architecturally
  this ADR's own "remote append-only witness" category, instantiated
  using the host's real hardware TPM as that witness's tamper-evident
  storage rather than an ordinary file. The guest never holds TPM
  authorization material; the TPM authorization boundary never crosses
  the network.

Full concrete design (NV index type/attributes/auth model, host service
protocol, guest integration, provisioning procedure, required tests):
[anti_rollback_tpm_host_witness.md](../tier1/specs/anti_rollback_tpm_host_witness.md).
**Design only — no TPM index has been provisioned, no daemon deployed, no
mutating TPM command executed.** `AntiRollbackAnchor`'s existing protocol
and `store.py`'s call site require no change (this ADR's own "Future
migration path" text, below, already anticipated this).

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
- `reports-ai/reviews/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`
