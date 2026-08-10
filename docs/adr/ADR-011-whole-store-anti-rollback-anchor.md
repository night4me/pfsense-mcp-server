# ADR-011: Whole-store anti-rollback anchor

- **Status:** Backend decided (2026-08-10); TPM counter provisioned and
  the host-side witness daemon implemented, real-hardware-verified, and
  running (Slice A/B, host-witness daemon Phases 1–2 — see
  `reports-ai/latest.md` for full session-by-session evidence). Live
  baseline-seeding of the production store is confirmed complete.
  Deployment model (persistent vs. manual) decided 2026-08-10 — see
  "Deployment model decision" below — **and the persistent deployment
  itself is now functionally verified live** (`enabled`/`active`,
  survived an unplanned host reboot, correct identity/hardening/TPM
  access/mTLS certs, deployed code confirmed to include the Phase 2
  hardware fixes; one optional hygiene item,
  `ConfigurationDirectoryMode`, remains unremediated — see
  `reports-ai/reviews/WITNESS_DAEMON_DEPLOYMENT_CONVERGENCE_REVIEW_2026-08-10.md`).
  This closes the anti-rollback anchor's provisioning/deployment
  milestone; it does **not** activate anything — fail-closed enforcement
  in `store.py` remains unimplemented, and WRITE remains fully
  unauthorized and unaffected by any of this — 0/3 active, empty
  allow-list.
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
**At the time this backend decision was recorded, this was design
only — no TPM index had been provisioned, no daemon deployed, no
mutating TPM command executed.** (That has since progressed — see
this ADR's Status line and "Deployment model decision" section below
for the current, authoritative state; this paragraph is preserved
as-written to record the decision accurately at the point it was
made.) `AntiRollbackAnchor`'s existing protocol and `store.py`'s call
site require no change (this ADR's own "Future migration path" text,
below, already anticipated this).

## Deployment model decision (2026-08-10)

Owner decision: **the persistent, systemd-managed witness daemon is the
intended reference/production architecture for the hardened
hardware-TPM-witness profile** — not a manually-started, foreground
process. This is a deployment-model decision layered on top of, and
consistent with, the backend decision above; it does not reopen or
change the chosen backend (physical TPM via a host-side witness
service), the wire protocol, or any security invariant already
specified in
[anti_rollback_tpm_host_witness.md](../tier1/specs/anti_rollback_tpm_host_witness.md).

- **Production behavior**: the witness daemon runs as a `systemd`
  service (`witness_daemon/systemd/pfsense-mcp-tpm-witness.service`),
  enabled to start automatically with the host and to restart
  automatically on failure (`Restart=on-failure`), so it is available
  for runtime Tier 1 verification without manual intervention after a
  host reboot or a daemon crash.
- **Manual/foreground startup** (`python3 -m witness_daemon` run
  directly, outside `systemd`) **remains useful only as a development,
  diagnostic, or recovery mode** — e.g. the read-only Phase 2
  real-hardware verification performed before this decision, or
  troubleshooting a failed service start. It is explicitly **not** the
  intended production deployment shape and must not be treated as a
  substitute for the systemd-managed service in normal operation.
- **Persistence does not imply, expand, or shortcut WRITE
  authorization.** Running the witness daemon continuously changes
  only how reliably the *read-only* anchor comparison
  (`tier1_anchor_check.run_anchor_startup_check()`) can succeed — it
  grants no new capability. `advance()`, any TPM-mutating command
  beyond what provisioning already performed, fail-closed WRITE
  gating, WRITE capability activation, `WriteEndpoints` population,
  and pfSense mutation all remain separately gated, unauthorized by
  this decision, and unchanged by it.
- **All existing security boundaries are preserved, not weakened, by
  making the daemon persistent**: the dedicated non-root service
  identity with no Proxmox-management privileges ("Service privilege
  separation"), the full `systemd` hardening directive list
  ("systemd hardening requirements"), mTLS with `CERT_REQUIRED` on
  both ends, network exposure restricted to VM 106's address only
  ("Firewall requirements"), the fixed TPM NV handle and the
  daemon's refusal to accept a caller-supplied handle, and the
  witness protocol's exact two-operation surface (`read`/`advance`,
  nothing else) — all unchanged by this decision. Persistence is an
  availability property, not a privilege expansion.
- This decision is also the target architecture for the planned
  `pfsense-mcp-security setup` provisioning wizard's hardened
  hardware-TPM-witness profile (idea-stage, not committed — see
  [ROADMAP.md](../ROADMAP.md)): when that tooling exists, selecting
  the hardened profile should provision the persistent systemd-managed
  daemon described here, not a manually-started process, while
  keeping the choice of security profile explicit rather than silently
  enabling stronger privileges.

Full deployment/verification detail (the reference unit file, the
`ConfigurationDirectoryMode` hardening value, and how to verify a real
installation) is in
[anti_rollback_tpm_host_witness.md](../tier1/specs/anti_rollback_tpm_host_witness.md)'s
"Deployment model" section — this ADR records the decision itself as
the single authoritative source; other project documents should point
here rather than restate it.

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
- [anti_rollback_tpm_host_witness.md](../tier1/specs/anti_rollback_tpm_host_witness.md) — concrete backend spec and "Deployment model" section
- [ROADMAP.md](../ROADMAP.md) — future `pfsense-mcp-security setup` provisioning-wizard direction (idea-stage)
- `tests/tier1/test_store.py::test_whole_store_rollback_remains_an_explicit_external_anchor_blocker`
- `reports-ai/reviews/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`
- `reports-ai/reviews/ADR_011_TOPOLOGY_REVIEW_2026-08-10.md`
