# Tier 1 — TPM-backed host-witness anti-rollback anchor (concrete `ADR-011` backend)

Status: implementation-ready specification; implementation not authorized.
Activation gate: `ADR-011`'s backend decision (below) plus Milestone 3
(anti-rollback activation) and, separately, explicit provisioning
authorization before any TPM-mutating command runs.
Related: [whole_store_anti_rollback.md](whole_store_anti_rollback.md)
(the generic `AntiRollbackAnchor` protocol this backend implements —
this document does not redefine it), [ADR-011](../../adr/ADR-011-whole-store-anti-rollback-anchor.md).

## Owner decision this document records

2026-08-10: the physical TPM 2.0 on the Proxmox host (Dell OptiPlex
3000) is the chosen `AntiRollbackAnchor` backend, accessed through a
narrowly-scoped host-side witness service — never through direct TPM
passthrough or a software vTPM to the guest (`ADR-011`'s topology review,
`reports-ai/reviews/ADR_011_TOPOLOGY_REVIEW_2026-08-10.md`, established
why: Proxmox's `tpmstate0` is an ordinary disk volume, included in the
same snapshot/backup/restore/clone lifecycle as the rest of the VM, and
does not provide rollback independence; physical passthrough is
unsupported by Proxmox and discouraged by QEMU's own documentation).

Verified hardware evidence (owner-supplied, from the Proxmox host):
`TPM2_PT_NV_COUNTERS = 3`, `TPM2_PT_NV_COUNTERS_AVAIL = 10`, 14 total NV
indices currently defined, of which 3 are counter type (`nt=0x1`) — 10
counter-type slots remain available; capacity for one dedicated project
counter is confirmed. All 14 existing indices are foreign/vendor/OS-owned
and must never be modified, reused, undefined, or otherwise touched by
this project.

**This document is a design only. No command in it has been executed.
See "Provisioning procedure" for the exact, listed-but-not-run commands,
and "Activation requirements" for what authorization each step still
needs.**

## Purpose

Implement the `AntiRollbackAnchor` protocol (`anti_rollback.py`, already
implemented and tested, backend-agnostic) using a TPM2 NV counter on the
Proxmox host as the durable, tamper-evident monotonic value, reached by
the `pfsense-mcp-server` guest (VM 106, `192.0.2.27`) only through a
narrow, purpose-built RPC exposed by a dedicated witness daemon on the
Proxmox host (`192.0.2.39`) — never direct TPM device access, never a
software vTPM.

## Security goals

- G1 (inherited from `whole_store_anti_rollback.md`): the anchor's
  durable state must live outside the blast radius of anything an
  attacker who can restore/replace/modify the guest's filesystem could
  also reach. Satisfied structurally here: the counter's actual value
  lives in physical TPM hardware on a different machine, reachable from
  the guest only through one narrow network operation.
- G2: the guest never holds, transmits, or requires the TPM NV index's
  own authorization secret. The TPM authorization boundary never crosses
  the network.
- G3: the witness daemon's network-facing surface exposes exactly the
  two operations `AntiRollbackAnchor` needs (`read`, `advance`) and
  nothing else — no generic TPM command forwarding, no access to any
  other NV index, no TPM ownership/hierarchy operations.
- G4: none of the 14 existing, foreign-owned NV indices are read,
  written, enumerated destructively, or otherwise put at risk by this
  design or its provisioning procedure.
- G5: a lost or corrupted witness-daemon secret must be recoverable via
  an explicit, documented re-provisioning procedure that starts from "no
  prior anchor" (matching `ADR-011`'s own stated safe default), never by
  silently weakening the index's auth model to work around the loss.

## Provisioning strategy — NV index selection

**Selection is enumerate-first, not range-guessed.** The safe strategy
is: (1) run `tpm2_getcap handles-nv-index` to obtain the exact list of
all 14 existing handles (owner-supplied counts confirm the number, not
yet the exact handle values); (2) choose one unused handle inside the
conventional owner/application-usable sub-range
(`0x01000000`–`0x01bfffff`), explicitly avoiding the TCG-reserved
platform-certificate range (`0x01c00000`–`0x01ffffff`) — the primary TCG
Registry of Reserved TPM 2.0 Handles and Localities document could not be
fetched directly during this review (HTTP 403); this range convention is
corroborated by tpm2-tools' own community documentation and examples
(which conventionally use handles like `0x1500016` for owner/application
NV indices) but should be re-confirmed against the primary TCG registry
before the handle is finalized, not assumed from secondary sources alone;
(3) confirm the chosen handle does not collide with any of the 14
enumerated handles from step 1 — collision avoidance by direct
enumeration, not by trusting a numeric range alone.

No specific handle number is finalized by this document — that is the
first concrete output of running the (not-yet-executed) enumeration
command in "Provisioning procedure" below.

## NV index type and attributes

- **Type**: `TPM_NT_COUNTER` (`nt=1`), matching the existing 3
  counter-type indices' own convention and the semantics
  `AntiRollbackAnchor.advance()` needs (`TPM2_NV_Increment`-only
  modification, per the TPM2 spec's own definition of the Counter type).
- **Size**: 8 bytes (the fixed size of a TPM2 NV counter value).
- **Hierarchy**: owner (`-C o`), not platform — this project's counter is
  an application-level index, not a platform/firmware-level one.
- **Attributes**: `authread|authwrite|nt=1` — **deliberately omitting**
  `ownerread`/`ownerwrite`. Only the index's own dedicated authorization
  secret (never the TPM's owner-hierarchy password) can read or increment
  it. This is the narrowest available access model and does not sacrifice
  recoverability: `TPM2_NV_UndefineSpace` (destroying and allowing
  re-provisioning of the index) is a hierarchy-level operation gated by
  owner/platform authorization regardless of the index's own
  `AUTHREAD`/`AUTHWRITE` bits — so losing the index's own secret is
  recoverable via owner-hierarchy undefine-and-reprovision (G5), without
  ever needing to grant the owner hierarchy standing read/write access to
  the live counter value.
- **`no_da`**: **not set** (dictionary-attack protection stays active).
  The TPM authorization boundary never crosses the network (G2) — the
  daemon is the only entity that ever presents the index's auth value,
  and it always presents the correct one in normal operation, so DA
  lockout risk from this index specifically is not a normal-operation
  concern. Leaving DA protection on is the more conservative choice
  against a scenario where a compromised host attempts to brute-force
  the secret. **Open item for provisioning time**: confirm via
  `tpm2_getcap properties-variable` (`TPM2_PT_LOCKOUT_COUNTER`,
  `TPM2_PT_MAX_AUTH_FAIL`) whether this TPM's dictionary-attack lockout
  counter is shared across all auth-protected objects/indices or scoped
  per-object — if shared, a lockout event on this index could also block
  other legitimate host TPM consumers, which changes the risk calculus
  and may argue for `no_da` after all. Not resolved by this design pass;
  flagged for the provisioning step, not assumed either way.

## Hierarchy / authorization model

Owner hierarchy defines the index (requires the Proxmox host's TPM owner
authorization once, at provisioning time only — the witness daemon never
needs or stores the owner-hierarchy password after provisioning
completes). Ongoing `read`/`advance` operations use only the index's own
dedicated authorization secret (`authread`/`authwrite`), generated
specifically for this index and never reused elsewhere. Policy-based
auth (`tpm2_policy*`, e.g., binding to PCR state or a policy secret) was
considered and **not recommended for the initial design** — it adds real
protocol complexity (a policy session per operation) for marginal benefit
here, since the actual trust boundary being protected is "who can reach
the daemon's narrow RPC," not "who can present TPM-level authorization"
(the daemon always presents the correct secret locally, regardless of
caller). Recorded as a possible future hardening, not required now.

## Secret storage and rotation

The index's own authorization secret is generated once at provisioning
time (e.g., via `tpm2_getrandom` or `openssl rand`, never a
human-chosen password) and delivered to the witness daemon via `systemd`
credentials (`LoadCredential=`/`SetCredential=`, tmpfs-backed, not a
plaintext file on persistent storage) — reusing the exact key-delivery
mechanism `TIER1_ACTIVATION_DECISIONS.md` already evaluated favorably
("systemd credential: Strong service-time delivery, tmpfs-backed,
unattended Linux startup") for the analogous encryption-key problem
elsewhere in this project, rather than inventing a new delivery
mechanism. **Rotation**: TPM2 NV index authorization values do not have
a simple in-place "rotate without losing history" operation matching
this project's needs — rotating this secret means `TPM2_NV_UndefineSpace`
+ re-provisioning a fresh index, i.e., the exact same procedure as
disaster recovery (G5). This is deliberate, not a gap: it matches
`HighWaterMark`'s own established "must be dedicated, explicitly
provisioned to the correct baseline" discipline (see "Initial baseline"
below) — a rotated/recovered counter is architecturally identical to a
freshly-provisioned one, and both need the identical explicit
baseline-seeding step.

The mTLS private key material for the guest↔host channel (below) is a
**second, independent** secret — never the same value as the TPM index's
own authorization secret, and never transmitted alongside it. Conflating
the two would let a network-level compromise reach the TPM authorization
boundary, breaking G2.

## Host service protocol

Minimal API, mirroring `AntiRollbackAnchor` exactly — no more, no fewer
operations:

```
read() -> { value: uint64 }
    Raises AnchorUnavailable if the TPM/service is unreachable.

advance(expected_current: uint64) -> { value: uint64 }
    Atomically: acquire a local lock serializing all TPM access (the
    physical device only ever processes one command at a time regardless
    of client concurrency); read the current counter value; if it does
    not exactly equal expected_current, return AnchorConflict WITHOUT
    touching the TPM at all (the CAS check happens in the daemon's own
    logic — TPM2_NV_Increment itself takes no "expected value" parameter);
    otherwise call TPM2_NV_Increment using the index's own stored
    authorization, then return the new value.
```

Transport: mutual TLS (mTLS), using a small dedicated certificate pair
generated specifically for this service (not a public CA) — pinned on
both ends, matching this project's own established TLS-trust discipline
(`TLSMode.STRICT`, never blanket-disabled verification) applied to a new
boundary. The daemon binds only to the interface reachable from VM 106,
or to all interfaces with host-level firewall restriction (see below) as
defense in depth regardless of transport security. **Open item,
unconfirmed this session**: whether the Proxmox host is itself a
Tailscale node (the guest is; the addresses supplied,
`192.0.2.27`/`192.0.2.39`, are plain LAN addresses, not Tailscale's
own `the CGNAT range Tailscale documents for itself` range) — if the host is also on the tailnet, Tailscale
ACLs scoping which peer may reach this port should be layered on top of
mTLS as additional defense in depth, not as a replacement for it; if not,
mTLS over the plain LAN path is the primary control and must not be
weakened to compensate.

## Guest-side integration design

A new concrete `AntiRollbackAnchor` implementation
(`anti_rollback_tpm_witness.py`, alongside the existing
`anti_rollback.py`, per `whole_store_anti_rollback.md`'s own
"Implementation checklist" — keep protocol and concrete backend in
separate files) implementing `read()`/`advance()` as thin, typed HTTP(S)
(mTLS) calls to the host witness service, translating
`AnchorUnavailableError` from any connection/TLS/timeout failure and
`AnchorConflictError` from the service's own conflict response — no new
behavior in `store.py`, which already only depends on the protocol.

## Security analysis

- **Rollback independence (the core property)**: satisfied. The guest
  has no local anchor state; an attacker who fully compromises/restores
  the guest's filesystem gains no path to the TPM counter except through
  the daemon's narrow, authenticated `advance()`, which only ever moves
  the counter forward from whatever value it currently, actually holds —
  there is no operation that decreases or resets it exposed to the
  network at all.
- **Blast radius of a guest compromise**: an attacker with full guest
  control can call `read()`/`advance()` as many times as the mTLS
  credential allows — meaning they can advance the counter (consuming
  "history," forcing a future legitimate mutation into
  `WholeStoreRollbackDetected` if the guest's own local high-water mark
  wasn't also correspondingly advanced) but cannot roll it backward.
  This matches the accepted threat model's framing that guidance/evidence
  mechanisms (and, by extension, this anchor) can only ever remove
  permission, never fabricate it — an attacker can deny service but
  cannot forge a false "not rolled back" signal.
- **Blast radius of a Proxmox host compromise**: out of scope for this
  anchor specifically — a host-level compromise is a strictly larger
  threat class than anything `ADR-011` claims to defend against (the host
  already has unlimited access to the guest's disk images via the
  hypervisor layer regardless of this design). Not a new gap introduced
  by this design.
- **Network eavesdropping**: mTLS prevents passive observation of
  `advance()` values and prevents an unauthenticated third party from
  issuing requests at all — the guest's own compromise (above) remains
  the realistic threat model, not network interception.
- **Foreign NV index safety (G4)**: the enumerate-then-select strategy
  and the owner-hierarchy-only definition step are the two structural
  protections; the provisioning commands below never reference any
  existing handle.

## Replay protection and concurrency

`advance()`'s own CAS semantics (compare `expected_current` against the
actual current value before touching the TPM) defeat naive request
replay by construction — a replayed old `advance` request carries a
now-stale `expected_current` and is rejected as `AnchorConflict` without
side effects. mTLS's own session framing provides transport-level replay
resistance as well. The daemon should additionally rate-limit requests
per source (defense against replay-flood/DoS noise, not a correctness
requirement) — a concrete numeric limit is not set by this design pass,
matching this project's own established "no numeric defaults without
evidence" discipline for `rate_policy.py`. Concurrency: the daemon
serializes all TPM access behind one local lock (the physical device
processes one command at a time regardless); the guest is architecturally
a single local process per this project's existing single-appliance
design, so no cross-client concurrency scenario is expected in practice,
but the daemon's serialization must not assume it.

## Fail-closed behavior

Unreachable TPM, unreachable service, or unreachable network all surface
as `AnchorUnavailableError` to `HighWaterMark.before_executing_transition()`
— already-implemented, already-tested behavior in the guest: `EXECUTING`
transitions are refused; `PREPARED`, load, and audit-inspection paths are
unaffected (G4 of the generic spec). No new fail-closed logic is needed
on the guest side; the witness daemon itself must not cache or fabricate
a value when the TPM is genuinely unreachable — a device error must
propagate as unavailable, never as a stale last-known value.

## Service privilege separation

- Dedicated, non-root system user (not `root`, not any Proxmox-management
  group `pveproxy`/`www-data`/etc.) with access to `/dev/tpmrm0` (the
  kernel TPM Resource Manager device — not raw `/dev/tpm0`; the resource
  manager safely serializes/multiplexes sessions for any other local TPM
  consumer on the host, avoiding an exclusive-access conflict with, e.g.,
  disk-encryption tooling that might also use the TPM). Access granted
  via the conventional `tss`/`tpm` group membership or an explicit udev
  rule, not broad device permissions.
- No other host privileges. Specifically not part of any group with
  Proxmox VM/storage/network management capability — a compromise of this
  daemon must not, by itself, grant any Proxmox administrative capability.

## systemd hardening requirements

`User=`/`Group=` fixed to the dedicated account (or `DynamicUser=`),
`NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`,
`PrivateTmp=true`, `ProtectKernelModules=true`, `ProtectKernelLogs=true`,
`ProtectClock=true`, `RestrictRealtime=true`, `LockPersonality=true`,
`MemoryDenyWriteExecute=true`, `RestrictAddressFamilies=AF_INET AF_INET6`
(scoped to exactly what the mTLS listener needs), `CapabilityBoundingSet=`
empty (device access via `DeviceAllow=/dev/tpmrm0 rw` in a scoped unit,
not a capability), `SystemCallFilter=@system-service`,
`LoadCredential=` for both the TPM index secret and the mTLS private key
— never plaintext files on persistent storage.

## Firewall requirements (not applied by this document)

The daemon's listening port must be reachable only from VM 106's address
(`192.0.2.27`), deny-by-default otherwise — whether enforced via
Proxmox's own per-node firewall or host-level `nftables`. **This is a
requirement for eventual deployment, not performed here** — "modifying
Proxmox firewall/network configuration" is explicitly not authorized by
this task.

## Backup / restore / physical-host replacement

- **Guest-side** VM backup/snapshot/restore/clone of VM 106: unaffected
  by design — no local anchor state exists in the guest to roll back.
- **Host OS** backup/restore/reinstall: the daemon's own bookkeeping may
  need reinstallation/redeployment, but the counter's true value lives in
  the TPM chip itself, not on any host disk image — restoring the host
  OS from backup does not roll the physical counter back.
- **Physical host or TPM chip replacement**: total, unavoidable loss of
  the counter's history. Requires the same re-provisioning procedure as
  initial setup, explicitly treated as "no prior anchor exists" — per
  `ADR-011`'s own stated safe default, not silently continued as if nothing
  happened. Whoever performs this must also reset the guest-side store's
  persisted high-water mark to match the new counter's actual initial
  value (see "Initial baseline" below) — skipping this step reopens
  exactly the gap `ADR-011` exists to close.

## Initial baseline — a real correctness finding, not a formality

**A freshly-defined TPM2 NV counter does not initialize to 0 on its
first increment.** Per the TPM2 specification's own NV_Increment
behavior (confirmed via tpm2-tools documentation research, not assumed):
when a counter-type index's `TPMA_NV_WRITTEN` attribute is clear (never
previously written), `TPM2_NV_Increment` initializes it to **the TPM's
own tracked largest-ever NV-counter value across the device's lifetime**
(a global monotonicity guarantee spanning counter deletion/recreation,
specifically so a deleted-and-redefined counter can never restart low
enough to be exploited) — then increments from there. Given this TPM
already has 3 active counters, the new project counter's real first
value is an **unpredictable, non-zero** number, not 1.

This directly interacts with `HighWaterMark.read()`'s own documented
default: it returns 0 when no local row exists yet, and its own
docstring already anticipates exactly this class of problem ("The
configured anchor must therefore be dedicated to the store and start at
0, **or be explicitly provisioned to the correct baseline** by whoever
sets up the concrete backend"). Without an explicit baseline-seeding
step, the very first real `EXECUTING` attempt after provisioning would
compare the TPM's true (large, non-zero) value against the store's
default-0 persisted mark, mismatch, and incorrectly raise
`WholeStoreRollbackDetected` on a perfectly legitimate first use — a
real, blocking correctness bug if this step is skipped.

**Required provisioning step, non-optional**: immediately after the
index's first `tpm2_nvincrement`, read the resulting value and seed the
guest-side store's `anchor_state` row (the existing, already-implemented,
HMAC-authenticated table `HighWaterMark._persist()` already writes to)
with exactly that value, before any real `EXECUTING` transition is ever
attempted against this store. This is provisioning-time administrative
work, not a code change to `HighWaterMark` itself — the existing
`_persist()` method already supports writing an arbitrary starting value;
what's needed is an explicit one-time invocation of it with the TPM's
actual first-read value, not a new mechanism.

## Provisioning procedure (commands listed, NOT executed)

Read-only reconnaissance (safe to run today, still not run by this
session):

```
tpm2_getcap handles-nv-index                    # enumerate all 14 existing handles exactly
tpm2_getcap properties-fixed                     # reconfirm NV_COUNTERS / NV_COUNTERS_AVAIL
tpm2_getcap properties-variable                  # check DA lockout counter scope (see NV attributes, above)
```

Mutating (require their own separate authorization before execution —
listed here for completeness of the design, per this task's explicit
instruction, not as pre-authorized):

```
# 1. Generate the index's dedicated authorization secret (never printed/logged in full)
tpm2_getrandom 32 > /run/credentials/.../nv-index-auth   # exact delivery path TBD with systemd creds design

# 2. Define the index (handle chosen from step-1 enumeration, avoiding all 14 existing + the 0x01c00000-0x01ffffff TCG-reserved range)
tpm2_nvdefine -C o -s 8 -a "authread|authwrite|nt=1" -p <secret> 0x01XXXXXX

# 3. First increment (establishes TPMA_NV_WRITTEN; initializes to the TPM's largest-ever counter value, NOT 0 -- see "Initial baseline")
tpm2_nvincrement -C 0x01XXXXXX -P <secret> 0x01XXXXXX

# 4. Read the resulting actual value immediately
tpm2_nvread -C 0x01XXXXXX -P <secret> -s 8 0x01XXXXXX --print-yaml

# 5. Seed the guest-side store's HighWaterMark with exactly the value from step 4
#    (administrative one-time operation against the pfsense-mcp-server store, not a TPM command)
```

## Required tests

- Unit tests for the new `anti_rollback_tpm_witness.py` implementation
  against a mocked witness-service transport (never a real TPM or network
  call in offline tests, matching every other Tier 1 module's existing
  `MockTransport`-equivalent convention) — covering the happy path,
  `AnchorConflictError` on mismatch, `AnchorUnavailableError` on
  connection/TLS/timeout failure.
- A dedicated test proving the CAS check happens in the daemon's own
  logic before any TPM call, not after (matches the existing anti-
  rollback spec's "confirm the check happens before, not after" review
  discipline, applied to this backend specifically).
- An integration-style test (against a software TPM simulator, e.g.
  `swtpm` running standalone for test purposes only — **never** as this
  project's actual production anchor, a distinction worth stating
  explicitly given §"Option 3" of the topology review) exercising a real
  `tpm2_nvdefine`/`tpm2_nvincrement`/`tpm2_nvread` cycle offline, to prove
  the daemon's TPM-interaction logic is correct before it ever touches
  the real hardware.
- A specific regression test for the "Initial baseline" finding above:
  simulate a freshly-provisioned counter whose first real value is
  non-zero, and confirm the seeding step (not the store's own 0-default)
  is what the first real `EXECUTING` transition compares against.

## Activation requirements

- [x] `ADR-011` backend decision made (this document, 2026-08-10).
- [ ] Primary-source TCG registry confirmation of the exact safe NV-index
      handle sub-range (this document's range guidance is corroborated by
      secondary/community sources; the primary TCG PDF was not
      successfully fetched during this review).
- [ ] `tpm2-tools` installed on the Proxmox host — its own separate,
      explicitly requested step (not authorized by this document).
- [ ] Read-only enumeration (`tpm2_getcap handles-nv-index`/
      `properties-fixed`/`properties-variable`) run and reviewed.
- [ ] NV index provisioned (steps 1–5 above) — its own separate,
      explicitly requested authorization, naming the exact chosen handle.
- [ ] `anti_rollback_tpm_witness.py` implemented and tested offline.
- [ ] Witness daemon implemented, systemd-hardened, and deployed on the
      Proxmox host.
- [ ] Host firewall configured to restrict the daemon's port to VM 106
      only.
- [ ] `store.py`'s `anti_rollback_anchor=None` default flipped to a hard
      refusal at activation time (already flagged as pending, unchanged,
      in `whole_store_anti_rollback.md`).
- [ ] `ADR-011`'s own `Status:` field updated from "Recommended — pending
      owner decision" once this backend is fully provisioned and verified
      end-to-end, not merely designed.
