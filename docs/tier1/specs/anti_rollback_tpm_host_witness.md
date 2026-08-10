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
HMAC-authenticated table `HighWaterMark._persist()` writes to) with
exactly that value, before any real `EXECUTING` transition is ever
attempted against this store. This is provisioning-time administrative
work, not a code change to `HighWaterMark` itself. Full crash-safe
procedure below.

## Provisioning state machine (2026-08-10 addendum — adversarial review, no mutation)

**Governing principle, applied to every state below without exception:
this procedure never repairs an ambiguity by decrementing, resetting, or
recreating the counter, and never silently trusts locally-cached
progress notes over directly re-inspectable TPM/store state. Any state
that cannot be proven from direct inspection halts for human review —
it is never guessed.**

### Design choice: state is derived, not logged

The procedure does **not** rely on a separate "provisioning progress"
log file as its source of truth (a log can itself drift from reality
after a crash). Instead, every invocation — first attempt or resumed —
begins with a **state-discovery phase** that re-derives exactly how far
provisioning has progressed from three directly-inspectable, independently
durable facts:

1. **TPM state**: does the candidate handle exist
   (`tpm2_nvreadpublic <handle>`)? If so, is `TPMA_NV_WRITTEN` set? If so,
   what does `tpm2_nvread` (with the correct index auth) currently return?
2. **Store state**: does `anchor_state` have a `high_water_mark` row?
   What value, and does its HMAC verify?
3. **Completion marker**: does `anchor_state` have a *separate*,
   dedicated `anchor_provisioning_complete` row (new key, same
   HMAC-authenticated table and mechanism `HighWaterMark._persist()`
   already uses — not the operational `high_water_mark` row itself) for
   this exact handle? This is the explicit "provisioning finished, safe
   for normal witness operation" gate the operational value's mere
   presence does not, by itself, prove — it is written only after
   TPM/store agreement is independently re-verified (state S8 below), not
   assumed from seeding alone.

This mirrors this project's own already-established discipline elsewhere
(`store.py`'s `_verify_schema()`/`_check_registry_integrity()`: re-derive
and re-verify from scratch on every load, never trust a cached belief
about prior state).

### States

| State | Meaning | How state-discovery detects it |
|---|---|---|
| S0 `NOT_STARTED` | No candidate handle chosen | No new handle beyond the 14 known-foreign ones |
| S1 `HANDLE_SELECTED` | A specific unused handle chosen (operator decision, not yet on the TPM) | Purely local/operator record — not yet TPM-visible; see "accidentally rerun" below for why this state alone proves nothing |
| S2 `SECRET_STORED` | Dedicated index-auth secret generated and durably stored (e.g., confirmed written to its systemd-credential-backed file) | Local file/credential-store presence — must be confirmed **durable** before proceeding to S3, since Proxmox reboot before this point would lose an only-in-memory secret |
| S3 `INDEX_DEFINED` | `tpm2_nvdefine` succeeded; index exists, `TPMA_NV_WRITTEN` still clear | `tpm2_nvreadpublic <handle>` succeeds; `TPMA_NV_WRITTEN` clear |
| S4 `INCREMENT_ISSUED` | First `tpm2_nvincrement` sent — **ambiguous on its own**, never trusted alone | Not independently detectable — S4 is a transient sub-state of the S3→S5 attempt, resolved by re-checking `TPMA_NV_WRITTEN`, never assumed from "the command was sent" |
| S5 `VALUE_READ` | `TPMA_NV_WRITTEN` confirmed set; actual value V read via `tpm2_nvread` | `tpm2_nvreadpublic` shows `TPMA_NV_WRITTEN` set; `tpm2_nvread` (idempotent, side-effect-free) returns V |
| S7 `STORE_SEEDED` | `anchor_state.high_water_mark` row written with value V | Row present, HMAC verifies, value = V |
| S8 `AGREEMENT_VERIFIED` | Fresh re-read of TPM value and store value confirmed **exactly equal** | Recomputed at verification time, not cached from S5/S7 |
| S9 `PROVISIONING_COMPLETE` | Dedicated `anchor_provisioning_complete` marker written (handle, timestamp, verified value) | Row present, HMAC verifies |
| S10 `WITNESS_OPERATIONAL` | Normal `read()`/`advance()` operation permitted | S9 confirmed present for the configured handle |

(There is no separate "S6" — reading the TPM value (S5) is itself
side-effect-free and always safely re-derivable at any later point, so no
extra persisted checkpoint is needed between S5 and S7; an earlier draft
of this design considered one and it was redundant.)

### Behavior after interruption at every step (the full failure-injection list)

- **Process crash, at any point**: re-run state discovery. Since every
  underlying operation (`tpm2_nvdefine`, `tpm2_nvincrement`,
  `_persist()`'s single SQL statement) is itself atomic at the
  TPM/SQLite level, a crash always leaves the system in a well-defined
  *prior completed* state — never a torn one. Resume from exactly what
  discovery finds. Never assumed from memory of "what step was I on."
- **Proxmox reboot**: TPM NV state (definedness, `TPMA_NV_WRITTEN`,
  value) is non-volatile by definition and survives. The one real risk is
  a reboot **before S2's secret is confirmed durably written** — if the
  secret only ever existed in an interactive shell's memory, it is lost,
  and the index (if already defined, S3+) becomes permanently
  unreadable/unwritable except via owner-hierarchy undefine-and-restart.
  This is exactly why S2 must be confirmed durable *before* S3 begins,
  not treated as a formality.
- **Guest reboot**: does not touch TPM state at all. Only affects S7 (an
  uncommitted store write is simply absent after reboot, per SQLite's own
  existing durability guarantees this project already relies on
  elsewhere) — state discovery correctly reports "not yet seeded," safe
  to resume.
- **Network interruption**: provisioning steps 2–5 (define/increment/
  read) are performed as a **local, on-host operator session on the
  Proxmox host itself** — never through the eventual daemon's own network
  RPC — specifically to remove network interruption as a hazard for these
  steps entirely. Network interruption only affects S7 (seeding the
  guest-side store, a separate, later, resumable step; see Guest reboot
  above).
- **Index defined but local metadata not written** (e.g., an operator's
  own notes about "which handle did I pick" are lost): never a problem by
  design — the *original* 14 foreign handles are recorded durably in this
  project's own documentation/report **before** provisioning begins
  (see "Handle-selection rule" below); the project's own handle is always
  re-derivable as "whichever handle now exists beyond that recorded set
  of 14," never dependent on fragile session/operator memory.
- **First increment succeeds but response is lost**: never retry
  `tpm2_nvincrement` blindly. Re-check `TPMA_NV_WRITTEN` via
  `tpm2_nvreadpublic` first. If set, the increment already took effect —
  proceed to read the actual value (S5) and use it, regardless of what
  value might have been expected. If clear, it did not take effect —
  safe to issue exactly one increment.
- **First increment succeeds, store seeding fails**: discovery shows
  `TPMA_NV_WRITTEN=true`, value V (re-readable, idempotent); no
  `high_water_mark` row. Resume: re-read V, seed the store with V. No
  re-increment, ever.
- **Store seeded, final marker not committed**: discovery shows TPM value
  V, store value V (agree), no `anchor_provisioning_complete` row. This
  is S8-done/S9-not-done. Resume: re-verify agreement (idempotent), then
  write the completion marker. No counter mutation needed.
- **Provisioning command accidentally rerun**: state discovery's
  completion-marker check (S9) is the primary guard — if present for this
  handle, the procedure **halts immediately**, refusing to touch the TPM
  at all, and reports "already provisioned." If rerun mid-sequence
  (S1–S8), discovery correctly resumes from the true current state
  (all steps above are individually idempotent/safely resumable by
  design) rather than restarting blindly. `tpm2_nvdefine` against an
  already-defined handle fails outright at the TPM level
  (`TPM_RC_NV_DEFINED`) as a second, independent guard.
- **Existing project handle discovered from a prior partial attempt**:
  diff the current full handle list against the recorded 14 foreign
  handles. If **exactly one** new handle is found, treat it as the likely
  prior attempt, but do not assume — verify its public attributes
  (owner-hierarchy, `nt=1`, 8-byte size) match this design's expected
  shape before touching it. If attributes don't match, or **more than
  one** unexpected new handle is found, halt for human review — never
  guess which one is "ours."
- **Wrong auth material supplied**: a single authorization failure
  against a believed-to-be-ours index is a **hard stop**, not a retry
  trigger — repeated automated retries risk triggering TPM dictionary-
  attack lockout (see "NV index type and attributes," `no_da`, above).
  Never fall back to a cached/guessed alternate secret; never fall back
  to owner-hierarchy auth as a workaround (`ownerread`/`ownerwrite` were
  deliberately not granted). If the secret is confirmed genuinely lost,
  the only safe path is owner-hierarchy `tpm2_nvundefine` (its own,
  separately authorized action) followed by re-provisioning from S0 —
  never secret recovery/brute-force.
- **Concurrent provisioning attempt**: `tpm2_nvdefine` against an
  already-existing handle fails at the TPM level, providing natural
  mutual exclusion for S3. Concurrent increments both succeed
  sequentially (the TPM serializes commands) — safe, since S5 always
  reads the actual resulting value rather than assuming a specific one.
  Store-side, the one-time seeding write (S7) must use **insert-only,
  fail-if-exists** semantics — deliberately **not** reusing
  `HighWaterMark._persist()`'s existing `INSERT ... ON CONFLICT DO
  UPDATE` pattern, which is correct for normal operational advancement
  but wrong for a one-time provisioning seed, where a second concurrent
  writer discovering a row already present must be a loud, visible
  conflict, never a silent overwrite.
- **Counter value unexpectedly greater than any locally recorded value**:
  this is the *expected*, designed-for consequence of the "counters don't
  start at 0" finding, not an anomaly to correct. During provisioning:
  log it clearly for operator awareness, then seed the store with the
  actual observed value — never adjusted, never rejected. During normal
  post-provisioning operation, this is already the existing, already-
  implemented, already-safe "anchor ahead of persisted" case
  `whole_store_anti_rollback.md`'s own Failure modes table documents
  ("Safe: this is the expected 'anchor ahead' case, not rollback").

### Handle-selection rule (rule proposed; no candidate selected)

1. Record the exact 14 existing handle values (not merely the count)
   durably in project documentation, **before** any provisioning
   attempt — this durable record is what makes "which handle is newly
   ours" always re-derivable later, independent of session/operator
   memory (see "local metadata not written," above).
2. Enumerate fresh via `tpm2_getcap handles-nv-index` at provisioning
   time; confirm it still shows exactly the same 14.
3. Select one unused handle in the conventional owner/application range
   (`0x01000000`–`0x01bfffff`), avoiding the TCG-reserved
   platform-certificate range (`0x01c00000`–`0x01ffffff`). **This
   document proposes the rule; it does not select or define the specific
   candidate handle** — that remains the first concrete output of
   actually running step 2 against the real, current handle list, per
   this task's explicit instruction not to define anything yet.

### NV attributes / auth model — reconfirmed against authoritative sources

`authread|authwrite|nt=1` (`TPM_NT_COUNTER`), owner hierarchy, no
`ownerread`/`ownerwrite`, no `policyread`/`policywrite`, `no_da` left
**unset** (dictionary-attack protection active) — unchanged from the
prior design pass, now re-confirmed with exact primary-source citations
for the two questions this task asked to pin down precisely:

- **Creation** is authorized by the hierarchy named in `tpm2_nvdefine -C`
  (owner, `-C o`, this design's choice) — confirmed directly from
  tpm2-tools' own documentation of `-C, --hierarchy`.
- **Deletion** (`tpm2_nvundefine`) hierarchy default: *"owner"* hierarchy
  when `TPMA_NV_POLICY_DELETE` is **clear**, *"platform"* when it is set
  ([tpm2_nvundefine manual](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_nvundefine.1.md)).
  This design never sets `TPMA_NV_POLICY_DELETE`, so deletion defaults to
  **owner** hierarchy — confirming, with a direct citation rather than
  inference, that G5's recovery path (owner-hierarchy undefine-and-
  reprovision if the index's own secret is lost) is real and does not
  require any attribute this design didn't already choose to set.
- **Normal `read()`/`advance()`** operations are protected by the
  index's own dedicated authorization value (`authread`/`authwrite`)
  only — never owner-hierarchy auth, never a policy session. Unchanged
  from the prior pass; restated here because this task asked for it to
  be reconfirmed precisely, not merely repeated.

### Secret generation and storage — reconfirmed, with a concrete process-argument fix

The prior draft's provisioning command listed `-p <secret>` as a literal
command-line argument — on review, this is exactly the exposure this
task's own instruction warns against ("must not appear... in process
arguments if avoidable"). tpm2-tools' own authorization-formatting
documentation directly addresses this: a `file:` prefix (or `file:-` for
stdin) supplies an auth value from a file/pipe instead of a literal
argument, "to prevent information leakage, [since] passwords passed as
options can be read from the process list or common shell history
features"
([tpm2-tools Authorization Formatting](https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/authorizations.md)).
**Corrected design**: the secret is generated once (e.g., `tpm2_getrandom`
piped directly into a credential file, never echoed to a terminal or
captured in shell history), written directly to its final systemd-
credential-backed location, and every subsequent `tpm2_nv*` invocation
references it via `-p file:/path/to/credential` (or piped via `file:-`),
never as a literal `-p <value>` argument. This satisfies every constraint
in this task's list: never in Git (not a project file at all — lives only
in the host's credential store); never in reports (this document names
the mechanism, never the value); never in shell history (file-based, not
typed); never in process arguments (file-based); never in logs (the
daemon must never log the secret, and `tpm2_nv*` commands using `file:`
don't place it in their own argv either); never in the guest (the secret
never leaves the Proxmox host); never in ordinary VM backups (it isn't
guest state — see "Backup / restore / physical-host replacement," above).

### Provisioning procedure (commands listed, NOT executed)

Read-only reconnaissance (safe to run, still not run by this session):

```
tpm2_getcap handles-nv-index                    # re-confirm exactly the 14 known-foreign handles
tpm2_getcap properties-fixed                     # reconfirm NV_COUNTERS / NV_COUNTERS_AVAIL
tpm2_getcap properties-variable                  # check DA lockout counter scope (see NV attributes, above)
```

Mutating (each requires its own separate authorization before execution
— listed for design completeness only, per this task's explicit
instruction, not pre-authorized; state-discovery per the state machine
above must precede every one of these on every invocation, including the
very first):

```
# 0. State discovery (read-only; run before every step below, including on first attempt)
tpm2_getcap handles-nv-index                                  # confirm still exactly 14 + [0 or 1] new
tpm2_nvreadpublic <candidate-handle> 2>/dev/null               # exists? TPMA_NV_WRITTEN set?

# 1. Generate the index's dedicated authorization secret directly to its credential file (never echoed/logged)
tpm2_getrandom 32 > <systemd-credential-path>/nv-index-auth

# 2. Define the index (handle from the enumerate-then-select rule above; NOT chosen by this document)
tpm2_nvdefine -C o -s 8 -a "authread|authwrite|nt=1" -p file:<systemd-credential-path>/nv-index-auth 0x01XXXXXX

# 3. First increment (establishes TPMA_NV_WRITTEN; initializes to the TPM's largest-ever counter value, NOT 0)
tpm2_nvincrement -C 0x01XXXXXX -P file:<systemd-credential-path>/nv-index-auth 0x01XXXXXX

# 4. Read the resulting actual value immediately (idempotent -- safe to re-run after any interruption)
tpm2_nvread -C 0x01XXXXXX -P file:<systemd-credential-path>/nv-index-auth -s 8 0x01XXXXXX --print-yaml

# 5. Seed the guest-side store (insert-only, fail-if-exists -- administrative operation, not a TPM command)
#    with exactly the value from step 4.

# 6. Re-read TPM value AND store value fresh; confirm exact equality (S8) -- administrative verification, not a TPM mutation.

# 7. Write the anchor_provisioning_complete marker (S9) -- administrative operation, not a TPM command.
```

### Cleanup / recovery procedure for every partial state

| Discovered state | Safe action |
|---|---|
| S0 (nothing done) | Proceed normally from step 0. |
| S1/S2 only (handle chosen/secret stored, TPM untouched) | Proceed; nothing to clean up — the TPM was never touched. |
| S3 (defined, unwritten) | Resume at step 3 (first increment). Not a failure state. |
| S3 with `TPMA_NV_WRITTEN` set but store empty (S5 reached, S7 not) | Resume at step 4 (read) then step 5 (seed) — never re-increment. |
| S7 done, S9 marker missing | Resume at step 6 (re-verify) then step 7 (mark complete) — no TPM interaction needed. |
| S9 present for this handle | **Halt.** Already provisioned; report and stop, do not touch the TPM. |
| Auth failure against believed-ours handle | **Halt.** Human review required; see "Wrong auth material," above — never retry automatically. |
| Ambiguous handle discovery (0 or 2+ unexpected new handles) | **Halt.** Human review required; see "Existing project handle discovered," above. |
| Confirmed-lost secret, index already defined | Owner-hierarchy `tpm2_nvundefine` (its own, separately authorized action), then restart from S0. Never attempted automatically by this procedure. |

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

**Provisioning-state-machine tests, required before any real deployment
(offline, against the `swtpm` simulator above — never real hardware)**:

- State-discovery correctness test for every state S0–S9: given a
  simulator seeded into each state directly, discovery must report
  exactly that state, not a neighboring one.
- Idempotent-resume test for every interruption point in the
  failure-injection list above: run the full procedure, kill it after
  each individual step, re-run from scratch, and assert the end state is
  identical to an uninterrupted run — for every step, not just a sample.
- Rerun-after-complete test: run the full procedure to S9, then run it
  again from scratch; assert it halts immediately at the discovery
  phase and makes zero further TPM calls.
- Ambiguous-handle-discovery test: simulate two unexpected new handles
  appearing; assert the procedure halts for human review rather than
  guessing.
- Wrong-auth test: simulate an authorization failure on the believed-ours
  handle; assert a single hard stop, zero automatic retries.
- Concurrent-seed test: two simulated concurrent provisioning attempts
  racing on the store-seeding step; assert exactly one succeeds and the
  other observes a loud conflict, never a silent second write.
- Secret-never-in-argv test: assert the actual subprocess argument lists
  the provisioning script constructs never contain the raw secret value
  — only `file:`-prefixed paths — closing the process-argument exposure
  this task's own review caught in the prior draft.

## Activation requirements

- [x] `ADR-011` backend decision made (this document, 2026-08-10).
- [ ] Primary-source TCG registry confirmation of the exact safe NV-index
      handle sub-range (this document's range guidance is corroborated by
      secondary/community sources; the primary TCG PDF was not
      successfully fetched during this review).
- [x] `tpm2-tools` installed on the Proxmox host, completed manually,
      read-only, 2026-08-10 — confirmed by the owner: TPM operational,
      `TPM2_PT_NV_COUNTERS = 3`, `TPM2_PT_NV_COUNTERS_AVAIL = 10`, all 14
      existing indices enumerated and inspected via `tpm2_nvreadpublic`,
      no project index created, no mutating command executed.
- [x] Read-only enumeration (`tpm2_getcap handles-nv-index`/
      `properties-fixed`/`properties-variable`) run and reviewed — see
      above.
- [ ] NV index provisioned (provisioning procedure above) — its own
      separate, explicitly requested authorization, naming the exact
      chosen handle. See "Smallest safe first mutating slice" below for
      the recommended scope of that authorization.
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

## Smallest safe first mutating slice (2026-08-10 addendum)

The narrowest possible first authorization is **provisioning steps 1–7
of the state machine above, and nothing else**: generate the secret,
define the index, perform exactly one increment, read it back, seed the
store, verify agreement, write the completion marker. This deliberately
excludes — as separate, later, independently-authorized steps — witness
daemon implementation or deployment, guest-side `AntiRollbackAnchor`
integration code, `store.py`'s `anti_rollback_anchor=None` default being
flipped to a hard refusal, host firewall changes, and anything related to
WRITE, the ADR-019 catalogue, or pfSense lab work. Provisioning the
counter is meaningful and independently verifiable on its own (the
verification step, S8, proves TPM and a *test* seed agree) without any
of those.

**Owner authorization wording, copy/paste-ready:**

> "I authorize running provisioning steps 1–7 against the Proxmox host's
> physical TPM exactly as specified in
> `docs/tier1/specs/anti_rollback_tpm_host_witness.md`'s provisioning
> state machine: generate a dedicated index-authorization secret (stored
> only as a host-local credential file, never in Git/logs/process
> arguments), define exactly one new NV counter index at a handle chosen
> by first re-running `tpm2_getcap handles-nv-index` and selecting an
> unused handle outside the TCG-reserved range, perform exactly one
> `tpm2_nvincrement`, read back the actual resulting value, and verify
> TPM/store agreement. This does not authorize deploying the witness
> daemon, guest-side integration code, flipping `store.py`'s anchor
> default, firewall changes, WRITE activation, or any pfSense mutation —
> each remains its own separate, later authorization. If any state
> encountered during provisioning does not match what state-discovery
> expects (per the state machine's own halt conditions), stop and report
> back rather than proceeding."
