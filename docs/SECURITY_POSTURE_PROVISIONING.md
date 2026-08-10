# Security posture provisioning — design specification (`pfsense-mcp-security setup`)

Status: architecture/design specification only, companion to
[`ADR-021`](adr/ADR-021-security-posture-provisioning.md) (the
authoritative decision record — read that first, including its
"Revision note" and "Model comparison" sections; this document expands
the **adopted two-axis model**'s mechanics). **Nothing here is
implemented.** No wizard code, no CLI entrypoint, no new environment
variable, and no runtime behavior exists yet. Building any of it is a
separate, future, explicitly-scoped authorization — this document does
not grant one.

## Purpose

`ADR-021` decided that a future `pfsense-mcp-security setup`
CLI/wizard should be built around **two independent axes** — capability
posture (`read_only`/`write_protected`) and anchor assurance
(`none`/`software`/`hardware_witness`) — rather than one linear ladder,
because the ladder cannot represent this project's own real deployment
state (`read_only` capability with `hardware_witness` assurance
already fully provisioned and verified). This document works out the
mechanics: the full per-axis requirement set, the detailed state
machine, which existing code areas a real implementation would
eventually touch (for future scoping — **none are modified by this
document**), and a phased implementation plan for if/when building the
wizard is separately authorized.

## The two axes, in detail

### Capability posture axis

| Value | Capability profile (`ADR-004`) | Config | WRITE |
|---|---|---|---|
| `read_only` | `auditor` | `PFSENSE_PROFILE=auditor` (today's default) | Inactive |
| `write_protected` | `engineer`, populated | `PFSENSE_PROFILE=engineer` + `WriteEndpoints` allow-list entries per the separately-governed WRITE endpoint risk process (`WRITE_ENDPOINT_RISK_MATRIX.md`, `ADR-020`) | Active — requires anchor assurance `≠ none` (validity constraint) and its own Milestone-9-class activation decision (`TIER1_ROADMAP.md`) |

Recovery Contract machinery (authoritative contracts `ADR-006`,
confirmation authority `ADR-012`, reconciliation authority `ADR-013`,
sealed executor `ADR-014`, rate/blast-radius defaults `ADR-015`) is
already implemented and tested, currently unreachable from production.
`write_protected` posture is what would first make it reachable —
identically, regardless of which anchor-assurance value accompanies it.

### Anchor assurance axis

| Value | `ADR-011` backend | Config | Daemon |
|---|---|---|---|
| `none` | No anchor | N/A | N/A |
| `software` | Remote append-only witness (non-hardware) — `ADR-011`'s own accepted "mandatory fallback" category | Not yet designed in detail — no remote-witness implementation exists in this repository today, only the TPM-backed one | N/A |
| `hardware_witness` | TPM-backed host witness (`ADR-011`'s backend decision) | The seven `PFSENSE_TIER1_*`/`WITNESS_*` variables already in real operational use (`PFSENSE_TIER1_STORE_PATH`, `PFSENSE_TIER1_STORE_KEY_FILE`, `PFSENSE_TIER1_EXPECTED_HANDLE`, `PFSENSE_TIER1_WITNESS_BASE_URL`, `PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE`, `PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE`, `PFSENSE_TIER1_WITNESS_SERVER_CA_FILE`) | Persistent, `systemd`-managed (`ADR-011`'s "Deployment model decision") — not a manually-started process |

**Note**: `software` (remote witness) is named in `ADR-011`'s own
architecture as the mandatory fallback where no TPM exists, but no
implementation of it exists in this codebase — only the TPM-backed
witness has been built. A real `write_protected` + `software`
combination is therefore currently **designed but not implementable**
until that backend exists; this is a real, named implementation gap,
not an oversight of this document.

### Validity constraint

**`write_protected` requires anchor assurance `≠ none`** — directly
sourced from `ADR-011`'s own accepted text ("if neither [TPM nor
remote witness] is available, mutation must stay blocked"). This is
the one rule a real implementation must enforce; see "State machine"
below for exactly where.

### Fail-closed enforcement — orthogonal to both axes

Reaching `hardware_witness` anchor assurance's `ACTIVE` state means the
anchor is provisioned, deployed, and read-verified — it does **not**
mean `store.py`'s `anti_rollback_anchor=None` → hard-refusal fail-closed
behavior is enabled. That remains its own, separate, future,
explicitly-scoped decision, unaffected by either axis, exactly as
`ADR-021`'s safety invariants state.

## Recommended UX presets

The wizard's default, simple front door (not the full grid):

| Preset | Capability posture | Anchor assurance |
|---|---|---|
| READ-only (default) | `read_only` | `none` |
| Software-protected WRITE | `write_protected` | `software` *(blocked until the remote-witness backend exists — see note above)* |
| Hardened hardware TPM witness | `write_protected` | `hardware_witness` |

**Advanced/staged path** (not a default preset): pre-provision
`hardware_witness` anchor assurance while remaining `read_only` —
exactly this project's own real deployment history. Should be
discoverable but not forced on operators who only want a simple
three-choice front door.

`read_only` + `software` is deliberately **not** offered as a preset
(low value: pre-provisioning a remote witness with no WRITE decision
made yet) — left as an open UX question in `ADR-021` (#6) whether to
expose it at all behind the advanced path.

## State machine — per axis

Each axis runs its **own independent instance** of the six-state
lifecycle (`DISCOVERED → SELECTED → PREREQUISITES_VERIFIED →
PROVISIONING → ACTIVE`, plus `DOWNGRADING`). They are not
synchronized — either can be at any state while the other is at any
other state, and this is intentional, not an inconsistency to resolve.

| State | Capability-posture axis | Anchor-assurance axis |
|---|---|---|
| `DISCOVERED` | Current `PFSENSE_PROFILE` value, `WriteEndpoints` contents | TPM device presence, existing Tier 1 store, existing daemon reachability |
| `SELECTED` | Operator names target (`read_only`/`write_protected`) | Operator names target (`none`/`software`/`hardware_witness`) |
| `PREREQUISITES_VERIFIED` | If target is `write_protected`: **re-check the anchor-assurance axis's current value here — this is where the validity constraint is enforced.** If anchor assurance is `none`, halt and direct the operator to the anchor axis first (or accept a combined preset that provisions both) | Re-derive TPM presence/store state fresh, never trust a prior `DISCOVERED` result without re-checking (mirrors the TPM provisioning spec's "state is derived, not logged" discipline) |
| `PROVISIONING` | Populate `WriteEndpoints`, set `PFSENSE_PROFILE=engineer` — each step individually confirmed | For `hardware_witness`: the already-specified provisioning state machine in `anti_rollback_tpm_host_witness.md` (generate secret, define NV index, first increment, seed store, mark complete), reused not reinvented — each step individually confirmed |
| `ACTIVE` | Requires the Milestone-9-class activation decision (`TIER1_ROADMAP.md`) — its own explicit approval, separate from every `PROVISIONING` step's confirmation | For `hardware_witness`: does **not** require the Milestone-9 decision — that gate is specific to WRITE activation, not anchor readiness. This is the axis independence's clearest consequence: this project already reached anchor-assurance `ACTIVE` without WRITE ever reaching it |
| `DOWNGRADING` | Deactivates WRITE; **does not touch the anchor-assurance axis** — a provisioned anchor is left in place | Independent of capability posture; downgrading to `none` while capability posture is `write_protected` `ACTIVE` must itself be rejected or forced to jointly downgrade capability posture (never leave the disallowed combination reachable) |

**Interruption behavior** (either axis): re-derive current state from
the environment itself on the next invocation, never from a separate,
potentially-stale progress log — matching the TPM provisioning state
machine's own already-established discipline. Every ambiguous state
halts for human review; none auto-resolves.

## Affected code areas (identified for future scoping — none modified by this document)

| Area | Current state (verified by reading, not modified) | Eventual relevance |
|---|---|---|
| `src/pfsense_mcp/profiles.py` | `Profile`/`AuditorProfile`/`EngineerProfile`, `get_profile()` (`ADR-004`) | Capability-posture axis maps 1:1 to this; wizard would set `PFSENSE_PROFILE` accordingly, not modify this module |
| `src/pfsense_mcp/config.py` | Loads `PFSENSE_PROFILE` (default `auditor`), fail-closed validation (`ADR-008`) | Wizard-generated config must still pass this same validation unchanged — no bypass. Anchor-assurance axis config is currently read only by the inert `tier1_anchor_check.py` path, not `config.py` itself |
| `src/pfsense_mcp/write_endpoints.py` | `WriteEndpoints`, currently zero entries | `write_protected` `PROVISIONING` would populate this per the separately-governed allow-list process — independent of which anchor-assurance value accompanies it |
| `src/pfsense_mcp/application.py` | Calls only `tier1_anchor_check.run_anchor_startup_check()`; imports nothing else from `pfsense_mcp.tier1` | A real fail-closed enforcement wiring decision would be separate from, and later than, either axis reaching `ACTIVE` |
| `src/pfsense_mcp/tier1/production_store.py`, `scripts/tier1_store_bootstrap.py` | Inert operator tooling, read-only status by default, `--provision` requires explicit flags | The anchor-assurance axis's `hardware_witness` `PROVISIONING` state would invoke this existing tooling, not reimplement it — independently of capability-posture axis state |
| `witness_daemon/` + its `systemd` unit | Implemented, real-hardware-verified, deployable | An anchor-assurance-axis "install the daemon" provisioning step would automate what is today a manual deployment |
| `tests/tier1/test_isolation.py` | Narrow, named exemptions only (`tier1_anchor_check.py`, `anti_rollback_tpm_witness.py`) | Any new wizard-side import of `pfsense_mcp.tier1` for provisioning would need its own narrow, reviewed exemption — same discipline, not relaxed |
| `docs/CONFIGURATION.md` | Documents only the currently-production-relevant env vars | Would eventually need the `PFSENSE_TIER1_*`/`WITNESS_*` vars documented once the anchor-assurance axis is real — independent of whether the capability-posture axis has also advanced |
| `Makefile`'s `write-allow-list-check`/`write-capability-check` | Assert zero entries / 0-of-3 active | Would need to evolve from "assert empty" to "assert matches the declared capability-posture axis state" — no equivalent check exists yet for anchor assurance and one would need designing |

## Phased implementation plan (for if/when separately authorized — not scheduled, not committed)

Ordering reflects the two axes' independence — anchor-assurance work is
**no longer gated behind capability-posture work**, correcting this
document's earlier draft (which had implicitly assumed hardware
provisioning follows WRITE protection, contradicting this project's own
actual history).

1. **Phase A — remaining design closure.** Resolve `ADR-021`'s
   remaining open questions (3–6: allow-list sharing, decommissioning
   path, interactive-vs-declarative UX, whether to expose `read_only` +
   `software`). Produces an accepted `ADR-021` (status → Accepted).
2. **Phase B — read-only discovery only.** Implement `DISCOVERED` and
   `PREREQUISITES_VERIFIED` for both axes, independently: a CLI that
   reports current capability posture and anchor assurance, writes
   nothing. Lowest-risk, independently useful today.
3. **Phase C — capability-posture axis, `read_only`.** Trivial by
   construction (already the default) but completes the
   `SELECTED → ACTIVE` path end to end for the simplest case, proving
   the state machine and confirmation UX.
4. **Phase D — anchor-assurance axis, `hardware_witness`, independent
   of capability posture.** Automates what this project has already
   done once by hand: TPM provisioning + persistent daemon deployment.
   **Not gated on Phase E** — can run before, after, or without it, as
   this project's own history already demonstrates.
5. **Phase E — capability-posture axis, `write_protected`.** Gated on
   Milestone 9's own activation decision being separately reached, and
   on the validity constraint (anchor assurance `≠ none`) already being
   satisfied by prior Phase D work (or by provisioning it as part of
   this phase, for an operator who skipped D).
6. **Phase F — downgrade paths for both axes**, built last, once
   upgrade paths for each are proven independently.
7. **Phase G — `software` anchor-assurance backend**, if ever
   prioritized: the remote append-only witness `ADR-011` names as the
   mandatory non-TPM fallback has no implementation in this repository
   today. Its own separate, future design/implementation effort,
   unblocked by and independent of every phase above.

Each phase is its own future authorization; nothing above is scheduled.

## Open design questions

See `ADR-021`'s "Open design questions" section (as revised) — this
document does not duplicate or resolve them, only provides the
mechanical grounding they'd need once resolved.

## References

- [`ADR-021`](adr/ADR-021-security-posture-provisioning.md) —
  authoritative decision record, including the ladder-vs-two-axis
  comparison this document's structure follows
- [`ADR-011`](adr/ADR-011-whole-store-anti-rollback-anchor.md) and
  [`anti_rollback_tpm_host_witness.md`](tier1/specs/anti_rollback_tpm_host_witness.md) —
  the anchor/daemon mechanics the `hardware_witness` anchor-assurance
  value reuses
- [`TIER1_ROADMAP.md`](TIER1_ROADMAP.md) — Milestone 9 activation gate
  (capability-posture axis only)
- [`WRITE_ENDPOINT_RISK_MATRIX.md`](WRITE_ENDPOINT_RISK_MATRIX.md),
  [`ADR-020`](adr/ADR-020-milestone-0-first-write-capability-candidate.md) —
  the separately-governed WRITE endpoint allow-list process
- [`CONFIGURATION.md`](CONFIGURATION.md) — current, unmodified
  environment-variable reference
- `reports-ai/reviews/WITNESS_DAEMON_DEPLOYMENT_CONVERGENCE_REVIEW_2026-08-10.md` —
  independent evidence this document's `read_only` + `hardware_witness`
  example state is grounded in
