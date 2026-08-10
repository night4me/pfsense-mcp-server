# Security posture provisioning — design specification (`pfsense-mcp-security setup`)

Status: companion specification to
[`ADR-021`](adr/ADR-021-security-posture-provisioning.md), **Accepted**
(2026-08-10, owner — see `ADR-021`'s "Acceptance note"). Read `ADR-021`
first, including its "Revision note," "Second revision note," "Model
comparison," and "Acceptance note" sections; this document expands the
**accepted two-axis model**'s mechanics. **Acceptance is architectural
only — nothing here is implemented.** No wizard code, no CLI
entrypoint, no new environment variable, and no runtime behavior exists
yet. Building any of it is a separate, future, explicitly-scoped
authorization this document does not grant.

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

`read_only` + `software` is deliberately **not** offered as a preset,
and **not offered behind the advanced path either** —
`ADR-021`'s question 6 resolved this as intentionally hidden until the
`software` backend exists (Phase G) and a concrete operator need is
identified. The advanced path therefore surfaces exactly one extra
combination beyond the three presets: `read_only` + `hardware_witness`.

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
| `DOWNGRADING` (= DEACTIVATE, per `ADR-021` question 4 — never DEPROVISION) | Deactivates WRITE; **does not touch the anchor-assurance axis, including the daemon/service state, not only the abstract value** — a provisioned anchor and a running-or-stopped daemon are both left exactly as they are | Independent of capability posture; stops/disables the witness daemon but leaves TPM NV counter value and guest-side store/high-water-mark untouched (fully reversible: re-enable, resume); downgrading to `none` while capability posture is `write_protected` `ACTIVE` must itself be rejected or forced to jointly downgrade capability posture (never leave the disallowed combination reachable, even momentarily) |

**DEPROVISION is explicitly not part of this table.** TPM NV index
deletion and guest-side store/integrity-key deletion are a separate,
rare, manually-authorized procedure outside the routine per-axis
lifecycle entirely — see `ADR-021`'s "Resolving open questions 3–6"
(question 4) for the full DEACTIVATE-vs-DEPROVISION distinction and
what must never happen automatically.

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

## Declarative vs. interactive provisioning (resolves `ADR-021` question 5)

Both modes are supported, but not symmetrically:

| Axis / step | Interactive | Declarative/non-interactive |
|---|---|---|
| Either axis's `DISCOVERED`/`PREREQUISITES_VERIFIED` (read-only) | Supported | Supported freely — no consent needed beyond invoking the tool |
| Capability-posture axis `PROVISIONING`/`DOWNGRADING` (`PFSENSE_PROFILE`, `WriteEndpoints` — software-only) | Supported | Supported, **with itemized, named authorization** (e.g. an explicit list of exactly which steps are authorized) — never a blanket `authorize: true` flag |
| Anchor-assurance axis `PROVISIONING`/`DOWNGRADING` that touches physical TPM state | Supported (the only mode) | **Not supported** — matches this project's standing practice of never automating TPM-facing commands (`CURRENT_MISSION.md`'s "Standing SSH constraint") |
| Anchor-assurance DEPROVISION (TPM/store deletion) | Supported, its own separate authorization, outside the routine lifecycle entirely | Not supported |

A first declarative/non-interactive invocation should require a
`--dry-run`/preview mode showing exactly what would be authorized and
executed without executing it, matching this project's general
practice of never running a live-host command without a prior
read-only preview. A real implementation would need a declarative
config format (new code area, not yet designed) capable of the same
per-step itemization the interactive flow already requires — sketching
that format is future implementation work, not part of this design
phase.

## Phased implementation plan (for if/when separately authorized — not scheduled, not committed)

Ordering reflects the two axes' independence — anchor-assurance work is
**no longer gated behind capability-posture work**, correcting this
document's earlier draft (which had implicitly assumed hardware
provisioning follows WRITE protection, contradicting this project's own
actual history).

1. **Phase A — design closure — complete, and accepted.** `ADR-021`'s
   open questions 3–6 (allow-list sharing, decommissioning path,
   interactive-vs-declarative UX, whether to expose `read_only` +
   `software`) are resolved; see `ADR-021`'s "Resolving open questions
   3–6" section. **`ADR-021` is Status: Accepted** (owner, 2026-08-10 —
   see its "Acceptance note"). Acceptance is architectural only —
   Phases B onward below each remain their own separate, future,
   explicitly-scoped implementation authorization; none is granted by
   acceptance.
2. **Phase B — read-only discovery only — implemented (2026-08-10).**
   `DISCOVERED`, and where evidence allows `PREREQUISITES_VERIFIED`,
   detail for both axes, independently: the `pfsense-mcp-security discover`
   CLI reports current capability posture and anchor assurance, writes
   nothing. See "Phase B — implemented" below for the actual commands,
   example output, and exact files. **No provisioning/setup subcommand
   exists yet** — Phase C onward remain future, separately-authorized work.
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

## Phase B — implemented (2026-08-10)

A real, installed `pfsense-mcp-security` CLI, registered the same way
`pfsense-mcp-server` is (`[project.scripts]` in `pyproject.toml`) and
shipped in the same wheel (it lives in `src/pfsense_mcp/`, unlike
`witness_daemon/`/`scripts/tier1_store_bootstrap.py`, which are
deliberately excluded from the package). One subcommand exists:
`discover`. It is genuinely read-only — see "Read-only guarantees"
below.

### Usage

```
$ pfsense-mcp-security discover
pfsense-mcp-security: security posture discovery (read-only)

Capability posture: read_only
  configured profile name:    auditor (valid=True)
  write capabilities active:  0 of 3
  allow-list entries:         0
  - PFSENSE_PROFILE='auditor', 0 WRITE capabilities active.

Anchor assurance:    hardware_witness
  evidence state:              provisioned_verified
  store configured:            True
  store exists:                True
  seeded / complete:           True / True
  handle:                      0x01500000
  baseline:                    2
  provisioned_at:              2026-08-10T15:10:16.416050+00:00
  witness configured:          True
  witness reachable:           True
  witness value:               2
  witness matches baseline:    True
  - Store provisioning record: handle=0x01500000 baseline=2 provisioned_at=2026-08-10T15:10:16.416050+00:00.
  - Witness value (2) matches persisted high-water mark (2).

Note: read_only + hardware_witness is a valid, representable combination
in the accepted ADR-021 two-axis model -- not one of the three curated
setup presets, but fully supported.
This report is read-only discovery only (ADR-021 Phase B). No
provisioning/setup subcommand exists yet.
```

The example above is real output, captured against this project's own
real production environment (the seven `PFSENSE_TIER1_*`/`WITNESS_*`
variables already in operational use) — proving Phase B's own
requirement that `read_only` + `hardware_witness` be recognized
accurately, not treated as a special case.

`pfsense-mcp-security discover --json` emits the same information as
deterministic, sorted-key JSON (`capability_posture`, `anchor_assurance`,
`notes`) for automation — verified byte-identical across repeated
invocations of the same environment.

Exit codes: `0` on a clean discovery result (including "nothing
configured" — that is not a failure); `2` if the anchor-assurance axis's
evidence state is `provisioned_mismatch` (a security-relevant anomaly:
the live witness value disagrees with the persisted high-water mark) —
signalling automation without conflating "just unconfigured" with
"something is actually wrong."

### Read-only guarantees

- Never calls `provision_anchor_baseline()`, `TpmHostWitnessAnchor.advance()`,
  or anything that constructs a `RecoveryContract`/`MutationExecutor`/
  `WriteApiClient`. Proven structurally (AST inspection of the actual
  shipped source, not the module's own docstring) by
  `tests/test_security_discovery_isolation.py`, and behaviorally by
  `tests/test_security_discovery.py`'s dedicated mutation-proof tests
  (a fake anchor whose `advance()` raises if ever called; a monkeypatched
  `provision_anchor_baseline` that raises if ever called — both tests
  pass because discovery never reaches either).
- Never calls `open_production_store()` / constructs
  `SqliteRecoveryContractStore` at all — its `__init__` always runs
  `_initialize_schema()` (`CREATE TABLE IF NOT EXISTS ...`), which is
  harmless for a healthy store but capable of creating missing tables
  as a side effect of merely looking, against a legacy/partial/foreign
  SQLite file. Instead calls the dedicated
  `read_only_anchor_provisioning_status()`
  (`src/pfsense_mcp/tier1/production_store.py`), which opens the store
  via SQLite's own `mode=ro` URI — the database engine itself refuses
  any DDL/DML attempt, a structural guarantee rather than a convention
  this module's own code happens to follow. A missing/incomplete/
  malformed schema surfaces as `store_error` evidence, never repaired.
  Found via pre-commit call-graph review (the original Phase B
  implementation went through `open_production_store()`) and fixed
  before this feature was ever committed; proven by dedicated
  regression tests asserting a foreign SQLite file (and a file with an
  incomplete `anchor_state` table) is left byte-for-byte unchanged and
  gains no new tables after discovery runs.
- Also never calls `read_only_anchor_provisioning_status()` (or
  anything else) against a store path that has not already been
  created on disk — SQLite's own `mode=ro` would refuse to create one,
  but the existence check happens first anyway, to keep "not
  provisioned" evidence accurate and avoid an avoidable error path.
  Mirrors `scripts/tier1_store_bootstrap.py`'s own existence check
  exactly; proven by a dedicated test asserting the store file (and its
  parent directory) still does not exist after discovery runs against
  an unconfigured-but-named path.
- `security_discovery.py` is the second, narrow, explicit exception to
  `pfsense_mcp.tier1` never being imported from outside its own package
  (`tier1_anchor_check.py` remains the first) — the isolation exemption
  list in `tests/tier1/test_isolation.py` now names both, and
  `security_cli.py` itself does not import `pfsense_mcp.tier1` at all,
  matching `application.py`'s own established pattern of only calling
  the exempted module's public functions.
- Evidence strings (which flow directly into `--json` output, intended
  for logging/automation) never embed a raw configured file path, URL,
  or unaudited third-party exception message. Several `Tier1Error`/
  `OSError`/`ssl.SSLError` messages from lower layers do embed absolute
  filesystem paths (e.g. a failed `ssl.SSLContext.load_cert_chain()`);
  discovery reports only the exception's *class name* in those cases,
  never `str(exc)` verbatim. Found during pre-commit review and fixed
  before this feature was ever committed; proven by dedicated
  regression tests asserting the raw configured path/URL never appears
  in evidence, for every failure state that could otherwise expose one.

### Files

- `src/pfsense_mcp/security_discovery.py` (new) — the read-only
  discovery data model and logic, structured dataclasses/enums, no
  logging or other side effects.
- `src/pfsense_mcp/security_cli.py` (new) — the actual
  `pfsense-mcp-security` entrypoint: argument parsing, human/`--json`
  formatting. Does not import `pfsense_mcp.tier1`.
- `src/pfsense_mcp/tier1/production_store.py` (modified) — added
  `read_only_anchor_provisioning_status()`, the genuinely read-only
  primitive `security_discovery.py` uses instead of
  `open_production_store()`. `open_production_store()` and
  `SqliteRecoveryContractStore` themselves are unchanged and remain
  the correct choice for every caller that needs a real,
  schema-guaranteed store (`scripts/tier1_store_bootstrap.py`,
  `tier1_anchor_check.py`).
- `pyproject.toml` — new `pfsense-mcp-security` console-script entry.
- `tests/test_security_discovery.py`, `tests/test_security_cli.py`,
  `tests/test_security_discovery_isolation.py` (new).
- `tests/tier1/test_isolation.py` — exemption list extended.

### What Phase B deliberately does not do

- No `select`/`provision`/`downgrade` subcommand — Phase C onward.
- No interactive prompting or confirmation flow — discovery needs none
  (it performs no mutating action), and the granular per-step consent
  model (`ADR-021`'s "User consent boundaries") only applies once a
  mutating subcommand exists.
- No declarative/config-file input — `discover` takes no target to
  authorize; the declarative-vs-interactive scoping table above applies
  starting at Phase C/D.
- `AnchorAssurance.SOFTWARE` is never resolved by Phase B — no
  remote-witness backend exists in this repository (Phase G); Phase B
  reports `unknown`/`none` rather than asserting a capability that
  cannot currently be verified.

## Open design questions

**All six of `ADR-021`'s original open questions are resolved** — see
its "Open design questions" and "Resolving open questions 3–6"
sections. This document does not duplicate the decisions, only
provides their mechanical grounding (the per-axis state-machine table,
the declarative-vs-interactive scoping table, and the affected-code
inventory above).

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
