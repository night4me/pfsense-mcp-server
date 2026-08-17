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
2b. **Planning slice — `SELECT TARGET → EVALUATE VALIDITY → ASSESS
   PREREQUISITES → GENERATE PLAN`, stopping before `PROVISIONING` —
   implemented (2026-08-10).** Not itself one of Phases C–F below (none
   of those are complete — no axis has moved past `DISCOVERED`/
   `PREREQUISITES_VERIFIED` toward a real `PROVISIONING`/`ACTIVE`
   transition). Instead, this is a read-only **planning** layer over
   Phase B's own discovery evidence: `pfsense-mcp-security plan
   --capability-posture <value> --anchor-assurance <value>` compares
   current state against an explicit target, enforces `ADR-021`'s
   validity constraint, and generates an ordered, structured,
   never-executed description of what *would* need to happen — drawing
   on the same requirement/state-machine detail Phases C–F describe
   below, without performing any of it. See "Planning slice —
   implemented" below for the actual commands, example output, exact
   files, and the full mutation-free argument. **A generated plan is
   never authorization to execute it** — selecting a target is intent,
   not execution authorization; no `select`/`provision`/`apply`
   subcommand exists yet.
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

## Planning slice — implemented (2026-08-10)

A second `pfsense-mcp-security` subcommand, `plan`, layered entirely on
top of Phase B's own `discover_security_posture()` — no new source of
live evidence, no new `pfsense_mcp.tier1` isolation exemption (this
module never imports `pfsense_mcp.tier1` at all; see "Read-only
guarantees" below). Bridges "what state do I have?" to "what would need
to happen to reach a selected target?" without performing any of it:
`DISCOVER → SELECT TARGET → EVALUATE VALIDITY → ASSESS PREREQUISITES →
GENERATE PLAN`, then stop, before `PROVISIONING`.

### Usage

```
$ pfsense-mcp-security plan --capability-posture write_protected --anchor-assurance hardware_witness
pfsense-mcp-security: security posture plan (analysis only -- not authorization)

Plan digest (schema v1): bff0326a38a3e8a3f8d2c9b72a6518c4129fef70b43282cabc70ca6f94f47f89  (plan identity only -- not authorization)
Current:  capability_posture=read_only  anchor_assurance=hardware_witness (provisioned_verified)
Target:   capability_posture=write_protected  anchor_assurance=hardware_witness
Target validity:      valid
Overall status:       plan_generated
Safe to proceed:      True  (plan validity only -- not authorization or execution readiness; see notes below)
capability_posture:   upgrade
anchor_assurance:     no_change

Steps (ordered; none executed):
  [1] (anchor_assurance) No change required
      ...
  [2] (capability_posture) Populate WriteEndpoints allow-list
      ...
      blocked:                False
  [3] (capability_posture) Set PFSENSE_PROFILE=engineer
      ...
      blocked:                False
  [4] (capability_posture) Obtain Milestone-9-class WRITE activation decision
      ...
      implementation_available: False
      blocked:                True
      blocked_reason:         src/pfsense_mcp/tools/write/ is a deliberately empty placeholder and
                               SUPPORTED_CAPABILITIES_THIS_BUILD excludes every *_WRITE Capability in
                               this build -- no WRITE tool implementation exists to register, regardless
                               of configuration or authorization state.

This plan is analysis only. It is NOT authorization to execute any step listed below. [...]
```

The example above is abbreviated for length (`...`/`[...]` mark omitted
lines; every value shown is drawn unaltered from a real, captured run
against this project's own real production environment). It also
demonstrates a finding this slice
made by reading the actual code, not asserting it: even after every
mechanically-real configuration step (`WriteEndpoints`, `PFSENSE_PROFILE`),
the final activation step is honestly reported as `implementation_available:
False` — `src/pfsense_mcp/tools/write/` is a deliberately empty
placeholder and no `*_WRITE` `Capability` is active anywhere in this
build, so there is currently no WRITE tool to register regardless of
authorization. **Valid design state is not the same as currently
implementable target** — the same distinction this slice also applies
to `anchor_assurance=software` (`docs/SECURITY_POSTURE_PROVISIONING.md`'s
own Phase G note), now shown to apply to WRITE activation itself.

`pfsense-mcp-security plan --json` emits the same information as
deterministic, sorted-key JSON for automation. Exit codes: `0` whenever
a plan was generated (including "already satisfied" and "valid target,
backend not implemented" — neither is a usage error); `2` if the
requested target combination is invalid per `ADR-021`, if the current
state shows a store/witness mismatch, or if the current anchor-assurance
state is indeterminate (e.g. a malformed/foreign file already at the
configured store path) — reusing `discover`'s own exit-code-2 meaning
rather than reinventing it.

### Read-only guarantees

- Never imports `pfsense_mcp.tier1` in any form — its only source of
  live evidence is the one `discover_security_posture()` call at the
  top of `generate_security_posture_plan()`; everything after that is
  pure, deterministic computation over already-collected evidence.
  Proven structurally (AST inspection) by
  `tests/test_security_plan_isolation.py`, and behaviorally by a test
  that replaces `sqlite3.connect`/`builtins.open` with functions that
  raise `AssertionError` if called, then generates plans for every
  target combination — passing only because plan generation performs
  no I/O of its own.
- **A generated plan is never authorization to execute it** — every
  `SecurityPosturePlan` carries this statement in its own `notes` field
  (machine-readable, not only documentation), proven present across
  every reachable target combination by a dedicated test. No field in
  the plan's schema could be mistaken for a "go ahead" signal: every
  prospective mutating step declares its own
  `authorization_required` value, and none is ever `none_required`.
- **`safe_to_proceed` means only "the plan itself is safe to present/
  continue reasoning about," never authorization.** Clarified explicitly
  (ADR-022 owner review, 2026-08-11; behavior and the published JSON
  schema unchanged) with a `SecurityPosturePlan` class docstring, an
  inline CLI caveat on the human-output line, and a `plan --help` epilog
  sentence — `True` means only that the target is architecturally valid
  and current evidence shows no detected anomaly; it does not mean
  approved, executable, that mutation is permitted, or that every step
  is unblocked or implemented.
- **Hardware witness never implies WRITE**: selecting
  `anchor_assurance=hardware_witness` never changes
  `capability_posture_transition`; reaching `write_protected` always
  requires its own explicit `--capability-posture write_protected`
  target, proven by dedicated tests.
- **Unavailable/indeterminate evidence is never treated as a clean
  slate.** Found during this session's own adversarial self-review: an
  early version of this slice, given a current anchor-assurance state
  of `unknown` (evidence_state `store_error`/`configuration_invalid` --
  e.g. a malformed/legacy/foreign file already at the configured store
  path), silently generated an ordinary "provision from scratch" plan,
  papering over the fact that *something* unexplained already occupies
  that path. Fixed: an indeterminate current anchor-assurance value now
  short-circuits to `PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE`
  (`safe_to_proceed=False`, no steps generated) before any transition
  logic runs, proven by dedicated regression tests.
- **Store/witness mismatch blocks progression, never treated as an
  ordinary prerequisite gate.** A detected mismatch forces
  `PlanOverallStatus.BLOCKED_ANOMALY_DETECTED` and every prospective
  mutating step to `blocked=True` with a mismatch-specific reason --
  distinct from the ordinary "the anchor-assurance axis must reach its
  target first" sequencing block an upgrade plan can otherwise show.
- **Raw string targets cannot bypass the validity constraint.** Found
  during adversarial self-review: `CapabilityPosture`/`AnchorAssurance`
  are `(str, Enum)` hybrids, and this module's internal logic compares
  them with `is`. A caller passing a plain, value-equal string instead
  of the actual enum member would satisfy every `==` check but silently
  fail every `is` check -- including the one guarding `write_protected`
  + `none` -- without raising. Fixed: both targets are coerced through
  their `Enum` constructor (idempotent for an already-correct member,
  raises `ValueError` for anything invalid) at the very top of
  `generate_security_posture_plan()`, closing this for every caller,
  not only this slice's own CLI (which already only ever constructed
  real enum members). Proven by a dedicated regression test.
- **Downgrade is DEACTIVATE, never DEPROVISION.** Every downgrade step
  this slice generates stops/disables the witness daemon only -- TPM NV
  counter value and the guest-side store/high-water-mark are described
  as untouched, and the step's own description states that TPM NV
  index deletion and guest-side store/integrity-key deletion are not
  included in this plan and would require their own separate
  authorization (`ADR-021` question 4). `MutationClass.DESTRUCTIVE_DEPROVISIONING`/
  `AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION` are declared
  in the schema for future forward-compatibility only and are never
  emitted by this slice -- proven both statically (AST) and
  behaviorally (a sweep over every reachable target combination and a
  representative set of current states).
- **Joint downgrades never pass through the disallowed
  `write_protected` + `none` combination, even momentarily.** When both
  axes downgrade at once, the capability-posture axis's steps are
  ordered before the anchor-assurance axis's, so WRITE deactivates
  first -- proven by a dedicated test.
- Evidence strings never introduce a new raw configured path/URL beyond
  what `security_discovery.py` (already audited) supplies via
  `current.*.evidence` -- this slice's own new text (step descriptions,
  `blocking_findings`, `notes`) never embeds one either, proven by
  dedicated regression tests against both an unreachable-witness and a
  malformed-store-path scenario.

### Files

- `src/pfsense_mcp/security_plan.py` (new) — the planning data model
  and logic: target validity evaluation, per-axis transition
  classification, ordered `PlanStep` generation, cross-axis ordering.
  No `pfsense_mcp.tier1` import.
- `src/pfsense_mcp/security_cli.py` (modified) — new `plan` subcommand:
  argument parsing (`--capability-posture`/`--anchor-assurance` with
  `choices=` excluding `unknown`), human/`--json` formatting, exit-code
  handling.
- `tests/test_security_plan.py`, `tests/test_security_plan_isolation.py`
  (new); `tests/test_security_cli.py` (modified, `plan`-subcommand
  coverage added).

### What the planning slice deliberately does not do

- No `select`/`apply`/`provision` subcommand — selecting a target here
  is intent, not execution authorization; no later command in this
  build turns a plan into action.
- No interactive prompting or confirmation flow, and no `--dry-run`
  flag — deliberately: this entire slice already behaves as a mandatory
  dry-run, and introducing `--dry-run` terminology without a
  corresponding non-dry-run mode would wrongly imply one exists.
- No `AnchorAssurance.SOFTWARE` provisioning capability — a target
  naming it is honestly reported as `TargetValidity.VALID_NOT_IMPLEMENTED`
  (a valid design-state, not a currently implementable one), never
  silently treated as invalid or silently treated as available.
- No repair/reconciliation of a detected mismatch or indeterminate
  current state — both are reported as blocking findings, never acted
  on.

## Doctor/preflight slice — implemented (2026-08-17)

A third `pfsense-mcp-security` subcommand, `doctor`, layered on top of
`discover_anchor_assurance()` (Phase B's own witness-readiness
evidence, reused completely unchanged) plus new, narrowly-scoped
filesystem checks over the four fixed Tier 1 artifact-exchange paths
`tier1/production_runtime.py` defines. Answers one question directly:
**can an operator safely begin a new Tier 1 signing ceremony right
now?** Two real incidents motivated it (see `docs/ROADMAP.md`'s
"Ceremony TTL/operator UX" section): a pre-positioned stale
`confirmation-signed.bin` left over from a completed ceremony, and a
signer whose local witness-store snapshot had gone stale, reporting
`provisioned_mismatch`. Both are exactly what `doctor` now catches
before an operator spends a ceremony's own limited validity window
finding out the hard way.

### What `doctor` checks

1. **Artifact-exchange path cleanliness** (4 checks, one per fixed
   path): the signed-authorization inbox, the pending-confirmation
   outbox, the signed-confirmation inbox, and the (W3 Slice 5A)
   authorization-preview outbox must each be **absent** before a fresh
   ceremony begins — a leftover file at any of these paths silently
   blocks the next ceremony's own write, because artifact writes use
   `write_secure_new()`'s exclusive-create discipline and never
   overwrite. For each configured path, `doctor` verifies: the env var
   is set; the configured value is an absolute path; the containing
   directory exists and is writable; and no file (including a broken
   symlink) already exists at the exact path.
2. **Witness readiness** (1 check): reuses
   `security_discovery.discover_anchor_assurance()` verbatim — no
   second witness client, no new TPM/network code. A ceremony is
   witness-ready only when the resulting `evidence_state` is exactly
   `provisioned_verified`; every other state (including
   `provisioned_mismatch`, the same anomaly `discover` itself already
   flags) is reported as not ready.

### What `doctor` deliberately does not check

- The full `build_production_runtime()` prerequisite set — store
  configuration, encryption/authority key files, the consumption
  store, and so on. A `doctor` result of `READY` means "the
  artifact-exchange paths are clean and the witness is currently
  verified," not "every precondition `build_production_runtime()`
  itself checks is satisfied."
- Whether the operator has a valid, unexpired authorization/
  confirmation artifact in hand — that is the ceremony's own concern,
  not a preflight question.
- Anything about pfSense itself (connectivity, credentials, the target
  alias's current state) — `doctor` never constructs a `PfSenseClient`
  or makes a network call to pfSense.

### Usage

```
$ pfsense-mcp-security doctor
pfsense-mcp-security: Tier 1 ceremony readiness check (read-only, diagnostic only)

Overall: NOT READY

  [OK] Signed PlanAuthorizationV2 inbox (artifact_exchange.authorization_inbox)
        /var/lib/pfsense-mcp/exchange/authorization-signed.bin is absent, as expected before a new ceremony.
  [OK] Unsigned PendingConfirmationRequest outbox (artifact_exchange.confirmation_pending)
        /var/lib/pfsense-mcp/exchange/confirmation-pending.bin is absent, as expected before a new ceremony.
  [FAIL] Signed ConfirmationEvidence inbox (artifact_exchange.confirmation_signed)
        A file already exists at /var/lib/pfsense-mcp/exchange/confirmation-signed.bin -- likely left over
        from a previous ceremony. Archive or remove it by hand before starting a new one; doctor never does
        this automatically.
  [OK] Non-authorizing AuthorizationPreview outbox (artifact_exchange.authorization_preview)
        /var/lib/pfsense-mcp/exchange/authorization-preview.bin is absent, as expected before a new ceremony.
  [OK] TPM anti-rollback witness readiness (witness_readiness)
        Witness verified and matches the persisted baseline (value=4).

Diagnostic only -- no artifact was deleted, moved, or repaired, and no witness/store state was changed.
```

`pfsense-mcp-security doctor --json` emits the same information as
deterministic, sorted-key JSON for automation, with each check's
`status` one of `pass`/`fail`/`not_configured` (deliberately three-way,
not a bool — "you haven't configured this yet" and "you configured it
and it's currently broken" call for different operator action, even
though both make the overall result `NOT READY`).

### Exit codes

Deliberately different from `discover`/`plan`, which exit `0` even when
"entirely unconfigured" — `doctor`'s whole purpose is a binary
readiness gate for automation, so an unconfigured host is genuinely
`NOT READY`, not a clean report of nothing-to-do.

- `0` — every check passed (`READY`).
- `1` — one or more checks failed or are not configured (`NOT READY`).
- `2` — usage error (argparse's own existing convention, unchanged).

### Operator remediation guidance

- A `FAIL` on an artifact-path check names the exact file. Confirm the
  prior ceremony genuinely completed (or was abandoned) before moving
  it aside by hand — `doctor` never does this for you, on purpose.
- A `FAIL` on the witness-readiness check with `evidence_state=
  provisioned_mismatch` is the same security-relevant anomaly
  `discover` already surfaces — investigate before proceeding; do not
  attempt a ceremony against a witness whose live value disagrees with
  the persisted baseline.
- A `FAIL` with any other `evidence_state` (`configuration_invalid`,
  `store_error`, `configured_unprovisioned`, `provisioned_unverified`,
  `provisioned_unreachable`) means the witness could not be positively
  confirmed current — run `pfsense-mcp-security discover` for the full
  diagnostic detail behind the summary.

### Read-only guarantees

- Never imports `pfsense_mcp.tier1` in any form — proven structurally
  by `tests/test_security_doctor_isolation.py`, mirroring
  `tests/test_security_discovery_isolation.py`'s own approach. Unlike
  `security_discovery.py`, this module is not a tier1-isolation
  exemption at all; it has no need to be.
- The four fixed artifact-exchange env var names are a deliberate,
  comment-linked *duplication* of `production_runtime.py`'s own
  constants, never an import — `tests/test_security_doctor.py::
  test_artifact_path_env_var_names_match_production_runtime` fails
  loudly if the two ever drift apart.
- Never deletes, moves, archives, or overwrites a file — every
  artifact-path check only reads filesystem metadata
  (`Path.exists()`/`Path.is_dir()`/`os.access()`), proven by dedicated
  tests that plant a stale artifact, run `doctor`, and assert the file
  is byte-for-byte unchanged afterward.
- Never mutates witness or store state — delegates entirely to
  `discover_anchor_assurance()`, itself already proven never to call
  `advance()` or any provisioning primitive; a dedicated test's fake
  witness anchor raises if `advance()` is ever called, proof rather
  than mere omission.
- No secrets, private keys, tokens, or artifact contents appear in any
  check's `detail` text — only file paths (operationally necessary for
  "archive/remove this file") and the same non-sensitive witness
  counter value `discover` already prints.

### Files

- `src/pfsense_mcp/security_doctor.py` (new) — the readiness-check data
  model and logic: the four artifact-path checks, the witness-readiness
  check, the combined `DoctorResult`. No `pfsense_mcp.tier1` import.
- `src/pfsense_mcp/security_cli.py` (modified) — new `doctor` subcommand:
  argument parsing, human/`--json` formatting, exit-code handling.
- `tests/test_security_doctor.py`, `tests/test_security_doctor_isolation.py`
  (new); `tests/test_security_cli.py` (modified, `doctor`-subcommand
  coverage added).

### What the doctor/preflight slice deliberately does not do

- No automatic cleanup of a stale artifact, ever — `doctor` diagnoses,
  an operator (or a future, separately-authorized command) decides
  what to do about it.
- No witness/store repair or reconciliation of any kind.
- Does not check the full `build_production_runtime()` prerequisite
  set (see "What `doctor` deliberately does not check" above) — a
  possible, separately-scoped future extension, not attempted here.
- No `--fix`/`--clean`/`--repair` flag of any kind on this subcommand.

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
