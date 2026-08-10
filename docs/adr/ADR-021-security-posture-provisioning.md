# ADR-021: Guided security-posture provisioning (`pfsense-mcp-security setup`)

- **Status:** Proposed — architecture/design only. Nothing in this ADR
  authorizes building the wizard, activating WRITE, enabling fail-closed
  anchor enforcement, or performing any TPM/pfSense mutation.
- **Date:** 2026-08-10 (revised same day — see "Revision note" below)

## Revision note

This ADR's first draft proposed a strict three-rung ladder
(`read_only → write_protected → hardware_witness`). Before any commit,
a rigorous comparison against a **two-axis model** (capability posture
× anchor assurance) found the ladder cannot represent this project's
own actual, intentional, already-achieved deployment state — **READ-only
capability with a fully provisioned, functionally verified hardware TPM
witness** (`reports-ai/reviews/WITNESS_DAEMON_DEPLOYMENT_CONVERGENCE_REVIEW_2026-08-10.md`)
— without inventing a special-case rung that secretly reintroduces two
axes anyway. This revision adopts the two-axis model as the
architectural decision. The three original named profiles survive as
curated UX presets over that model, not as the exhaustive state space.
Full comparison in "Model comparison" below. This ADR was never
committed in its ladder form — this is not a supersession of an
accepted decision, only iteration before acceptance.

## Context

The project's security-relevant capabilities are currently selected by
several independent, low-level mechanisms an operator must each get
right individually: the `PFSENSE_PROFILE` environment variable
(`auditor`/`engineer`, [ADR-004](ADR-004-capability-profiles.md)), the
`WriteEndpoints` allow-list ([ADR-005](ADR-005-inert-tier-0-write-infrastructure.md)),
the Tier 1 production store env vars
(`tier1/production_store.py`), and — as of
[ADR-011](ADR-011-whole-store-anti-rollback-anchor.md) — a set of
witness-daemon connection variables for the TPM-backed anti-rollback
anchor. Nothing today presents these as one coherent, named choice.
`docs/ROADMAP.md`'s "Operator setup and security profiles" section
first named the target end state: a guided `pfsense-mcp-security setup`
CLI/wizard so an operator ends up with exactly the privilege level they
intended — never silently more.

This ADR is the requested architecture/design phase for that idea. **It
does not implement the wizard, any posture, WRITE, or fail-closed
enforcement.**

## Terminology decision: "posture," not "profile"

`ADR-004` already defines **capability profile** as a specific,
narrower, already-implemented mechanism: an enum
(`auditor`/`engineer`) selecting which MCP tool capabilities
`ToolRegistry.register_all()` registers (`src/pfsense_mcp/profiles.py`).
This ADR's operator-facing choice is a strictly higher-level concept —
called **security posture** throughout, to avoid colliding with
`ADR-004`'s already-accepted term. As of this revision, "posture" now
names a *point in the two-dimensional model below* (a capability-posture
value paired with an anchor-assurance value), not a single linear rung.

## Model comparison

### Model A (rejected): strict three-rung ladder

`read_only → write_protected → hardware_witness`, each a superset of
the one below, WRITE and anchor bundled into one linear choice.

### Model B (adopted): two independent axes

- **Capability posture**: `read_only` | `write_protected` — maps 1:1
  onto `ADR-004`'s capability profile (`auditor` | `engineer`).
- **Anchor assurance**: `none` | `software` | `hardware_witness` — maps
  onto `ADR-011`'s own already-accepted backend hierarchy (absent |
  remote append-only witness | TPM-backed host witness).

One validity constraint, directly derived from `ADR-011`'s own accepted
text ("TPM2 NV counter where the production host has one; a remote
append-only witness... as the **mandatory** fallback where it does not.
**If neither is available, mutation must stay blocked**"):

> **`write_protected` requires `anchor assurance ≠ none`.**

Of the six combinations, exactly one is invalid
(`write_protected` + `none`) and is rejected by that one rule. The
other five are all real, meaningful states:

| Capability posture | Anchor assurance | Valid? | Corresponds to |
|---|---|---|---|
| `read_only` | `none` | Yes | Today's actual default |
| `read_only` | `software` | Yes (low value, not a curated preset) | Pre-provisioned remote witness, WRITE still off |
| `read_only` | `hardware_witness` | Yes | **This project's actual current deployment** |
| `write_protected` | `none` | **No — rejected** | Disallowed by `ADR-011`'s own recommendation |
| `write_protected` | `software` | Yes | The original "software-protected WRITE" profile |
| `write_protected` | `hardware_witness` | Yes | The original "hardened hardware TPM witness" profile |

### Evaluation

- **Conceptual clarity**: the ladder conflates "what capability is
  exposed" with "what protects it." The anchor protects the Recovery
  Contract store's integrity — with WRITE inactive, the store never
  holds contracts, so provisioning the anchor ahead of time is a
  *readiness* property, not an active protection yet. The two-axis
  model has native vocabulary for that; the ladder does not.
- **Downgrade/upgrade semantics**: in the ladder, "hardware_witness →
  write_protected" (drop the hardware requirement, WRITE stays active)
  and "write_protected → read_only" (WRITE deactivates) are
  qualitatively different operations hiding under one ordinal relation
  — itself a symptom of two axes pretending to be one. The two-axis
  model also expresses a real operational need the ladder structurally
  cannot: deactivate WRITE while keeping a provisioned hardware anchor
  in place (a real, plausible request — expensive hardware setup
  shouldn't have to be redone to temporarily pause WRITE).
- **`ADR-004` compatibility**: capability posture maps exactly 1:1 onto
  the capability-profile enum. The ladder's `write_protected` and
  `hardware_witness` both collapsed onto `engineer` — a many-to-one
  relationship the two-axis model eliminates.
- **`ADR-011` compatibility — decisive**: `ADR-011` already states
  mutation must stay blocked without *some* anchor. The two-axis model
  expresses this as one explicit, testable constraint. The ladder had
  no clean way to state it — it was sitting unresolved as this ADR's
  original "open question 2."
- **Wizard UX**: a free 2×3 grid is not good default UX (one
  combination is invalid, and not all five valid ones are equally
  useful to most operators) — see "Recommended UX presets" below for
  how the model still supports simple, curated choices.
- **Rejecting invalid combinations**: one small, `ADR-011`-grounded
  rule rejects exactly the one invalid combination. The ladder cannot
  even pose the question — avoiding it only by being unable to
  represent a real, valid, already-achieved state.

**Model B (two axes) is adopted.** Model A is retained in "Alternatives
considered" with this reasoning, not deleted from the record.

## Decision

### Recommended UX presets (over the two-axis model, not a competing model)

The wizard's default, simple front door still offers three named,
curated combinations — preserving the original request's spirit
exactly, now precisely grounded:

| Preset name | Capability posture | Anchor assurance |
|---|---|---|
| **READ-only** (default) | `read_only` | `none` |
| **Software-protected WRITE** | `write_protected` | `software` |
| **Hardened hardware TPM witness** | `write_protected` | `hardware_witness` |

An **advanced/staged path** — not a default preset, but explicitly
supported by the model — lets an operator pre-provision hardware anchor
assurance while remaining on the `read_only` capability posture,
deciding on WRITE separately and later. This is not a hypothetical: it
is exactly this project's own real deployment history (the TPM/witness
daemon sequence was fully built and verified with WRITE at 0/3
throughout). The wizard should surface this as a legitimate, named
path, not force operators through a WRITE decision to get hardware
readiness done.

### State machine (revised: per-axis, not one combined lifecycle)

Each axis has its **own independent instance** of the six-state
lifecycle already established (`DISCOVERED → SELECTED →
PREREQUISITES_VERIFIED → PROVISIONING → ACTIVE`, plus `DOWNGRADING`,
echoing `ADR-019`'s `FeatureCapabilityState` vocabulary and the TPM
provisioning spec's "derive state, don't trust a log" discipline). The
two axis-lifecycles can progress **independently and in either order**
— this is the model's central expressive gain over the ladder. Today's
real state is exactly: anchor-assurance axis at `ACTIVE`
(`hardware_witness`), capability-posture axis at `ACTIVE`
(`read_only`, i.e., its own permanent resting default, not "behind" or
"incomplete").

The `write_protected` capability posture's own `PREREQUISITES_VERIFIED`
state must check the anchor-assurance axis's current value and refuse
to proceed to `PROVISIONING` if it is `none` — this is where the
validity constraint is actually enforced in the state machine, not as
an afterthought.

### User consent boundaries

Unchanged in spirit from the original draft, now applied per axis:

- Read freely (environment discovery for either axis, unconfirmed).
- **Every mutating step, on either axis, requires its own explicit,
  distinct confirmation** — never one blanket approval for a whole
  preset. Selecting the "Hardened hardware TPM witness" preset still
  requires separate confirmations for each of: capability-profile
  change, allow-list population, TPM secret generation, NV index
  definition, daemon deployment — mirroring the granular authorization
  pattern already proven necessary in practice (Slice A, Slice B,
  Milestone 0, the TPM provisioning steps).
- Hardware presence never implies posture/axis selection — detecting a
  TPM must never cause the wizard to auto-select or default toward
  `hardware_witness` assurance.
- No unattended axis changes — operator-invoked only.

### Upgrade/downgrade rules (per axis)

- **Capability posture upgrade** (`read_only → write_protected`):
  requires the validity constraint already satisfied
  (`anchor assurance ≠ none`) — if not yet satisfied, the wizard must
  direct the operator to the anchor-assurance axis first (or accept
  provisioning both together, e.g. via the "Software-protected WRITE"
  or "Hardened hardware TPM witness" presets), never silently proceed
  with an anchor-less WRITE activation.
- **Capability posture downgrade** (`write_protected → read_only`):
  deactivates WRITE (capability profile reverts, allow-list clears).
  **Does not touch the anchor-assurance axis** — a provisioned TPM
  anchor or remote witness is left exactly as it is, matching
  `ADR-005`'s "inert by construction" philosophy applied to a
  now-unused-but-not-destroyed asset.
- **Anchor-assurance upgrade/downgrade**: independent of capability
  posture entirely. Downgrading anchor assurance while
  `write_protected` is active must re-check the validity constraint —
  downgrading to `none` while `write_protected` is active is itself
  invalid and must be rejected or forced to also downgrade capability
  posture, never silently leave the system in the disallowed
  `write_protected` + `none` state.
- **No silent re-upgrade on either axis**: re-entering a previously
  `ACTIVE` state must re-verify prerequisites fresh, never assume
  prior provisioning is still valid without re-checking.

### Safety invariants (apply unconditionally)

- **The validity constraint is enforced, not advisory**: the system
  must never reach or remain in `write_protected` capability posture
  with `none` anchor assurance. This is the two-axis model's one
  hard-coded rule, directly grounded in `ADR-011`'s own accepted text.
- **The wizard is a provisioning/configuration tool, never a new
  dispatch path** — no generic/dynamic MCP tool registration, no
  `getattr`-style dispatch, no weakening of the existing "one MCP tool
  → one `Capability` → exactly one fixed call" invariant
  (`CURRENT_MISSION.md`).
- **WRITE tool registration only ever happens through the already-
  accepted capability-profile + allow-list mechanism** (`ADR-004`,
  `ADR-005`).
- **Fail-closed anti-rollback enforcement in `store.py`
  (`anti_rollback_anchor=None` → hard refusal) remains its own,
  separate, explicit activation decision** — reaching `hardware_witness`
  anchor assurance does not implicitly enable it; unaffected by either
  axis's state.
- **TPM mutation only via the already-established, narrowly-scoped
  provisioning primitives** (`provision_anchor_baseline()`,
  `tpm_cli.py`'s fixed-argv wrapper) — no generic "run a TPM command"
  surface.
- **`advance()` is never called by provisioning or posture-selection
  code** — reserved exclusively for the sealed executor (`ADR-014`),
  which no combination in this model builds or enables.
- **Reaching `ACTIVE` on the capability-posture axis for
  `write_protected` requires the same Milestone-9-class activation
  decision `TIER1_ROADMAP.md` already requires** — unaffected by this
  ADR. Reaching `ACTIVE` on the anchor-assurance axis for
  `hardware_witness` does **not** require that decision — provisioning
  hardware readiness ahead of WRITE activation is exactly what already
  happened and remains explicitly permitted, gated only by its own
  (already-established) TPM provisioning authorization steps.
- **No pfSense mutation** is introduced, implied, or made easier by any
  combination defined here.

## Consequences

### Positive

- Correctly represents this project's own real, intentional deployment
  state (`read_only` + `hardware_witness`) as a first-class point in
  the model, not a special case or an unrepresentable anomaly.
- Encodes `ADR-011`'s own already-accepted "mutation must stay blocked
  without an anchor" rule as one explicit, enforceable constraint
  instead of leaving it an open question.
- Lets hardware-dependent, expensive, one-time provisioning proceed on
  its own schedule, independent of the separately-gated WRITE
  activation decision — matching how this project has actually
  operated so far.
- Still gives operators a simple, three-preset front door for the
  common cases — the added expressiveness is available, not mandatory,
  UX complexity.

### Negative

- Two independent axes are a more complex mental model than one linear
  ladder — mitigated by curated presets as the default UX surface.
- The validity constraint (`write_protected` requires anchor `≠ none`)
  is a new piece of enforced logic that must be kept correct — a single
  well-defined rule, but a real one, not present in the (simpler,
  but less accurate) ladder.
- Downgrade rules are now per-axis rather than one scalar step, which
  is more precise but requires the wizard UX to clearly distinguish
  "reduce capability" from "reduce assurance" as separate operator
  choices.

## Alternatives considered

- **Strict three-rung ladder (Model A, this ADR's original draft)**:
  rejected — cannot represent `read_only` + `hardware_witness` (this
  project's own real state) without inventing a special-case fourth
  rung that secretly reintroduces two axes; conflates two operations
  ("reduce capability" vs. "reduce assurance") under one downgrade
  step; collapses `ADR-004`'s clean binary capability-profile mapping
  into a many-to-one relationship. Full comparison above.
- **Reuse "profile" instead of introducing "posture":** rejected —
  direct collision with `ADR-004`'s already-accepted, narrower term.
- **Extend `ADR-011` in place:** rejected — this ADR's subject spans
  multiple other ADRs (`004`/`005`/`006`/`008`/`011`/`020`), not a
  continuation of the anchor's own deployment shape specifically.
- **Let the wizard perform all provisioning for a preset as one atomic
  action:** rejected — contradicts the granular, per-step consent this
  project has consistently required for every real mutating action so
  far.
- **Free, uncurated 2×3 grid as the primary UX (no presets):**
  considered and rejected as the *default* surface — most operators
  benefit from the three named presets; the full grid (minus the one
  invalid combination) remains available as the advanced path, not the
  front door.

## Open design questions (not resolved by this ADR)

1. ~~Is a fourth, unnamed state — "anchor provisioned, WRITE still
   inactive" — worth naming explicitly?~~ **Resolved by this revision**:
   this is exactly `read_only` + `hardware_witness` in the two-axis
   model, no longer unnamed or special-cased.
2. ~~Does `write_protected` require *some* anti-rollback protection, or
   does it knowingly forgo the whole-store-rollback property?~~
   **Resolved by this revision**: `ADR-011`'s own text requires it —
   encoded as the validity constraint (`write_protected` requires
   anchor `≠ none`).
3. **Do `write_protected` and `hardware_witness` presets share one
   `WriteEndpoints` allow-list, or can the allow-list differ by anchor
   assurance** (e.g., only `hardware_witness` may enable a particular
   high-risk endpoint)? Still open.
4. **What is the actual decommissioning path** for un-provisioning a
   TPM index / stopping and removing the daemon, if ever needed? Still
   explicitly out of scope for this ADR's downgrade rules (which leave
   hardware inert rather than touching it).
5. **Should the wizard be interactive-only, or also support a fully
   declarative/config-file-driven mode**? Still open.
6. **Should `read_only` + `software` (pre-provisioned remote witness,
   WRITE still off) be offered in the UX at all**, given it was
   identified as low-value in the comparison table above, or hidden
   behind the advanced path alongside `read_only` + `hardware_witness`?
   New question raised by this revision.

## References

- [ADR-004](ADR-004-capability-profiles.md) — capability profiles; the
  capability-posture axis maps 1:1 onto this
- [ADR-005](ADR-005-inert-tier-0-write-infrastructure.md) — inert Tier 0
  WRITE infrastructure
- [ADR-006](ADR-006-recovery-contract-philosophy.md) — Recovery
  Contract philosophy
- [ADR-008](ADR-008-fail-closed-configuration.md) — fail-closed
  *configuration validation* (a general principle; distinct from the
  Tier 1 anchor's own, still-pending, fail-closed *mismatch*
  enforcement in `store.py`)
- [ADR-011](ADR-011-whole-store-anti-rollback-anchor.md) — whole-store
  anti-rollback anchor; the anchor-assurance axis maps onto this ADR's
  backend hierarchy, and its "mutation must stay blocked without an
  anchor" text is this ADR's validity constraint's direct source
- [ADR-019](ADR-019-api-surface-capability-discovery-and-extension-architecture.md) —
  `FeatureCapabilityState` evidence-vs-authorization vocabulary this
  ADR's per-axis state machines echo
- [ADR-020](ADR-020-milestone-0-first-write-capability-candidate.md) —
  Milestone 0 WRITE capability candidate naming
- [`TIER1_ROADMAP.md`](../TIER1_ROADMAP.md) — Milestone 9 activation
  decision, unaffected/unshortcut by this ADR
- [`SECURITY_POSTURE_PROVISIONING.md`](../SECURITY_POSTURE_PROVISIONING.md) —
  companion specification (per-axis state machine detail, affected
  code inventory, phased implementation plan)
- [`ROADMAP.md`](../ROADMAP.md) — "Operator setup and security
  postures" entry this ADR formalizes
- `reports-ai/reviews/WITNESS_DAEMON_DEPLOYMENT_CONVERGENCE_REVIEW_2026-08-10.md` —
  independent evidence for the real `read_only` + `hardware_witness`
  state this revision's comparison is grounded in
