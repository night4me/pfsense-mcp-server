# ADR-021: Guided security-posture provisioning (`pfsense-mcp-security setup`)

- **Status:** **Accepted** (2026-08-10, owner) — the two-axis model,
  its state machine, consent boundaries, upgrade/downgrade rules, and
  the resolutions to all six open design questions are the accepted
  architecture for security-posture provisioning. **Acceptance is
  architectural only.** It does not authorize building the wizard,
  activating WRITE, enabling fail-closed anchor enforcement, or
  performing any TPM/pfSense mutation — each remains its own separate,
  later, explicitly-scoped authorization, exactly as every safety
  invariant below already states. See "Acceptance note" below.
- **Date:** 2026-08-10 (proposed, revised twice, and accepted same day
  — see "Revision note," "Second revision note," and "Acceptance note"
  below)

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

## Second revision note

Design closure for the four remaining open questions (allow-list
sharing, hardware decommissioning, interactive-vs-declarative UX,
whether to expose `read_only` + `software`) — see "Resolving open
questions 3–6" under "Decision" below, and the updated "Safety
invariants" and "Open design questions" sections. No change to the
two-axis model itself, the validity constraint, the state machine, or
any already-decided content from the first revision. This ADR remains
uncommitted at the time each revision was made — both are iteration
before acceptance, not a supersession of an accepted decision.

## Acceptance note

Owner accepted this ADR's architecture as written on 2026-08-10, after
the second revision closed all six open design questions. Accepted, in
summary: the two-axis model (capability posture `read_only`/
`write_protected`; anchor assurance `none`/`software`/`hardware_witness`);
curated presets as the primary UX with the advanced hardware-first
path also supported; one shared `WriteEndpoints` allow-list across
both WRITE-capable presets; the DEACTIVATE-vs-DEPROVISION
decommissioning split with retain-not-delete as the default; both
interactive and declarative setup UX, with physical-TPM-mutating steps
remaining interactive-only; `read_only` + `software` hidden/unsupported
in the UX until a real implementation and use case exist; and the
persistent, `systemd`-managed witness daemon (`ADR-011`'s own
"Deployment model decision") as the intended `hardware_witness`
deployment model.

Nothing about the decisions themselves — the model, the state machine,
the resolutions to questions 1–6, or the reasoning in "Model
comparison"/"Alternatives considered" — changed as part of acceptance;
this note records that the owner reviewed and approved the
already-written architecture, not a new revision of it. **Acceptance
does not authorize implementation.** Every safety invariant below
(no WRITE activation, no fail-closed enforcement, no `advance()`, no
TPM/pfSense mutation, no new MCP dispatch path) remains in force
exactly as written; building the wizard, any posture's `PROVISIONING`
step, or any code at all is its own separate, future, explicitly-scoped
authorization this note does not grant.

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

#### Resolving open questions 3–6

Each question below states its decision, rationale, security
implications, upgrade/downgrade implications, UX consequences, and any
new invariant introduced — added to "Safety invariants" below, not
left implicit.

#### Question 3 — allow-list sharing between WRITE-capable presets

**Decision: one shared `WriteEndpoints` allow-list across both
`write_protected` presets (`software` and `hardware_witness` anchor
assurance). Anchor assurance changes protection strength only, never
which endpoints are allow-listed.**

- **Rationale**: `src/pfsense_mcp/write_endpoints.py` is already a
  single, global, class-level allow-list — there is no existing or
  implied per-profile/per-anchor parameterization anywhere in the
  codebase. A dual-allow-list mechanism would be new architecture built
  for a distinction (endpoint risk vs. anchor strength) the project's
  own `WRITE_ENDPOINT_RISK_MATRIX.md` already treats as orthogonal:
  every rating there (`Critical`/`High`/etc., rollback difficulty,
  blast radius) is a property of the *endpoint itself*, independent of
  how the mutation history is tamper-evidenced.
- **Security implications**: no loss of least privilege — the
  allow-list still governs *which* mutations are ever permitted at
  all, gated by the existing per-endpoint risk review
  (`WRITE_ENDPOINT_RISK_MATRIX.md`, `ADR-020`-style candidate
  authorization), unaffected by this decision. What changes between
  `software` and `hardware_witness` is how tamper-evident the mutation
  *history* is, not what mutations are approved.
- **Upgrade/downgrade implications**: switching anchor assurance
  between `software` and `hardware_witness` (once `software` exists —
  see Phase G) never requires touching `WriteEndpoints` — one less
  moving part during any anchor-assurance transition.
- **UX consequences**: simpler mental model — "what can I mutate" and
  "how well is that mutation history protected" are visibly separate
  questions in the wizard, never bundled into one allow-list-selection
  step.
- **Left open, deliberately, not unresolved**: if a future specific
  WRITE candidate is judged too high-risk without hardware-level
  assurance specifically, that is its own future, evidence-backed,
  `ADR-020`-style decision on *that one endpoint* — not a structural
  change to this ADR's shared-allow-list model. No such candidate
  exists today (WRITE remains 0/3).

#### Question 4 — hardware decommissioning path

**Decision: sharply distinguish DEACTIVATE (routine, reversible, part
of the normal `DOWNGRADING` state, retains all TPM/store state) from
DEPROVISION (rare, destructive, its own separately-authorized procedure
outside the routine axis lifecycle, never automatic).**

**DEACTIVATE** (extends the existing per-axis `DOWNGRADING` state,
already defined above):

1. Stop relying on the anchor for confirmation (only meaningful once
   fail-closed enforcement exists, which it does not).
2. Stop/disable the witness daemon (`systemctl stop`/`disable`) — TPM
   NV counter value and the guest-side store's high-water-mark/
   provisioning record are **untouched**. Fully reversible: re-enable,
   restart, resume.
3. Uninstall the daemon's deployed code/unit — a bigger step than (2)
   but still touches neither TPM state nor guest store state; resuming
   requires redeployment (matching the reference unit's own "extract
   the exact reviewed commit's source" procedure), not
   re-provisioning.

None of the above requires touching the physical TPM or deleting any
guest-side file. **This is the entirety of what "downgrade
anchor-assurance away from `hardware_witness`" means in the routine
lifecycle.**

**DEPROVISION** (rare, manual, explicitly *not* part of the routine
`DOWNGRADING` state — its own separate procedure, mirroring how
provisioning itself required narrowly-scoped, exact-wording
authorization):

- **TPM NV index deletion** (`tpm2_nvundefine`): genuinely destructive
  and non-reversible in the way an operator might expect — this
  project's own documented finding is that a freshly-*re*-defined
  counter does not resume at its old value, it starts over (`docs/tier1/specs/anti_rollback_tpm_host_witness.md`'s
  "Initial baseline" section). Must **never** happen automatically;
  requires its own explicit, narrowly-scoped authorization, and must
  be scoped to *exactly* the project's own index — the same "never
  touch the other 14 foreign/vendor-owned indices" invariant the
  provisioning spec already established applies identically in
  reverse.
- **Guest-side store/integrity-key deletion**: also never automatic.
  Higher stakes than it first appears — if `write_protected` posture
  was ever active, this store may hold real Recovery Contract history,
  not just anchor bookkeeping; deleting it is a decision about audit
  material, not only about anchor cleanup.
- **Default behavior on any anchor-assurance downgrade is retain, not
  delete** — matching `ADR-005`'s "inert by construction" philosophy,
  now extended explicitly from the capability-posture axis (already
  established) to the anchor-assurance axis (new as of this
  resolution). Retained TPM/store state costs nothing and preserves
  the option to resume `hardware_witness` later without
  re-provisioning from zero.

**Downgrade to `software` or `read_only`**:

- `hardware_witness → software`: not actually executable until the
  `software` backend exists (Phase G, unimplemented) — stated
  explicitly rather than assumed working.
- `hardware_witness → none`: only permitted jointly with the
  capability-posture axis being at (or downgrading to) `read_only` —
  otherwise it would create the disallowed `write_protected` + `none`
  combination. This extends the validity-constraint enforcement
  already specified for upgrades to downgrades explicitly.

**What must never happen automatically** (consolidated):

- TPM NV index undefine/delete.
- Guest-side store or integrity-key deletion.
- Any transition that would leave `write_protected` posture active
  with `none` anchor assurance, even momentarily.
- Daemon stop/removal triggered *merely* by a capability-posture
  downgrade (`write_protected → read_only`) — the existing rule that
  capability-posture downgrade "does not touch the anchor-assurance
  axis" is extended here to explicitly include the daemon/service
  state, not only the abstract axis value.

- **Security implications**: prevents an operator from accidentally
  losing hard-won hardware provisioning state via a routine WRITE-off
  downgrade, and prevents any automated path from ever reaching an
  irreversible TPM action.
- **Upgrade/downgrade implications**: covered above — DEACTIVATE is
  fully within the normal per-axis `DOWNGRADING` state; DEPROVISION is
  explicitly outside it.
- **UX consequences**: the wizard's routine "turn off WRITE" or
  "reduce assurance" flows never present a destructive option;
  deprovisioning, if ever built, is a clearly separate, harder-to-reach
  procedure (analogous to how this project already treats rare
  operations like Milestone 8's live lab run as "its own separate
  command-level approval").

#### Question 5 — interactive vs. declarative wizard UX

**Decision: support both, with an asymmetric scope. Interactive and
declarative/non-interactive modes are both offered for the
capability-posture axis and for read-only discovery of either axis.
Anchor-assurance `PROVISIONING`/DEPROVISION steps that touch physical
TPM state remain interactive (human-confirmed in real time) only.**

- **Rationale**: this project's own standing practice, unbroken across
  every real TPM-facing action so far (`CURRENT_MISSION.md`'s "Standing
  SSH constraint" — TPM-facing commands are always run manually by a
  human on the console, never automated), is direct evidence that
  TPM-touching steps are not currently trusted to unattended execution
  in this project even by its own maintainers. Automation/CI/headless
  use cases are real and legitimate for the *software-only* parts of
  posture provisioning (setting `PFSENSE_PROFILE`, populating
  `WriteEndpoints`) but extending that to hardware provisioning would
  be a new, unevidenced trust decision this ADR does not make.
- **Declarative mode's consent model**: a declarative/config-file-driven
  run must supply the **same granularity of itemized, named
  authorization** the interactive flow requires — e.g., an explicit
  list of exactly which capability-posture steps are authorized, never
  one blanket `authorize: true` flag. This mirrors the TPM provisioning
  spec's own already-established "exact copy/paste authorization
  wording" pattern — declarative mode is that same pattern delivered
  via a file instead of a prompt, not a weaker form of consent.
- **Mandatory dry-run**: any declarative/non-interactive invocation
  must support (and a first unattended use should require) a
  `--dry-run`/preview mode showing exactly what would be authorized and
  executed without executing it — matching this project's general
  practice of never running a live-host command without a prior
  read-only preview.
- **Security implications**: keeps the single highest-risk surface
  (physical TPM mutation) under the same human-in-the-loop discipline
  already proven necessary, while enabling real automation value for
  the lower-risk, purely-software capability-posture axis.
- **Upgrade/downgrade implications**: declarative mode applies
  identically to capability-posture upgrades and downgrades (both are
  software-only config changes); anchor-assurance transitions that
  don't touch TPM state (e.g., stopping the daemon) could reasonably
  support declarative mode too — a refinement left to the
  companion spec, not this ADR, since it doesn't change any invariant
  here.
- **UX consequences**: a CI/automation user gets a real, itemized,
  auditable non-interactive path for capability-posture work; a
  human at the console is still required for anything TPM-facing,
  with no headless bypass.

#### Question 6 — whether to expose `read_only` + `software` in the UX

**Decision: intentionally hidden — not offered as a visible preset, and
not offered in the advanced path either, until the `software` backend
actually exists (Phase G) and a concrete operator need is identified.**

- **Rationale**: two independent reasons, either alone sufficient.
  First, the `software` (remote append-only witness) backend has **no
  implementation anywhere in this repository** — surfacing it in UX
  today would offer an option that cannot actually execute, which this
  project's own discipline (never asserting a capability exists before
  it's verified) argues against. Second, even once implemented, this
  combination's identified value (pre-provisioning a remote witness
  with no WRITE decision made yet) is real but weak compared to
  `read_only` + `hardware_witness`'s concrete justification — this
  exact project's own actual deployment history, not a hypothetical.
- **Distinction from `read_only` + `hardware_witness`** (which *is*
  kept as an advanced path): that combination has already happened, for
  real, in this project. `read_only` + `software` has no such grounding
  — it is a theoretical grid cell, not an evidenced use case.
- **Security implications**: none — this is a UX-exposure decision, not
  a validity-constraint change. The two-axis model still technically
  allows this combination; it is simply not surfaced.
- **Upgrade/downgrade implications**: none — no transition rule
  changes; an operator cannot reach this combination through the UX at
  all until this decision is revisited.
- **UX consequences**: the advanced path is simpler as a result —
  exactly one extra combination (`read_only` + `hardware_witness`)
  beyond the three curated presets, not two.
- **Revisit condition, stated explicitly**: once the `software` backend
  exists (Phase G) and a concrete operator need for
  `read_only` + `software` is identified, this decision should be
  revisited as its own small, separate design update — not reopened
  speculatively before then.

## Safety invariants (apply unconditionally)

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
- **`WriteEndpoints` is one shared, global allow-list** — no
  per-anchor-assurance or per-preset allow-list mechanism exists or is
  introduced; any future endpoint-specific requirement for a particular
  anchor-assurance level is its own separate, evidence-backed,
  `ADR-020`-style decision on that endpoint, not a structural change
  here (resolves question 3).
- **TPM/store deprovisioning is never automatic and never part of the
  routine `DOWNGRADING` state** — TPM NV index deletion and guest-side
  store/integrity-key deletion each require their own explicit,
  narrowly-scoped authorization, separate from any routine axis
  transition; TPM-scoped deletion must never touch any of the host's
  other, foreign-owned NV indices; the default behavior on any
  anchor-assurance downgrade is retain, not delete (resolves question
  4).
- **Declarative/non-interactive provisioning is scoped to the
  capability-posture axis and to read-only discovery of either axis
  only** — any anchor-assurance step that touches physical TPM state
  remains interactive, human-confirmed-in-real-time only, matching this
  project's standing practice for TPM-facing commands; declarative
  authorization must be itemized and named, never a blanket flag
  (resolves question 5).
- **`read_only` + `software` is not exposed in the wizard UX** — hidden
  from both the curated presets and the advanced path until the
  `software` anchor-assurance backend exists and a concrete need is
  identified; the two-axis model still technically permits it (resolves
  question 6).

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

## Open design questions

**All six original questions are now resolved.** None remain blocking.

1. ~~Is a fourth, unnamed state — "anchor provisioned, WRITE still
   inactive" — worth naming explicitly?~~ **Resolved**: this is exactly
   `read_only` + `hardware_witness` in the two-axis model, no longer
   unnamed or special-cased.
2. ~~Does `write_protected` require *some* anti-rollback protection, or
   does it knowingly forgo the whole-store-rollback property?~~
   **Resolved**: `ADR-011`'s own text requires it — encoded as the
   validity constraint (`write_protected` requires anchor `≠ none`).
3. ~~Do `write_protected` and `hardware_witness` presets share one
   `WriteEndpoints` allow-list, or can the allow-list differ by anchor
   assurance?~~ **Resolved**: one shared, global allow-list; anchor
   assurance changes protection strength only. See "Resolving open
   questions 3–6" above.
4. ~~What is the actual decommissioning path for un-provisioning a TPM
   index / stopping and removing the daemon?~~ **Resolved**: DEACTIVATE
   (routine, reversible, retains all state) sharply distinguished from
   DEPROVISION (rare, destructive, its own separate authorization,
   never automatic). See "Resolving open questions 3–6" above.
5. ~~Should the wizard be interactive-only, or also support a fully
   declarative/config-file-driven mode?~~ **Resolved**: both, scoped —
   declarative mode for the capability-posture axis and read-only
   discovery; anchor-assurance TPM-touching steps remain interactive
   only. See "Resolving open questions 3–6" above.
6. ~~Should `read_only` + `software` be offered in the UX at all?~~
   **Resolved**: intentionally hidden until the `software` backend
   exists and a concrete need is identified. See "Resolving open
   questions 3–6" above.

No new open questions were introduced while resolving these — each
decision above either closes its question outright or explicitly names
its own future, separately-scoped follow-on (the `software` backend's
own implementation effort; a future endpoint-specific anchor
requirement, if one is ever evidenced; the exact deprovisioning
authorization wording, to be drafted if and when that action is
actually being sought, matching this project's practice of drafting
exact authorization wording only when real and imminent).

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
- [`WRITE_ENDPOINT_RISK_MATRIX.md`](../WRITE_ENDPOINT_RISK_MATRIX.md) —
  the existing, orthogonal, per-endpoint risk-review process question
  3's decision explicitly does not duplicate
- [`anti_rollback_tpm_host_witness.md`](../tier1/specs/anti_rollback_tpm_host_witness.md) —
  the "never touch the other foreign-owned NV indices" and "a
  re-defined counter does not resume its old value" findings question
  4's DEPROVISION rules are grounded in
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
