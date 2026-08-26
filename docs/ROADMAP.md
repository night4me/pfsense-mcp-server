# Public roadmap

This roadmap communicates direction, not a promise of dates or features. Items
under **Committed** are accepted project goals; **Candidate** items require
design/review; **Ideas** are exploratory. No roadmap entry activates a
capability or authorizes a production change.

## Current baseline

**2026-08-22 update — current immutable published baseline is v0.7.0**
(PyPI and GitHub; see `CHANGELOG.md`'s `[0.7.0]` entry) — the first
release to add `pfsense_get_official_guidance`, a separate,
structurally distinct official-documentation guidance tool (never a
96th pfSense READ capability; see `docs/OFFICIAL_GUIDANCE_LAYER.md`).
`v0.6.0` itself was a READ-capability expansion over the prior `v0.5.1`
baseline (84 → 95 tools); `v0.5.0` was the major expansion before that
(42 → 84 tools, exactly a 100% increase); `v0.5.1` was a documentation-
accuracy and security-communication patch over `v0.5.0`. No WRITE
capability changed across any of these releases.

**Update (2026-08-27): the current immutable published baseline is now
`v0.7.2`** — `v0.7.1` (documentation/packaging correction) and `v0.7.2`
(a `MutationExecutor` clock-injection fix, a validation-pipeline
performance improvement, and the `pfsense-mcp-security bootstrap` CLI
subcommand) shipped after the paragraph above was written; see
`CHANGELOG.md`'s `[0.7.1]`/`[0.7.2]` entries. Neither changed the
production MCP surface or any WRITE capability. **A `v0.8.0` release
candidate is additionally prepared on `main`** (the `recover` CLI
subcommand, the full `setup` guided-provisioning wizard, and a
restart-classification correctness fix) but is not yet tagged,
released, or published — see `README.md`'s "Release status" section
and `CHANGELOG.md`'s `[Unreleased]` entry. The `v0.2.x`/`v0.3.0`
sections immediately below are kept exactly as originally written, as
an accurate historical record of what shipped and when — not rewritten
to look cleaner. Treat "v0.3.0" in their text as the baseline *at the
time those sections were written*, not the current one.

- Production MCP surface: **95 pfSense READ tools + 1 official-guidance
  tool, 0 default-reachable WRITE tools** — the READ/WRITE split is
  enforced mechanically on every CI run
  (`scripts/write_capability_check.py`), not merely documented.
- **One WRITE capability now exists and is `verified=True`**:
  `set_firewall_alias_description_v1`
  (`WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION`). It is still
  unreachable under the default profile — reaching it requires an
  operator to explicitly select `write_protected` *and* a real,
  owner-driven, per-mutation Ed25519 authorization/confirmation
  signing ceremony every single time; `verified=True` does not itself
  enable WRITE. This reflects **two independently-verified live
  executions against a disposable LAB appliance** (never
  production/home pfSense), including least-privilege execution
  through a dedicated 4-privilege pfSense identity and TPM
  anti-rollback witness advancement confirmed against physical
  hardware both times — see
  [ADR-026](adr/ADR-026-first-write-capability-adapter.md) for the
  complete evidence chain. This is the "Tier 1 — first controlled
  mutation" milestone described further below, now realized for this
  one capability, not only planned.
- Tier 0 WRITE infrastructure: present, tested, and — for this one
  capability specifically — no longer only inert. The rest of the
  Tier 1 framework (every other potential WRITE capability) remains
  structurally isolated and unreachable pending a second, separately
  owner-authorized capability (see "Tier 2" below).
- **A second, fully offline-only backend now exists**: research into
  using Netgate's official Nexus/pfSense Plus API as a second READ
  transport (never a replacement for the existing community
  `pfSense-pkg-RESTAPI` backend) ran through seven phases and is
  currently paused at a stable, fully-isolated checkpoint — see
  "Nexus — second backend research track" below.

## v0.2.x — hardening and public-project readiness

### Committed

- Preserve the existing 42-tool READ API and GET-only production path.
- Establish public CI for Python 3.11–3.13, CodeQL, Bandit, branch coverage,
  package build/install checks, and credential-free architecture checks.
- Complete security, threat-model, architecture, API, contribution, and release
  documentation.
- Keep WRITE endpoint allow-list empty and WRITE capabilities inactive.
- Publish no package until artifacts pass inspection/Twine and the approved MIT
  license metadata is present.

### Candidate

- Replace or retire stale generated checkpoint/backlog state.
- Add tests for uncovered configuration and transport error branches.
- Split oversized test modules without behavior changes.
- Maintain wholly synthetic public-certificate fixtures.
- Add dependency advisory/constraints policy after CI baseline stability.

### Not in scope

- New MCP tools or READ capabilities.
- Tier 1 activation.
- Network transport beyond local stdio.

## v0.3.0 — inert Tier 1 foundation and compatibility discipline

### Committed

- Keep the v0.2.2 public MCP contract and production READ behavior unchanged.
- Specify, implement, and test the Recovery Contract, closed state machine,
  canonical digests, authenticated persistence, policy bindings, audit event
  model, protected-artifact encryption, key lifecycle, whole-store
  anti-rollback protocol, confirmation/reconciliation authorities, rate/
  blast-radius containment, and a sealed mutation executor composing all of
  it behind one chokepoint — done; every subsystem is implemented and
  tested, still entirely unreachable from production.
- Keep the Tier 1 package outside production bootstrap with an empty mutation
  policy, no WRITE endpoint, no executor construction, and no registered
  WRITE tool.
- Produce a risk-ranked WRITE endpoint study and a disposable-lab acceptance
  design and offline-tested harness before asking the owner to select a
  first capability and run a live lab acceptance pass.

### Candidate

- Mechanically split client/registry test modules by domain.
- Extract private singleton/list response-mapping helpers after characterization
  tests prove identical public behavior.
- Add cross-release MCP schema diffing that distinguishes additive, compatible,
  and breaking changes.
- Formalize generated-document freshness and remove stale state ambiguity.
- Maintain the owner-approved license, package publication process, provenance,
  and reproducible dependency constraints.
- Preserve descriptor-bound API-key loading as a security invariant.

### Possible ideas

- A documented internal diagnostics CLI that remains outside the MCP surface.
- Optional tamper-evident audit forwarding containing metadata only.
- Resource/rate controls if measured deployments show a need.
- A READ capability covering `/system/webgui/settings` (WebGUI/Admin
  Access configuration, including the configured `ssl-certref`) —
  found missing during a real-world diagnostic session (2026-08-10):
  an agent could enumerate certificates but not determine which one
  the GUI actually presents. See `READ_BACKLOG.md`'s "Post-snapshot
  discovery" addendum for the precise gap and evidence. Not scoped or
  authorized here — a new capability requires the same review any
  public-contract addition does. See also the "WebGUI Evidence Layer"
  idea below, the broader future direction this specific gap motivated.

## Tier 1 — first controlled mutation

**2026-08-16/17 update — this milestone is realized for exactly one
capability, `set_firewall_alias_description_v1`.** The paragraph
below ("the first capability and endpoint remain unnamed...") is kept
as the original framing at the time this section was written; it is
now historical, not current. The capability has been named, built,
and independently live-verified twice — see the "Current baseline"
section above and [ADR-026](adr/ADR-026-first-write-capability-adapter.md).
Tier 1 activation for any *further* capability remains its own
separate, explicitly authorized program — this milestone's completion
for one capability does not carry over to any other.

Tier 1 activation is a separately authorized security program. v0.3.0 may
contain inert framework code, but the first capability and endpoint remain
unnamed until threat, reversibility, upstream semantics, encryption, durable
anti-rollback, and operator-authentication decisions are approved.

### Required before commitment

All of the following are **satisfied, with live evidence, for the one
accepted capability** (`set_firewall_alias_description_v1` —
[ADR-026](adr/ADR-026-first-write-capability-adapter.md)). They remain
the required bar for any *future* additional capability, each judged
independently rather than inherited.

- Authoritative Recovery Contracts loaded by ID and bound to capability,
  endpoint, method, target, intent, snapshot, and rollback plan.
- Atomic legal state transitions, replay/concurrency controls, and expiry.
- Explicit durable persistence/crash/restart behavior.
- Typed payload transmission and exact HTTP outcome validation.
- Semantic read-back before commitment and after rollback.
- Operator reconciliation for ambiguous outcomes.
- Capability-specific least privilege, audit, tests, and private test-appliance
  acceptance.

See [Tier 1 roadmap](TIER1_ROADMAP.md). Zero WRITE tools register for any
capability that has not individually cleared every gate above.

## Nexus — second backend research track (paused, 2026-08-17)

**Working name: Nexus dual-backend support.** Netgate publishes an
official pfSense Plus API (`Netgate/pfsense-api`, "Nexus"), distinct
from the community `pfSense-pkg-RESTAPI` package this project has
always used. A seven-phase research/design/offline-implementation
track (Phases A–G, 2026-08-16/17) investigated whether Nexus could
become a **second, additive** READ backend — never a replacement for
the existing community backend, and never authorized to touch WRITE.

**Current state, precisely:**

- **Nexus READ: OFFLINE-TESTED / LIVE-BLOCKED.** One capability
  (`pfsense_get_carp_status`) was proven to map completely,
  deterministically, and semantically to Nexus's schema (not merely
  by field name) and has a real, offline-tested implementation
  (`NexusSession` → `NexusTransport` → `NexusCarpStatusReader`,
  102 tests under `tests/backends/`, 92 of them specifically under
  `tests/backends/nexus/`). It has never been exercised against a
  real Nexus Controller — no live Nexus access has ever occurred in
  this project's history. Two other candidates
  (`pfsense_get_gateway_status`, `pfsense_get_firewall_aliases`) were
  diffed with equal rigor and correctly classified `PARTIAL` and left
  unimplemented rather than forced, after their required fields
  (an `id: int` domain-model convention this project uses, with no
  Nexus counterpart) proved unmappable without fabricating data.
- **Nexus WRITE: BLOCKED BY ADR-031.** [ADR-031](adr/ADR-031-backend-target-identity-boundary.md)
  states a mandatory invariant — a mutation authorized for one backend/
  appliance must never become executable through a different backend/
  device merely because a normalized operation looks equivalent — and
  is a prerequisite gate for any future Nexus WRITE work, not yet
  implemented (deliberately: it is architecture/invariant documentation
  only, no cryptographic binding exists yet, and none was authorized
  to be built during this track).
- **No runtime wiring exists.** `src/pfsense_mcp/backends/` (including
  every Nexus file) is proven, by an AST-based test with no carve-outs,
  to be imported by nothing outside itself — not `factory.py`, not
  `tools/registry.py`, not `application.py`. It cannot currently affect
  the running MCP server in any way.
- **Resume conditions**, in order: a real Nexus Controller, a target
  device, and appropriately least-privileged credentials become
  available; the CARP-read RBAC/device-scoping questions
  ([ADR-032](adr/ADR-032-nexus-read-transport-architecture.md)'s Phase
  G section) are resolved *before* the first live authentication
  attempt — explicitly not by defaulting to a Controller admin
  credential to bypass that uncertainty.

Full detail: [ADR-030](adr/ADR-030-dual-pfsense-api-backend-architecture.md)
(architecture/compatibility), [ADR-031](adr/ADR-031-backend-target-identity-boundary.md)
(backend/target identity boundary), [ADR-032](adr/ADR-032-nexus-read-transport-architecture.md)
(transport design, implementation, and live-readiness assessment),
[`NEXUS_COMPATIBILITY_MATRIX.md`](NEXUS_COMPATIBILITY_MATRIX.md) (the
full 42-tool compatibility survey).

## Operator setup and security postures (architecture accepted, implementation not started)

Future `pfsense-mcp-security setup` CLI/wizard: let an operator
explicitly choose their security posture at setup time rather than
silently ending up with stronger privileges than intended. This item
moved from idea-stage to a completed architecture/design phase on
2026-08-10, was **revised the same day** after a rigorous comparison
found the original three-rung ladder couldn't represent this project's
own real deployment state, and was **accepted by the owner, same day,
after a second revision closed all remaining open design questions** —
[ADR-021](adr/ADR-021-security-posture-provisioning.md) is now the
authoritative, **Accepted** decision record, with mechanical detail in
[`SECURITY_POSTURE_PROVISIONING.md`](SECURITY_POSTURE_PROVISIONING.md).
**Acceptance is architectural only** — nothing below authorizes
building the wizard, any posture, WRITE, or fail-closed enforcement;
each remains its own separate, future, explicitly-scoped
authorization.

**Model: two independent axes, not one linear ladder.** `ADR-021`
adopted a **capability posture** axis (`read_only`/`write_protected`,
mapping 1:1 onto `ADR-004`'s capability profiles) crossed with an
**anchor assurance** axis (`none`/`software`/`hardware_witness`,
mapping onto `ADR-011`'s own backend hierarchy), with one validity
constraint directly sourced from `ADR-011`'s own accepted text:
**`write_protected` requires anchor assurance `≠ none`** ("if neither
[TPM nor remote witness] is available, mutation must stay blocked").
This correctly represents this project's own actual production state —
`read_only` capability with `hardware_witness` assurance already fully
provisioned and verified — as a first-class, valid point in the model,
not a special case the original ladder couldn't express.

The wizard's default front door still offers three named, curated
presets over that model (see `ADR-021`/`SECURITY_POSTURE_PROVISIONING.md`
for the full grid, including the advanced/staged path):

- **READ-only** (`read_only` + `none`, default) — today's actual
  production default, named explicitly rather than left an implicit,
  never-consciously-chosen default.
- **Software-protected WRITE** (`write_protected` + `software`) — a
  future Tier 1 WRITE capability (see "Tier 1" above) protected by the
  existing Recovery Contract / sealed-executor machinery plus a
  non-hardware anti-rollback witness. The `software` anchor backend
  itself has no implementation in this repository yet — a named,
  separate future effort.
- **Hardened hardware TPM witness** (`write_protected` +
  `hardware_witness`) — Tier 1 WRITE plus the `ADR-011` anti-rollback
  anchor backed by a real TPM. **The persistent, systemd-managed
  witness daemon is the intended production behavior, not a
  manually-started daemon** — see
  [ADR-011](adr/ADR-011-whole-store-anti-rollback-anchor.md)'s
  "Deployment model decision" section (authoritative). If/when this
  wizard is built, selecting this preset should be able to provision
  the persistent witness architecture automatically — service
  installation/configuration and the full existing hardening posture
  (dedicated identity, least privilege, mTLS, restricted network
  exposure, fixed TPM handle/invariants) — while keeping the choice
  explicit and never silently enabling stronger privilege than the
  operator selected.

Each axis's own activation gates (Tier 1's "Required before
commitment" above, `ADR-011`'s backend/deployment decisions, WRITE
capability/allow-list population, `TIER1_ROADMAP.md`'s Milestone 9
activation decision — which applies to the capability-posture axis
only, not to anchor-assurance provisioning — etc.) are unchanged and
unaffected by this design phase — the wizard, if built, would provision
toward an explicitly chosen combination's already-existing gates, not
bypass or shortcut them.

Two mutation-free CLI slices are implemented on top of this design:
`pfsense-mcp-security discover` (current-state evidence) and
`pfsense-mcp-security plan` (compares current evidence against an
explicit target and generates an ordered, never-executed plan) — see
`SECURITY_POSTURE_PROVISIONING.md`'s own implementation sections. The
boundary between that planning layer and actually authorizing/executing
one specific planned step — without turning target selection, plan
generation, a stale plan, or an AI/MCP request into reusable or implicit
mutation authority — is designed and **Accepted** (2026-08-11, owner) as
its own separate architecture, **architectural acceptance only**:
[ADR-022](adr/ADR-022-execution-authorization-boundary.md), companion
spec [`EXECUTION_AUTHORIZATION_BOUNDARY.md`](EXECUTION_AUTHORIZATION_BOUNDARY.md).
No authorization/execution code exists; building any part of it remains
its own separate, future, explicitly-scoped authorization.

**2026-08-16 update — the "Hardened hardware TPM witness" preset is now
partially *realized*, not only designed.** The full authorization →
one-time-consumption → `RecoveryContract` → confirmation → sealed-executor
ceremony this preset describes has now been exercised end-to-end,
live, twice, against a disposable LAB appliance
(`docs/adr/ADR-026-first-write-capability-adapter.md`), for the one
accepted `set_firewall_alias_description_v1` capability. The wizard
itself — an interactive tool that *provisions* this state for an
operator — remains unbuilt; everything provisioned for this workstream's
own LAB deployment (witness daemon, off-host signer, pinned authorities,
scoped pfSense credential) was done by hand, by the owner and an AI
session working together across many narrow, individually-authorized
steps, not by any wizard. That manual process is itself the best
available specification for what the wizard needs to automate — the
concrete open design/implementation items below, refined against that
lived experience rather than only theory:

- **Ceremony TTL/operator UX** — the live ceremonies surfaced concrete,
  addressable friction, all fixable without touching the 5-minute
  authorization/confirmation freshness window itself (which must stay
  exactly as tight as it is — the window is a deliberate security
  property, not a UX defect):
  - **Reporting/documentation work must never happen inside a started
    clock.** Every real timing failure this workstream hit was caused
    by intermediate reports-ai synchronization or narration eating into
    an already-running 5-minute window, never by the ceremony's own
    steps being slow. A wizard (or any operator tooling) built on top of
    this ceremony should structurally separate "prepare" (non-time-
    sensitive: generate the preview, pre-stage the signer's authority/
    witness-identity files, verify connectivity) from "execute"
    (time-sensitive: sign → verify → deliver → consume → confirm →
    execute, continuously, with zero pauses for anything else) as two
    distinct, clearly-labeled modes — never one undifferentiated flow.
  - **Stale artifact-exchange files caused two separate real
    incidents** (a pre-positioned `confirmation-signed.bin` from a
    prior completed ceremony; a signer with a stale local witness-store
    snapshot reporting `provisioned_mismatch`). Both were caught by
    read-only preflight checks and root-caused correctly, but a
    dedicated `doctor`/preflight command that checks *all* fixed
    artifact-exchange paths are empty and the signer's local evidence
    snapshot is current *before* generating a fresh preview would catch
    both automatically instead of relying on an operator noticing.
  - **A visible remaining-validity countdown** (in the CLI review
    output, refreshed live) would make the "how much time do I actually
    have left" question — which this workstream repeatedly had to
    answer by manually diffing timestamps — a glance instead of
    arithmetic.
  - **The signing tool should refuse up front, before rendering any
    review, if the artifact it's about to review is already
    unrecoverably close to expiry** (e.g. under some small fixed
    margin), with a clear "re-prepare and try again" message — turning
    a wasted review-then-refuse cycle into an immediate, actionable
    refusal. This is a stricter refusal, not a relaxed one — it never
    extends validity, only refuses earlier and more clearly than
    reaching the existing `now < expires_at` check deeper in the flow.
  - None of the above changes what is or isn't authorized, extends any
    TTL, adds a grace period, or auto-approves anything — each is
    purely about making the existing, unchanged freshness/confirmation
    semantics easier for a human to operate correctly under.
- **pfSense least-privilege bootstrap**, now that it has been done once
  for real (`reports-ai/reviews/SLICE6_LEAST_PRIVILEGE_PROVISIONING_2026-08-16.md`):
  the wizard's own version of this step should derive privilege IDs the
  same way this workstream ultimately did — from the installed REST API
  package's own source (`Core/Endpoint.inc::get_method_priv_name()`'s
  deterministic per-endpoint-per-method naming), pinned to the actually
  installed package version, never guessed or hardcoded — and should
  separate account creation (needs a password field even for
  API-key-only use) from API-key self-generation (requires a distinct,
  narrow, revocable bootstrap privilege the target account does not
  otherwise need). **`pfsense-mcp-security bootstrap`: implemented,
  offline-verified only, 2026-08-23** (ADR-033 CLI Integration Slice 3)
  — journal-aware, locking, deterministic orchestration of the engine
  above, wired as the CLI's only mutating subcommand. No live pfSense
  appliance has been contacted by this development task; see
  [`ADR-033`](adr/ADR-033-pfsense-least-privilege-bootstrap-architecture.md)'s
  "CLI/runtime integration Slice 3" section for the full design and
  exit-code model. `pfsense-mcp-security setup` (the full interactive
  wizard this bullet originally describes) remains unbuilt.
- **Doctor/preflight** (`pfsense-mcp-security doctor`): **implemented
  2026-08-17** — a genuinely safe, separable, read-only command,
  independent of the rest of the wizard. Checks the four fixed Tier 1
  artifact-exchange paths are clean and that the anti-rollback witness
  is currently `provisioned_verified`, directly addressing the two real
  incidents that motivated it (a pre-positioned stale
  `confirmation-signed.bin`; a signer with a stale local witness-store
  snapshot). One deterministic READY/NOT READY verdict, human and
  `--json` output, exit codes `0`/`1`/`2`. Never repairs, cleans, or
  mutates anything — diagnostic only. Full detail:
  [`SECURITY_POSTURE_PROVISIONING.md`](SECURITY_POSTURE_PROVISIONING.md)'s
  "Doctor/preflight slice" section. This is only the doctor/preflight
  slice, not the full `pfsense-mcp-security setup` wizard — the rest of
  this section's items (least-privilege bootstrap automation, signer
  separation, authority key generation, config/env generation, etc.)
  remain unbuilt.
- **Signer separation, authority key generation, config/env generation,
  validation, rollback, and explicit owner decision points** all remain
  as originally scoped above — the live ceremony re-confirmed each of
  these boundaries is load-bearing (in particular: the signer never
  holding pfSense credentials, and the confirmation and authorization
  authorities being genuinely separate keys) rather than surfacing any
  reason to reconsider them.

## WebGUI Evidence Layer (idea, not committed — independent of the security-posture work above)

Working name: **WebGUI Evidence Layer**. Idea-stage future direction
only — no design work beyond this roadmap entry exists yet, no ADR
exists, and nothing below authorizes building it, adding a dependency,
adding an MCP tool or capability, or touching a live pfSense appliance.
A dedicated ADR/spec is a future step once this is actually being
designed, not created merely to record the idea.

**Motivation**: a real-world, read-only certificate-manager diagnostic
session (2026-08-10) found a concrete, structural limit, not a bug —
the REST API correctly exposed the certificate inventory and expiry
(the MCP correctly identified the expired certificate), but could not
answer "which certificate is the webConfigurator actually presenting,"
because that relationship is only visible in the pfSense WebGUI itself
(`system.webgui.ssl-certref`, exposed at `/system/webgui/settings` —
see `READ_BACKLOG.md`'s "Post-snapshot discovery" addendum and the
matching item above). The owner independently confirmed the correct
answer via the GUI. This roadmap entry is about the general shape of
that gap, not only this one endpoint.

**Preferred hierarchy** (most to least authoritative):

1. **REST API** — authoritative structured source whenever the
   required information is exposed. Stays primary; this idea does not
   change that.
2. **Read-only WebGUI extraction/parsing** — a targeted fallback for
   information genuinely absent from the API, only. Prefer structured
   extraction from known WebGUI pages (parsing rendered HTML/DOM for a
   specific, known field) over image interpretation wherever feasible.
3. **Screenshot evidence** — the final visual fallback, used only when
   the relevant information cannot be reliably extracted structurally.
   May also be *captured* as provenance/evidence for a WebGUI-derived
   observation, independent of whether it was the extraction method —
   but capture is not the same as retention; see the retention
   questions below, which this idea deliberately leaves open rather
   than assuming screenshots are kept by default.

**Non-negotiable architectural principle: this must NOT become a
general browser-control capability.** An authenticated browser session
capable of submitting forms or clicking mutating controls would be an
undeclared WRITE path entirely outside the MCP capability registry —
directly contradicting this project's own foundational invariants
(`ADR-001` READ-only production architecture, `ADR-004` explicit
capability profiles, `ADR-005` WRITE stays inert until separately
authorized). Any future design must therefore investigate, at minimum:

- an explicit allow-list of supported WebGUI pages/routes — never
  arbitrary navigation;
- mapping specific READ capabilities/questions to their known relevant
  WebGUI page(s), so the model requests narrowly scoped supplementary
  evidence, never browses generally;
- navigation/read operations only;
- **prohibit POST/PUT/PATCH/DELETE and form submission** outright;
- prohibit interacting with Apply/Save/Delete or any other action
  control, even by accident (e.g. never click anything, only read
  rendered content);
- no generic arbitrary browser-automation surface exposed to the
  model, ever;
- credentials, cookies, CSRF tokens, and session material must never
  be returned to the model;
- WebGUI access represented explicitly in the capability/security
  model — not hidden inside an existing READ capability's
  implementation;
- **explicit provenance attached to every observation**, distinguishing:
  - `API_VERIFIED`
  - `WEBGUI_STRUCTURED_VERIFIED`
  - `WEBGUI_VISUAL_VERIFIED`
  - `INFERRED`
  - `UNKNOWN`
- WebGUI evidence must never silently override contradictory API
  data — disagreement between sources must be surfaced explicitly, not
  resolved by picking one silently;
- screenshots are evidence, not canonical structured configuration —
  never treated as a structured data source;
- **failure of the WebGUI evidence layer must never change pfSense
  state** — a failed/unavailable/ambiguous WebGUI read degrades to
  `UNKNOWN`, exactly like any other unreachable READ source in this
  project, never a fallback that silently mutates anything;
- **screenshot retention must not be assumed permanent or the
  default** — capturing a screenshot (for a visual-fallback
  observation, or as provenance alongside a structured one) is not the
  same decision as keeping it. Left as an open question for future
  design, not decided here: capture on demand rather than continuously;
  retain only when explicitly required for provenance/audit, not by
  default; redaction of sensitive WebGUI content before any retention;
  a bounded retention lifecycle (not indefinite storage); and, when a
  structured (`WEBGUI_STRUCTURED_VERIFIED`) observation is
  independently sufficient on its own, retaining an accompanying
  screenshot should not be required just because one was captured
  during extraction.

**Potential future capability shape** (illustrative only, not a frozen
contract): something resembling `pfsense_get_webgui_evidence(page=...)`.
Exact tool shape, naming, and whether it is one tool or several remains
undecided.

**Capability-specific evidence mapping — a design question worth
investigating explicitly**, rather than a single generic
"fetch any WebGUI page" tool: whether each existing READ capability
should carry its own declared WebGUI evidence source, e.g.:

> `SYSTEM_CERTIFICATE_READ`
> — REST source: certificate API (already implemented)
> — WebGUI evidence source: Certificate Manager page (not implemented)

This would let a future implementation request narrowly scoped
supplementary evidence automatically, only when the normal REST-backed
READ capability's answer is genuinely incomplete for the question
asked — never as a general "browse the GUI" escape hatch.

## Tier 2 — additional controlled capabilities

**2026-08-17 update — Tier 1 now has production evidence** (see
"Current baseline" above), satisfying this section's own precondition
for the first time. **Selecting a second WRITE capability remains
explicitly pending a separate, future owner decision** — Tier 1's
completion for one capability does not by itself authorize a second
one. [`WRITE_ENDPOINT_RISK_MATRIX.md`](WRITE_ENDPOINT_RISK_MATRIX.md)
already triages 240 upstream writable endpoint classes by risk,
rollback strength, verification confidence, and blast radius, so this
decision — whenever the owner chooses to make it — has a prepared,
reviewed starting point rather than a blank one.

### Possible future direction

Tier 2 may add further mutations only after Tier 1 has production evidence and
each capability independently satisfies the same recovery standard.

Potential categories—without commitment—include narrowly reversible firewall
alias maintenance or similarly bounded resources. High-blast-radius network,
interface, routing, authentication, certificate/private-key, VPN, and service
mutations should remain deferred until the recovery model has substantial
operational evidence.

Tier 2 should consider:

- capability-specific authorization/profile separation;
- policy-as-code approval for targets and payload shape;
- multi-operation transaction limits and dependency ordering;
- stronger operator identity if transport expands beyond trusted local stdio;
- independent safety review for every endpoint.

## Long-term vision

The project may become a trustworthy pfSense operations interface for MCP
clients: strongly typed, capability-scoped, observable, recoverable, and useful
for both audit and carefully controlled administration.

Long-term success means:

- public schemas remain intentionally small and credential-free;
- READ stability is protected as controlled capabilities evolve;
- mutations are recoverable by construction rather than prompt convention;
- public CI stays fully synthetic and private infrastructure stays private;
- compatibility, provenance, and security evidence accompany every release;
- operators can understand exactly what authority a profile and tool grant.

## How roadmap changes are accepted

Roadmap edits require normal review. Moving an item from Candidate/Ideas to
Committed requires explicit owner approval. Capability activation additionally
requires architecture, security, acceptance, Git, and release approval under
the repository policy.
