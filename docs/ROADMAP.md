# Public roadmap

This roadmap communicates direction, not a promise of dates or features. Items
under **Committed** are accepted project goals; **Candidate** items require
design/review; **Ideas** are exploratory. No roadmap entry activates a
capability or authorizes a production change.

## Current baseline

- Immutable published baseline: v0.3.0 — the same READ-platform contract as
  v0.2.2, plus the Tier 1 architecture and inert safety framework as
  implemented, tested, and structurally isolated code. Production
  mutation remains separately blocked.
- Production MCP surface: 41 READ tools, 0 WRITE tools.
- Tier 0 WRITE infrastructure: present, tested, and inert.

## v0.2.x — hardening and public-project readiness

### Committed

- Preserve the existing 41-tool READ API and GET-only production path.
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
  public-contract addition does.

## Tier 1 — first controlled mutation

Tier 1 activation is a separately authorized security program. v0.3.0 may
contain inert framework code, but the first capability and endpoint remain
unnamed until threat, reversibility, upstream semantics, encryption, durable
anti-rollback, and operator-authentication decisions are approved.

### Required before commitment

- Authoritative Recovery Contracts loaded by ID and bound to capability,
  endpoint, method, target, intent, snapshot, and rollback plan.
- Atomic legal state transitions, replay/concurrency controls, and expiry.
- Explicit durable persistence/crash/restart behavior.
- Typed payload transmission and exact HTTP outcome validation.
- Semantic read-back before commitment and after rollback.
- Operator reconciliation for ambiguous outcomes.
- Capability-specific least privilege, audit, tests, and private test-appliance
  acceptance.

See [Tier 1 roadmap](TIER1_ROADMAP.md). Until every gate is accepted, zero
WRITE tools register.

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

## Tier 2 — additional controlled capabilities

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
