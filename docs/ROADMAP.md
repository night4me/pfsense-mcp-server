# Public roadmap

This roadmap communicates direction, not a promise of dates or features. Items
under **Committed** are accepted project goals; **Candidate** items require
design/review; **Ideas** are exploratory. No roadmap entry activates a
capability or authorizes a production change.

## Current baseline

- Immutable published baseline: v0.2.2 project, packaging, CI, documentation,
  and READ-platform hardening.
- Active development milestone: v0.3.0 Tier 1 architecture and inert safety
  framework. Production mutation remains separately blocked.
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
- Specify and test the Recovery Contract, closed state machine, canonical
  digests, authenticated persistence, policy bindings, and audit event model.
- Keep the Tier 1 package outside production bootstrap with an empty mutation
  policy, no WRITE endpoint, no executor, and no registered WRITE tool.
- Produce a risk-ranked WRITE endpoint study and disposable-lab acceptance
  design before asking the owner to select a first capability.

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
