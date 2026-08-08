# Tier 1 implementation blueprint

This directory contains the implementation-ready architecture produced in
response to the independent Claude architecture review
(`reports-ai/reviews/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`). It converts that
review's recommendations into specifications precise enough that a future
implementation agent (Codex or Claude) can build Phases 1–3 of
[`IMPLEMENTATION_ROADMAP.md`](IMPLEMENTATION_ROADMAP.md) without making a
new security-relevant design decision.

## Contents

- [`IMPLEMENTATION_ROADMAP.md`](IMPLEMENTATION_ROADMAP.md) — the
  definitive phase sequence (inert corrections → architecture
  implementation → sealed executor → disposable-lab validation → first
  adapter → production readiness review). Start here.
- [`specs/`](specs/) — one implementation-ready specification per
  subsystem: protected artifact encryption, key lifecycle, whole-store
  anti-rollback, confirmation authority, reconciliation authority, the
  sealed executor, the capability adapter contract, adapter restrictions,
  rate/blast-radius policy, and the disposable-lab execution model. Each
  spec defines purpose, security goals, invariants, trust boundaries,
  state ownership, interfaces, failure modes, recovery behavior,
  non-goals, required tests, activation requirements, and four
  checklists (implementation/review/security/test).

## Relationship to existing Tier 1 documents

This blueprint does not replace or duplicate the existing top-level Tier 1
documents — it resolves the open decisions they identified:

| Existing document | What this blueprint adds |
|---|---|
| [`../TIER1_ARCHITECTURE.md`](../TIER1_ARCHITECTURE.md) | Concrete interfaces for the components it describes narratively |
| [`../RECOVERY_CONTRACT_SPEC.md`](../RECOVERY_CONTRACT_SPEC.md) | Unchanged — remains the normative contract/fault specification |
| [`../TIER1_ACTIVATION_DECISIONS.md`](../TIER1_ACTIVATION_DECISIONS.md) | Resolved by [`../adr/`](../adr/) ADR-009 through ADR-016 |
| [`../TIER1_ROADMAP.md`](../TIER1_ROADMAP.md) | Milestone sequence unchanged; `IMPLEMENTATION_ROADMAP.md` here gives the concrete phase-by-phase execution order within those milestones |
| [`../WRITE_ENDPOINT_RISK_MATRIX.md`](../WRITE_ENDPOINT_RISK_MATRIX.md) | Unchanged — remains the source inventory for candidate selection |
| [`../TIER1_LAB_PLAN.md`](../TIER1_LAB_PLAN.md) | Operationalized by [`specs/disposable_lab_execution_model.md`](specs/disposable_lab_execution_model.md) |

## What this blueprint does not authorize

Nothing here activates WRITE, adds a production endpoint, adds a WRITE MCP
tool, adds a capability to any profile, contacts pfSense, or changes
release state. Every spec's "Activation requirements" section states its
own gates explicitly; `IMPLEMENTATION_ROADMAP.md`'s phase gates state the
overall sequence and where separate, explicit owner authorization remains
required.
