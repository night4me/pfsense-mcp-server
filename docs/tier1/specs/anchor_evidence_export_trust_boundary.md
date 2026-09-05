# Tier 1 — AnchorEvidenceExport trust boundary

Status: mechanism implemented (schema, sign/verify primitives, signer-side
discovery, plan-generation wiring, CLI config-split fix); **posture-evidence
private key NOT provisioned anywhere — this is an explicit, still-open owner
gate.**
Activation gate: the owner must select and personally execute one of the
candidate key-custody options below before `AnchorEvidenceExport` can be used
for a real Batch-1 signing ceremony.
Related: `ADR-021`/`ADR-022` (narrow amendment pending, see the ADR amendment
this spec is paired with), `src/pfsense_mcp/tier1/anchor_evidence_export.py`,
`src/pfsense_mcp/security_discovery_export.py`,
[confirmation_authority.md](confirmation_authority.md) /
[reconciliation_authority.md](reconciliation_authority.md) (this spec reuses
their `PinnedAuthority`/Ed25519 mechanics and their established precedent that
signing-side tooling lives off-host, deliberately outside `pfsense_mcp`).

## Background — the incident this responds to

2026-09-05: Round-1 Batch-1 authorization signing failed closed correctly —
the isolated signer's freshly re-derived security-plan digest did not match
the preview's own copy. Forensic reconciliation proved the root cause was an
environment-completeness gap in the signing instructions (missing
`PFSENSE_TIER1_STORE_PATH`/`_KEY_FILE`/`PFSENSE_TIER1_WITNESS_*` env vars on
the signer), not a real security-state drift, not a code regression, and not
preview corruption. A secondary, independent finding surfaced during that
investigation: the signer's own local copy of the runtime anchor store
(`store.json`) was already stale (baseline 3 vs. VM106's real baseline 4).

That staleness was structural, not accidental: the only way the signer
previously had to independently re-derive anchor assurance was holding a
**copy of the runtime `RecoveryContract` store and its integrity key**.
Nothing keeps that copy in sync, and holding it hands the signer the same
symmetric key that authenticates the real store — broader trust than the
signer's actual job (independently re-deriving the anchor-assurance inputs to
`compute_plan_digest()`) requires. `AnchorEvidenceExport` exists to close
that gap without widening the signer's trust footprint.

## Purpose

1. Define exactly what evidence the signer needs to independently re-derive
   `compute_plan_digest()`-equivalent anchor assurance.
2. Prove `AnchorEvidenceExport` supplies exactly that set, no more.
3. Record the still-open question — where the private key that signs a real
   `AnchorEvidenceExport` should live — with candidates, trust boundaries,
   and a recommendation, **without provisioning any real key** (explicit
   owner gate, 2026-09-05 owner direction: "STOP before creating/copying/
   installing a real posture-evidence private key anywhere").

## What is already built (this session; local commits only, not pushed)

- `tier1/anchor_evidence_export.py` — canonical
  `AnchorEvidenceExportPayload`/`AnchorEvidenceExport` schema, Ed25519
  sign/verify primitives, `to_bytes`/`from_bytes` serialization.
- `security_posture_types.py` — the 6 shared discovery types, extracted from
  `security_discovery.py` so a caller needing only the types is never forced
  to import `production_store.py`/`sqlite3` (mirrors the `transport_target.py`
  ADR-028 extraction precedent).
- `security_discovery_export.py` — signer-side `discover_anchor_assurance_
  from_export()`: verifies the export's signature, `store_id`, and bounded
  freshness window; performs the live TPM witness read itself; never imports
  `production_store.py`.
- `security_plan.py` — `generate_security_posture_plan_from_discovery()`:
  the same pure `_build_plan_from_discovery()` body `generate_security_
  posture_plan()` already used, now callable directly from an
  already-computed `SecurityPostureDiscovery` — proven byte-identical
  `compute_plan_digest()` for equivalent store-based and export-based
  evidence (`tests/test_security_plan_from_discovery.py`).
- `signing/write_batch1_signing.py` — unrelated CLI defect fixed in the same
  session: `_load_config()` split into `_load_authorization_config()`/
  `_load_confirmation_config()` so each subcommand only requires its own env
  vars.

**None of the above ever creates, holds, reads, or logs a real
posture-evidence private key.** `sign_anchor_evidence_export()` exists and is
exercised only by tests, with synthetic, ephemeral keys generated fresh per
test run.

## Security goals

- G1: The signer never holds a copy of the mutable runtime `RecoveryContract`
  store, its encryption key, or its integrity key merely to re-derive anchor
  assurance.
- G2: The evidence-signing key must never become a new, additional
  long-lived signing authority resident on VM106's ordinary runtime
  process — VM106 already holds the symmetric preview/pending-integrity keys
  required to run the ordinary Batch-1 write flow; this change must not add
  a new asymmetric signing authority to that same blast radius.
- G3: A forged, stale, or wrong-identity export must fail closed at least as
  strongly as the existing store-based discovery path — proven by identical
  `AnchorAssuranceDiscovery`/`compute_plan_digest()` semantics for equivalent
  evidence, not a weaker, signer-specific approximation.
- G4: Whatever mechanism eventually produces a real export must be at least
  as isolated as the mechanism that already signs Batch-1
  authorization/confirmation artifacts (the VMID 100 signer ceremony), never
  less.

## Trust boundary table

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Export vs. runtime store | Ed25519 signature by the pinned posture-evidence authority | Any claim the export makes about `baseline`/`handle`/`provisioned_at` | `verify_anchor_evidence_export_signature()` (implemented) |
| Export freshness | Bounded `[issued_at, expires_at)` window | An old, no-longer-current export | `discover_anchor_assurance_from_export()`'s freshness gate (implemented) |
| Exported evidence vs. live witness | A live TPM witness `.read()` at verification time | The export's own claimed baseline, taken alone | `discover_anchor_assurance_from_export()` always cross-checks the live witness value against `export.baseline`; never trusts the claimed baseline unverified (implemented) |
| Export identity vs. wrong-store substitution | `expected_store_id` supplied explicitly by the caller | The export's own `store_id` field | Explicit equality check, refused (not silently ignored) on mismatch (implemented) |
| Signing authority vs. VM106 runtime | Wherever the real private key ends up living | VM106's ordinary process | **Not yet closed — this is the open owner gate this document exists to inform** |

## Candidate key-custody mechanisms (owner decision required)

### Candidate 1 — New key generated and held on VM106 runtime

Rejected outright. This is precisely "provisioning a new posture-evidence
private key onto the ordinary runtime as an implementation convenience,"
which the owner explicitly forbade — it would violate G2 directly.

### Candidate 2 — The signer (VMID 100) signs its own evidence

Rejected. The signer is the *verifier* of anchor evidence in this design; if
it also produced the evidence it verifies, "independent evidence" collapses
to self-attestation with zero security value — the signer would merely be
re-asserting its own prior belief, defeating the reason
`AnchorEvidenceExport` exists at all.

### Candidate 3 — The TPM host witness daemon (192.168.1.39) gains a signing role

Rejected for now, not permanently. The daemon's role today is strictly
`GET /anchor/read` (open to any mTLS-trusted client) and `POST /anchor/
advance` (fingerprint-gated, per the existing `WITNESS_ADVANCE_CLIENT_
FINGERPRINTS` allow-list). Adding "sign an `AnchorEvidenceExport`" would be a
brand-new daemon capability requiring its own dedicated key-custody review —
out of scope for "the narrowest *existing* isolated mechanism," which is
what this decision was scoped to find.

### Candidate 4 — Reuse the existing off-host operator signing workflow, with a new dedicated key (RECOMMENDED)

The Batch-1 authorization/confirmation ceremony already has an established,
reviewed, working off-host signing workflow: an operator holds private key
material entirely off VM106, runs a signing script, and types an explicit,
interactive approval — never automated, never resident on VM106 or in the
MCP server process. `confirmation_authority.md`/`reconciliation_authority.md`
already establish the precedent that signing-side tooling for each new
signing domain is deliberately kept outside `pfsense_mcp` entirely, and that
the underlying Ed25519 mechanics (`PinnedAuthority`/`PinnedAuthoritySet`,
`ed25519_authority.py`) are reused, never reinvented, per domain.

This candidate:

- Mints a **new, dedicated** Ed25519 keypair — never reuses the
  authorization/confirmation/reconciliation private key bytes. Domain
  separation is already structurally enforced: `anchor_evidence_export.py`'s
  own `_SIGNING_DOMAIN` literal (`"pfsense-mcp-anchor-evidence-export-v1"`)
  ensures a signature over one domain's payload can never verify as a
  signature over another's, even if the same key were ever (incorrectly)
  reused.
- Places that new private key in the **same off-host custody** the existing
  authorization/confirmation keys already use — operator-controlled, never
  resident on VM106, never resident in the MCP server process.
- Requires no new physical device, workflow, or infrastructure — reuses the
  exact "operator holds the key, runs a script, types the literal approval"
  mechanics already proven correct for Batch-1 Round-1 signing.
- Satisfies G2 exactly: no new signing authority is added to VM106. VM106
  remains, as it is today, a producer of read-only evidence to be exported —
  never a signer of anything.

### Candidate 5 — Hardware-backed key (HSM / security key)

Not rejected, but out of scope for this decision. `confirmation_authority.
md`'s own Non-goals already record hardware-backed signing as a future
upgrade path requiring no verifier-side change — the verifier only ever
holds a public key and checks a signature, regardless of where the matching
private key physically lives. Candidate 4 is the minimal viable answer
today; Candidate 5 remains available as a strict, drop-in upgrade later.

## Recommendation

**Candidate 4.** A new, dedicated `posture-evidence` Ed25519 authority,
generated and held exactly where the existing authorization/confirmation
authorities already live (off VM106, operator-controlled), never on VM106's
ordinary runtime, never reusing existing authority key bytes. This is the
narrowest existing isolated mechanism that can produce this signature
without giving VM106's ordinary runtime a new long-lived signing authority:
no new infrastructure, no new device, no new custody model — only a new,
domain-separated keypair inside a workflow that already exists and has
already been exercised successfully (Batch-1 Round-1).

## What still needs building once the key exists (deliberately not started)

- An off-host signing command (mirrors `sign_anchor_evidence_export()`,
  already implemented and tested with synthetic keys) invoked from a script
  analogous to `write_batch1_signing.py` but never imported into
  `pfsense_mcp` — reads the already-computed, already-read-only anchor
  provisioning fields VM106 exposes, builds the payload, signs it with the
  off-host key, writes the resulting `AnchorEvidenceExport` to a file for
  transfer to the signer.
- A pinned-authority configuration on the signer analogous to
  `PinnedAuthority`/`PinnedAuthoritySet` already used for
  authorization/confirmation verification — reuses the exact same
  `ed25519_authority.py` primitives; no new verification mechanism needed.
- An operator runbook covering export-refresh frequency, expiry-window
  choice, and transfer mechanism (likely the same tar-over-SSH mechanism
  already used for the 54-file Batch-1 signer code transfer).

## Non-goals

- This document does not provision a real private key. That step is an
  explicit owner gate (2026-09-05 owner direction) and remains unchecked
  below until the owner personally executes it.
- This document does not implement the off-host signing script. Tracked as
  a distinct future deliverable, mirroring `confirmation_authority.md`'s own
  precedent of leaving signing-side tooling as a separate, explicitly
  out-of-`pfsense_mcp` deliverable.
- This document does not select a concrete expiry duration for a real
  export — that is a policy decision for whoever runs the off-host signing
  script, informed by how frequently a signer sitting actually occurs
  (mirrors `write_batch1_signing.py`'s own `_AUTHORIZATION_VALIDITY =
  timedelta(minutes=5)` "short enough that a stale artifact is
  operationally implausible" reasoning, but is not itself specified here).

## Activation requirements

- [x] `AnchorEvidenceExport` schema + Ed25519 sign/verify primitives
      implemented and tested (`tests/tier1/test_anchor_evidence_export.py`,
      39 tests).
- [x] Signer-side discovery function implemented and tested, proven never
      to import `production_store.py`/`sqlite3`
      (`security_discovery_export.py`,
      `tests/test_security_discovery_export.py`,
      `tests/test_security_discovery_export_isolation.py`).
- [x] Plan-generation wired for export-based evidence, proven
      byte-identical `compute_plan_digest()` for equivalent store-based and
      export-based evidence (`tests/test_security_plan_from_discovery.py`).
- [ ] Owner selects a key-custody candidate (Candidate 4 recommended above).
- [ ] Real posture-evidence private key generated and placed per the
      selected candidate — **owner-only action; not performed by, and not
      in scope for, this change.**
- [ ] Off-host signing script built.
- [ ] Signer's pinned-authority configuration updated to trust the new
      `authority_id`.
- [ ] A live LAB/production ceremony performed with a real export — out of
      scope for this session per explicit owner constraints (no LAB/
      production contact, no real key provisioning).

## Review checklist

- [ ] Confirm no code path in this repository ever constructs a real
      (non-test, non-ephemeral) `Ed25519PrivateKey` for the posture-evidence
      authority — grep for it, mirroring `confirmation_authority.md`'s own
      Security checklist for its domain.
- [ ] Confirm the chosen custody candidate never reuses
      authorization/confirmation/reconciliation key bytes for this new
      domain.
- [ ] Confirm the signer's trust in an export's `store_id`/freshness fields
      is always checked against explicit, operator-supplied expected
      values — never inferred from the export itself.

## Test checklist

- [x] Canonical export serialization round-trip
      (`tests/tier1/test_anchor_evidence_export.py`).
- [x] Ed25519 verify: correct authority, wrong authority, unknown authority,
      tampered signed field.
- [x] Malformed/empty proof rejected at construction.
- [x] Schema-version mismatch rejected.
- [x] Wrong `store_id` / expired / future-dated / boundary freshness
      rejected (`tests/test_security_discovery_export.py`).
- [x] Witness unavailable / value-mismatch outcomes reported, not
      reconciled.
- [x] Equivalent store-based and export-based evidence produce
      byte-identical `evidence_fingerprint`/`compute_plan_digest()`
      (`tests/test_security_plan_from_discovery.py`).
- [x] Signer-discovery isolation: never imports `production_store.py`/
      `sqlite3`, never calls a mutating tier1 method
      (`tests/test_security_discovery_export_isolation.py`,
      `tests/tier1/test_isolation.py`).
- [ ] End-to-end live ceremony with a real key — deferred to owner-gated
      activation.
