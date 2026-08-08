# Tier 1 activation decisions

Status: decision record for future design. Nothing in this document authorizes
an endpoint, adapter, tool, capability, credential, or mutation.

**Resolution:** the open decisions below are recommended and specified in
[ADR-009 through ADR-016](adr/README.md) and
[docs/tier1/specs/](tier1/specs/), following an independent architecture
review (`reports-ai/reviews/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`). This
document's options analysis remains valid background reading; treat the
ADRs as the current recommendation and
[`docs/tier1/IMPLEMENTATION_ROADMAP.md`](tier1/IMPLEMENTATION_ROADMAP.md)
as the execution sequence.

## External reviews and current conclusion

Three hostile review lenses reach the same conclusion:

- State/cryptography review: record HMAC, closed transitions, CAS, reservations,
  exact binding, and no-retry ambiguity handling are sound foundations. Store
  confidentiality, whole-store rollback, and authenticated manual resolution
  remain activation blockers.
- Supply-chain review: Tier 1 adds no runtime dependency, import path, endpoint,
  or packaged secret. A future crypto provider must be reviewed and pinned as a
  separate dependency decision.
- Hostile-maintainer review: a poorly written adapter could bypass safety if it
  receives a raw transport. The future executor must exclusively own transport,
  policy, state transitions, send count, and verification orchestration.

Framework readiness was **READY FOR WRITE DESIGN ONLY** at the time of this
review. Design has since become implementation: every Phase 1–4 subsystem in
[`docs/tier1/IMPLEMENTATION_ROADMAP.md`](tier1/IMPLEMENTATION_ROADMAP.md) is
now implemented and tested, including the sealed executor and an
offline-tested disposable-lab harness — see that document's phase-completion
table for the authoritative current status. It is still not ready for a real
adapter, a *live* disposable-lab mutation, or production activation: those
each remain gated on a real candidate adapter, live lab evidence, and
separate, explicit capability/endpoint authorization, none of which this
review or its resolution grants.

## Protected-artifact confidentiality options

HMAC authenticates stored bytes but does not hide them. A provider must use
authenticated encryption and keep the encryption key outside the SQLite file.

| Option | Strengths | Costs and failure modes | Assessment |
|---|---|---|---|
| OS keyring | Familiar API and rotation indirection | Headless availability and backend security vary; session services may be absent | Possible, requires exact Linux backend decision |
| systemd credential | Strong service-time delivery, tmpfs-backed, unattended Linux startup | Ties deployment to systemd; rotation/recovery need unit procedures; encryption primitive still needed | Good key-delivery candidate, not a complete codec |
| libsodium SecretBox/AEAD with local key | Mature authenticated encryption, offline, simple envelope | Adds reviewed dependency; local key file lifecycle, backup and rotation remain operator duties | Good codec candidate after dependency/key policy approval |
| age-style local encryption | Auditable recipient model and useful offline recovery | Subprocess/library choice, identity rotation, and unattended decryption add complexity | Better for backup/export than hot store access |
| TPM-sealed key | Hardware binding and measured-state options | Recovery, hardware portability, provisioning and disaster recovery are complex | Highest assurance option for mature deployments, not first implementation |

No provider is selected. Owner decisions must cover threat model, unattended
startup, rotation, backup, recovery, key loss, retention, and secure deletion.

## Whole-store anti-rollback options

An internally authenticated old database remains valid. A hash chain stored only
inside that database does not fix this.

| Option | Detects old DB restore? | Operational tradeoff |
|---|---:|---|
| External monotonic counter/checkpoint | Yes, if independently durable and atomically advanced | Must reconcile counter/store crash ordering |
| Append-only external digest log | Yes, if attacker cannot roll back both | Requires protected remote/local append service and availability policy |
| TPM/NVRAM counter | Yes, hardware-backed | Write endurance, provisioning and recovery complexity |
| Signed checkpoint outside DB | Only if checkpoint storage has independent rollback protection | A second ordinary file alone is insufficient |
| Git-like internal hash chain | No, by itself | Useful tamper evidence, not an independent anchor |

Activation requires an owner-selected independent anchor and explicit recovery
rules for store-ahead, anchor-ahead, unavailable-anchor, backup restore, and
disaster recovery. Availability failure must block mutation.

## Authenticated owner confirmation

The implemented verifier protocol accepts opaque, exact-bound evidence; it does
not select an authority. Viable providers are:

- detached signature by an owner key, verified locally against a pinned public
  key; strong and offline, with explicit key rotation/revocation procedures;
- hardware-backed signature; strongest key custody, higher operator friction;
- local confirmation file containing a detached signature, atomically consumed;
- CLI challenge/response only when the response is cryptographically derived
  from the full contract challenge;
- MCP confirmation evidence only when it carries an externally authenticated
  signature. A plaintext token, prompt assertion, or boolean is insufficient.

The recommended design study is a detached signature over the complete evidence
envelope, optionally hardware-backed. The owner must choose authority identity,
algorithm, key custody, revocation, expiry, nonce replay store, and emergency
reconciliation authority before implementation.

## Rate, concurrency and blast radius

Authorization is primary; rate controls only contain damage. Policy must be
atomic and monotonic-time based, scoped independently by capability, canonical
target, and global executor. It must define outstanding PREPARED limits,
concurrent mutation limits, cooldown, expiry cleanup, rollback-attempt limits,
and a manual-reconciliation lockout. Refused and dry-run attempts need explicit
accounting semantics. No numeric defaults are selected without lab evidence.

## Candidate 1: firewall-alias description-only PATCH

This remains the preferred **design study**, not an authorized adapter.

- Natural identity: exact normalized alias name; numeric ID is locator only.
- Intended projection: description text only, with an explicit bounded type.
- Forbidden: name, type, address/content entries, detail, bulk fields, create,
  delete, apply/reload, and any field not present in the approved projection.
- Snapshot/fingerprint: complete semantic alias projection, including all
  forbidden fields, plus config-history evidence if the endpoint changes config.
- Request: exact verified PATCH endpoint and only the accepted description
  payload required by lab OpenAPI; no pass-through dictionaries.
- Read-back: exactly one alias by natural name; intended description matches and
  every forbidden field equals the pre-state.
- Rollback: patch the original description only after current state/fingerprint
  proves no unrelated change; then read back full semantic equality.
- Ambiguity: no retry; authoritative re-read, then authenticated reconciliation.
- Concurrency: one reservation per canonical alias; other aliases may proceed
  only under global/capability policy.
- Lab blockers: prove exact request shape, whether omitted fields are preserved,
  whether a reload/apply occurs implicitly, config-history behavior, timeout
  ambiguity, concurrent manual edit, and deterministic rollback.
- Residual risk: aliases influence firewall policy; an apparently descriptive
  update may trigger broader config writes or reload behavior.

## Candidate 2: system-tunable description-only PATCH

This is a weaker fallback study. Natural identity is exact tunable name. Only
description may change; name and value are forbidden. Snapshot, fingerprint,
read-back, rollback, ambiguity, and concurrency rules mirror Candidate 1.
Disposable-lab OpenAPI must prove the API does not require or rewrite the value,
and must measure config/service side effects. Because tunables are system-level
configuration and endpoint semantics may couple description and value, this
candidate is not preferred without stronger evidence.

No third candidate currently demonstrates a lower combined blast radius,
identity risk, rollback uncertainty, and API ambiguity.

## Disposable-lab evidence required

For either candidate, the isolated lab must capture a known-good synthetic
baseline and exercise normal mutation/rollback plus network loss, response loss,
pfSense restart, stale snapshot, duplicate target, concurrent manual change,
failed verification, rollback conflict, config-history failure, store restart,
and ambiguous outcome. The hypervisor snapshot is containment, never claimed as
application rollback. Production remains outside the test network.

## Mutation/property testing decision

Seeded deterministic fuzz tests currently cover canonical object ordering and
the full transition matrix without adding a dependency. Hypothesis would add
value once typed adapter projections exist; adding it now would mostly restate
finite invariants. Focused mutation testing should first target canonical
framing/limits, contract validation, transition guards, policy matching, and
store CAS/reservation/audit checks. Tool adoption is deferred until a maintained
runner and bounded CI budget are selected.
