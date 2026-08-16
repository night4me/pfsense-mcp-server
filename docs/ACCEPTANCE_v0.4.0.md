# Acceptance — v0.4.0

**Status: release-candidate quality, prepared, not yet tagged or
published.** This document records what has been verified as of the
release-preparation commit; the final "Acceptance boundary" section below
states precisely what is, and is not, authorized by it.

## Release scope

v0.4.0's public MCP contract is **unchanged from v0.3.1: 42 READ tools, 0
WRITE tools under the default profile.** No new tool, no new capability,
no schema change, no removal.

The headline change is that the one WRITE capability this project has
ever accepted, `set_firewall_alias_description_v1`
(`WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION`), is now `verified=True`.
That flag had been deliberately `False` since it was introduced —
described in its own module docstring as "an intentional, additional
layer of protection beyond the activation gate, not an oversight" —
pending independent live evidence. That evidence now exists:

- **Two real pfSense mutations**, both against a disposable, isolated LAB
  appliance (`https://pfsense-test.lab.invalid`), never production or
  home pfSense, each driven through the complete, unmodified production
  Tier 1 ceremony (fresh authorization → off-host signature → one-time
  consumption → `RecoveryContract` → confirmation → off-host signature →
  sealed executor). Both reached `RecoveryContract` state `VERIFIED` with
  a clean, MAC-authenticated audit trail and zero rollback/reconciliation
  events. The TPM anti-rollback witness advanced exactly once per
  mutation (`2 → 3`, then `3 → 4`), independently confirmed against the
  persisted high-water mark both times.
- **The second of those two mutations was performed entirely through a
  dedicated, least-privilege pfSense identity** (`pfsense_mcp_tier1_lab`)
  holding exactly the four privileges the production path needs — never
  the administrative account — with its privilege grant independently
  re-read and confirmed unchanged both before and after the mutation.
- **A strict, owner-confirmed re-check of every ADR-026 acceptance-matrix
  row**, evaluated individually against its own exact wording (not
  grandfathered from any earlier pass), confirmed every row satisfied —
  either by this live evidence directly, or by production-bound offline
  tests exercising the real Tier1 composition with only the external
  pfSense transport substituted.

See `docs/adr/ADR-026-first-write-capability-adapter.md` for the complete
evidence chain, and `docs/SECURITY_MODEL.md`'s "Recovery and WRITE
status" section for the current, precise description of what
`verified=True` does and does not expose.

**`verified=True` does not enable WRITE by default.** Reaching the tool
still requires every one of these, simultaneously:

1. An operator explicitly selecting `PFSENSE_PROFILE=write_protected`
   (never the default).
2. The endpoint's allow-list entry (present, but inert without the other
   two conditions).
3. A successfully constructed production runtime — itself requiring the
   full Tier 1 security material (pinned Ed25519 authorities, a
   provisioned encrypted `RecoveryContract` store, live TPM witness
   connectivity) to be independently configured; a deployment missing
   any of it gets `None` back from `build_production_runtime()` and the
   tool is never registered, regardless of profile or `verified`.

And even once reachable, every individual mutation still requires the
operator to personally drive the full signing ceremony described above —
nothing about it is automatic, and no MCP client, AI session, or
automated process can complete it unattended.

## Accepted changes

- `src/pfsense_mcp/write_endpoints.py`: `FIREWALL_ALIAS_DESCRIPTION.verified`
  `False → True`, with the module docstring rewritten to state the exact
  live-evidence chain that justifies it.
- Two "tripwire" tests specifically designed to fire the moment this flag
  changed (`tests/tier1/test_acceptance.py`,
  `tests/tier1/test_acceptance_isolation.py`) converted into positive
  assertions of the new state — including a new regression proving
  `issue_acceptance_context()` now permanently refuses the real endpoint
  (its one-time acceptance-evidence-gathering path is retired for this
  endpoint, by design, once `verified=True` holds).
- `docs/adr/ADR-026-first-write-capability-adapter.md`: full live-evidence
  sections recording both mutations, the least-privilege credential
  proof, and the strict row-by-row re-check.
- One new offline regression test closing a genuine gap found during the
  strict re-check (`test_production_adapter_send_timeout_reaches_
  reconciliation_not_failed_or_resend`) — a `TransportTimeoutError` on
  the real adapter's send correctly lands in `RECONCILIATION`, never
  licenses a resend.
- `RecoveryContract.is_permanently_unresumable()`: a pure, additive,
  read-only observability helper for the (harmless, historical, never
  deleted) dead `PREPARED` contracts left by earlier ceremony attempts
  that expired before completion.
- `PfSenseUser.expires`: nullable-model correctness fix (the live API
  legitimately returns `null`, not `""`, when no expiration is set) found
  while gathering least-privilege evidence.
- `PfSenseClient.get_config_history_revisions()`: new, narrow READ
  capability added to gather config-history side-effect evidence
  (ADR-026 row 18); not part of the production WRITE path.
- Documentation consistency pass across `docs/SECURITY_MODEL.md`,
  `docs/THREAT_MODEL.md`, `README.md`, `SECURITY.md`,
  `docs/tier1/IMPLEMENTATION_ROADMAP.md`, and every `examples/*.md` MCP
  client guide, correcting stale "WRITE is categorically inert/absent"
  claims and stale `41`-tool counts (the 42nd tool, `pfsense_mcp_info`,
  shipped in v0.3.1) to the current, accurate state.
- `examples/README.md` gained a new section explicitly documenting the
  `write_protected` profile opt-in, since no client guide previously
  mentioned it at all.

## CI evidence

To be finalized against the exact release-preparation commit before
tagging — this section must record that commit's own successful CI
(`pytest` across supported Python versions, coverage, docs, Bandit) and
CodeQL run URLs, matching the discipline every prior `ACCEPTANCE_vX.Y.Z.md`
in this repository follows. Not yet filled in as of this document's
initial commit; see the corresponding commit message and `git log` for
the exact SHA and `gh run list` for its CI/CodeQL results in the
meantime.

## Package verification

- Version metadata: `0.4.0`; Python 3.11+; supported production platform
  Linux; MIT `License-Expression`; Markdown README; typed-package marker.
- Hatchling builds one wheel and one sdist with the expected console
  entry point.
- Distribution verification requires the license, README, PyPI
  procedure, this acceptance document, package source, metadata, and
  entry point (`scripts/verify_distribution.py` updated to require
  `docs/ACCEPTANCE_v0.4.0.md` specifically).
- Clean wheel installation/import and configuration-absent fail-closed
  startup pass through `make package-check`.
- Strict Twine checks pass for both artifact types.
- Artifacts exclude credentials, key/private-key files, `.env`, AI
  reports (`reports-ai/`), local configuration, caches, fixtures, and
  temporary state — confirmed by direct member-listing inspection of
  both the wheel and sdist, not only by the automated check.

## Security invariants

- Credential values and prohibited credential fields remain absent from
  MCP schemas, outputs, logs, errors, fixtures, documentation, and
  distributions.
- Production READ transport remains GET-only and independently
  endpoint-gated.
- Capability profiles remain authoritative; annotations and tool
  restrictions cannot grant access.
- The Auditor profile registers exactly 42 READ tools without
  restriction; Engineer registers zero. Both independently re-confirmed
  this release, unchanged from v0.3.1.
- **The WRITE endpoint allow-list contains exactly one entry
  (`FIREWALL_ALIAS_DESCRIPTION`), which is now `verified=True`, but zero
  WRITE tools register under the default profile** — independently
  confirmed via `make quick`'s write-capability-inactivity check (`0 of 3
  *_WRITE capabilities are default-reachable`) and `make validate`'s
  public MCP contract snapshot (`42 tools`, unchanged).
- Reaching the one gated WRITE tool requires explicit `write_protected`
  profile selection **and** a successfully constructed production
  runtime **and** a real, owner-driven signing ceremony per mutation —
  all three independently re-verified live, twice, this release.
- Public CI uses no production configuration, credential, or live
  pfSense call.

## Verification evidence

- Full offline pytest (2823 passed, 42 live-skipped), Ruff, mypy,
  `mkdocs --strict`, `make quick` (11 stages), `make validate` (20
  stages), and `make package-check` pass on the release-state tree.
- Bandit, fixture safety, repository security, GET-only, WRITE
  import-absence, write allow-list scope, WRITE-capability inactivity,
  and git-identity-leak checks pass.
- Two independently-verified live pfSense mutations against the LAB
  appliance (see "Release scope" above) — `docs/adr/
  ADR-026-first-write-capability-adapter.md` records the complete,
  independently-reconstructed evidence chain for both, not copied from
  any intermediate session report.
- No production or home pfSense call, credential access, or mutation was
  performed while preparing this release state.

## Compatibility

All 42 tool names, inputs, outputs, schemas, and semantics from v0.3.1
are **unchanged**. This is a non-breaking release for every existing
deployment: the public contract snapshot
(`tests/contracts/mcp_public_contract_v0.4.0.json`, renamed from the
v0.3.1-era file, content byte-identical) continues to gate any future
drift via `make validate`.

## Known limitations

Unchanged from v0.3.1 unless noted: the supported trust boundary remains
a local stdio MCP process controlled by a trusted launcher; Linux remains
the supported production platform for descriptor-bound credential
loading; CodeQL SARIF upload remains an open, undecided option;
GitHub Pages redeployment remains a manual step; `dependabot.yml`'s
cadence remains a deferred judgment call.

New to this release:

- A second WRITE capability, or broadening the one accepted capability's
  scope, remains explicitly out of scope — this project's own standing
  roadmap ceiling requires a new, separate, explicit owner decision
  before either.
- The scoped least-privilege pfSense identity used for the second live
  mutation is not (yet) the persistent runtime default in
  `tier1-lab.env` — that file still points at the administrative
  credential for day-to-day LAB work; switching the default is a
  separate, low-risk, not-yet-decided follow-up, distinct from this
  release's own acceptance criteria.
- Ceremony TTL/operator-UX improvements, the `pfsense-mcp-security
  setup` wizard, and a full GitHub Actions/release-workflow audit were
  reviewed to varying depth as part of this release's preparation — see
  the corresponding sections of the preparation record for exactly what
  was and was not completed.

## Acceptance boundary

This document accepts the v0.4.0 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload,
live pfSense access beyond what is already recorded above, credential
rotation, or any further WRITE. Each of those remains a separate,
explicit, owner-only action.
