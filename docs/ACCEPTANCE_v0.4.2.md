# Acceptance — v0.4.2

**Status: published — the `v0.4.2` tag and PyPI release point at this
commit.** This document records what changed since
`docs/ACCEPTANCE_v0.4.1.md`, which remains the authoritative acceptance
record for every functional and security claim unchanged by this
release — nothing in the Tier 1 architecture, `verified=True` gating,
the scoped pfSense credential, or the live-evidence chain changed
between v0.4.1 and v0.4.2.

## Release scope

v0.4.2 is a **documentation/packaging presentation patch only**. Its
public MCP contract is unchanged from v0.4.1/v0.4.0/v0.3.1: 42 READ
tools, 0 WRITE tools under the default profile (confirmed byte-identical
against the frozen `tests/contracts/mcp_public_contract_v0.4.1.json`
snapshot). No new tool, no new capability, no schema change, no
security-relevant code change of any kind — no file under `src/` changed
between v0.4.1 and this release.

Everything that changed is README/documentation-site presentation:

1. **Portable README links for PyPI.** 29 README link occurrences
   across 11 distinct targets were repository-relative and silently
   broke when the same file rendered as the PyPI long_description
   (PyPI's renderer has no repository filesystem context). Converted to
   either the published MkDocs page or an absolute GitHub blob URL,
   matching the convention `mkdocs.yml` already used for its own
   non-MkDocs-published links. A regression check
   (`readme_portability_errors` in `scripts/validate_docs.py`, wired
   into `make validate`) now fails the build if a repo-relative link is
   ever reintroduced.
2. **Corrected 42-tool catalog wording** — README had one stale
   "41-tool catalog" reference; every other reference in README,
   `docs/API.md`, and `scripts/public_contract.py` already agreed on 42.
3. **`docs/ACCEPTANCE_v0.4.0.md`'s status line corrected** to accurately
   describe that v0.4.0's PyPI publish failed (it previously read
   "published," written before that failure was discovered) and point
   to v0.4.1 as the fix. `v0.4.0`'s tag/Release were not touched.
4. **7 documentation pages exposed in `mkdocs.yml`'s navigation** that
   existed in the repository but were never linked from nav
   (`ACCEPTANCE_v0.3.0/v0.3.1/v0.4.0/v0.4.1`, `ADR-027/028/029`), and the
   deployed documentation site itself — stale since a 2026-08-09 build —
   redeployed from current `main`, publishing these plus everything
   added since then (`ADR-020` through `ADR-026`, TPM host-witness and
   production-store-bootstrap subsystem specs).
5. **Public-facing security description improvements** in README's
   "Security-first by design" section and its first-screen "42 READ / 0
   WRITE" line — every added claim traces directly to
   `docs/adr/ADR-026-first-write-capability-adapter.md`'s existing
   evidence chain; no new security capability or claim beyond what that
   document already substantiates.

## What this release does NOT do

- Does not perform, and did not require, any further pfSense contact of
  any kind (no WRITE, no privilege change, no credential rotation).
- Does not touch the TPM witness in any way.
- Does not move, delete, or reuse the `v0.4.0` or `v0.4.1` git tags or
  their GitHub Releases. Both remain permanent, accurate historical
  records.
- Does not introduce, imply, or claim any new security capability.

## Acceptance boundary

This document accepts the v0.4.2 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further pfSense/witness/credential action. Each of those remains a
separate, explicit owner decision, taken only after this document and
the exact commit SHA it corresponds to have been reviewed.
