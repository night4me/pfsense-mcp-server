# Acceptance — v0.4.1

**Status: published — the `v0.4.1` tag and PyPI release point at this
commit.** This document records what changed since
`docs/ACCEPTANCE_v0.4.0.md`, which remains the authoritative acceptance
record for every functional and security claim unchanged by this
release — nothing in the Tier 1 architecture, `verified=True` gating,
the scoped pfSense credential, or the live-evidence chain changed
between v0.4.0 and v0.4.1.

## Release scope

v0.4.1 is a **release-repair release only**. Its public MCP contract is
unchanged from v0.4.0/v0.3.1: 42 READ tools, 0 WRITE tools under the
default profile. No new tool, no new capability, no schema change, no
security-relevant code change of any kind.

Three things changed, all documentation/build-metadata:

1. **`[build-system] requires` tightened** from `hatchling>=1.25,<2.0`
   to `hatchling>=1.25,<1.32`, fixing v0.4.0's PyPI publish failure
   (`twine check --strict` rejected `Metadata-Version: 2.5`, which a
   Hatchling release beyond the new ceiling emits by default). Verified
   directly: an isolated-equivalent build at the new ceiling resolves
   exactly `hatchling==1.31.0` and produces `Metadata-Version: 2.4`,
   confirmed by inspecting the built wheel's `METADATA` file and a clean
   `twine check --strict` pass. The floor (`1.25`) was independently
   re-confirmed still installable and fully test-passing via
   `make min-deps-check`.
2. **The long-standing "v0.3.1 is published on PyPI" claim in README was
   found false and corrected.** No `v0.3.1` git tag, GitHub Release,
   publish-workflow run, or PyPI upload has ever existed — v0.3.1 was
   prepared only (version bump + changelog entry, commit `459262e`,
   2026-08-09) and the tag/release/publish sequence was never carried
   out. See this release's `CHANGELOG.md` entry for the full,
   read-only-investigated finding.
3. **A new README "Security-first by design" section** documents the
   protected-WRITE architecture's actually-shipped properties, without
   unsupported ranking/superlative claims, and states plainly that
   `verified=True` does not itself enable WRITE by default.

## What this release does NOT do

- Does not perform, and did not require, any further pfSense contact of
  any kind (no WRITE, no additional READ ceremony, no privilege change,
  no credential rotation).
- Does not touch the TPM witness in any way — `high_water_mark` remains
  `4`, unchanged since v0.4.0's own restoration ceremony.
- Does not move, delete, or reuse the `v0.4.0` git tag or its GitHub
  Release. Per `docs/PYPI_RELEASE.md`'s own "Failure and rollback"
  policy ("a Git tag or GitHub Release must not be moved to conceal a
  bad upload" / "fix the problem in a new patch version"), v0.4.0's tag
  and Release remain a permanent, accurate historical record of a
  release that was tagged and announced on GitHub but never
  successfully reached PyPI — they are not edited, hidden, or
  retroactively "fixed" by this release.
- Does not retroactively create a `v0.3.1` tag or upload a `v0.3.1`
  package to PyPI or TestPyPI. The historical record
  (`docs/ACCEPTANCE_v0.3.1.md`, the `[0.3.1]` changelog entry) is
  preserved as written at the time; only the since-added, objectively
  false "published" claims elsewhere were corrected.

## Acceptance boundary

This document accepts the v0.4.1 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further pfSense/witness/credential action. Each of those remains a
separate, explicit owner decision, taken only after this document and
the exact commit SHA it corresponds to have been reviewed.
