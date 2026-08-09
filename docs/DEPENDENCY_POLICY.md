# Dependency and supply-chain policy

## Scope

The project supports Python 3.11–3.13. Runtime dependencies use explicit
minimum versions and next-major upper bounds. Development tooling is optional
and similarly bounded. A dependency change must preserve the offline test
suite, package verification, GET-only enforcement, and credential
non-disclosure guarantees.

## Updates

Dependabot checks Python packages and GitHub Actions weekly. Its pull requests
are proposals, not automatic approvals: maintainers review release notes,
security impact, compatibility, and the complete local/CI verification before
merging. Major-version updates are handled deliberately rather than grouped or
blindly accepted.

GitHub Actions are pinned to immutable commit SHAs with a human-readable
release comment. A version-tag-only reference is not sufficient for a
security-sensitive workflow.

## Reproducibility

The library intentionally has no committed deployment lockfile: consumers may
resolve compatible versions within the declared ranges. CI records the Python
matrix and resolved environment in job logs. Release artifacts should be built
from a clean checkout with `SOURCE_DATE_EPOCH` set to the release commit time,
then checked with `make package-check` and `twine check`.

A release SBOM should describe the built distribution environment, not the
developer host. CycloneDX JSON is the preferred format. `make sbom` implements
this: it builds a fresh wheel, generates the SBOM from a clean, isolated
install of that wheel (never the developer host) using a pinned
`cyclonedx-bom` version installed into a second, separate throwaway venv, and
verifies the result offline (`scripts/verify_sbom.py` — CycloneDX shape,
component name, non-empty dependency list, no local home path or
editable-install reference) before writing it to the git-ignored
`dist/sbom/`. `make sbom` is deliberately outside `quick`/`validate`/
`release-check`: it requires network access to install the pinned generator
tool and is not needed for every local iteration. Generating the SBOM is not
the same as publishing it — attach it to a GitHub Release as an artifact only
after owner review of its content, exactly as any other release artifact
requires the Owner Approval Gate. SBOM tooling itself is not a runtime
dependency of the package.

## Security response

Security advisories take priority over the normal update cadence. Dependency
findings must be assessed for reachability in this local stdio, GET-only
architecture; severity alone does not establish exploitability. Report
vulnerabilities through [SECURITY.md](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md), not a public issue.
