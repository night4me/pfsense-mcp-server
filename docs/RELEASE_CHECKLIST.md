# Release checklist

This checklist separates public reproducible verification from private
appliance acceptance. A public CI result never substitutes for live
acceptance, and live access is never required to contribute.

## Public CI

- Clean editable install on Python 3.11, 3.12, and 3.13.
- Ruff formatting and lint checks.
- mypy static type checking.
- Complete offline pytest suite with live tests confirmed skipped.
- `make quick` architecture checks.
- Branch-coverage report, with no arbitrary threshold.
- Build and inspect the sdist and wheel.
- Install the wheel in a clean environment and verify its entry point
  fails closed when configuration is absent.
- Bandit Python security scan.
- CodeQL Python analysis.
- No credentials, private infrastructure, or live network calls.

## Local offline release gates

- Run `make quick` and `make validate`.
- Run `make coverage`, review uncovered security-relevant branches, and
  record genuine gaps.
- Run `make security-static` and classify every finding.
- Run `make package-check` and inspect the artifact member report.
- Run fixture safety and repository security scans.
- Confirm GET-only enforcement, empty WRITE allow-list, inactive WRITE
  capabilities, and zero registered WRITE tools.
- Review `git diff --check`, the complete diff, and the changed-file
  manifest.

## Private-infrastructure acceptance

These checks are local-only and require separate approval. They never run
in public CI.

- Inspect configured credential paths with metadata-only operations.
- Run only the approved live-safe READ suite.
- Confirm the pfSense REST API reports `read_only=true`.
- Enumerate MCP schemas and confirm the accepted READ-tool count, zero
  WRITE tools, and absence of prohibited credential properties.
- Confirm no mutating request occurred.

Never capture, print, upload, or commit production credentials, request
headers, appliance responses, or identifying infrastructure details.

## Publication

- Follow the detailed [PyPI release procedure](PYPI_RELEASE.md) for clean
  builds, artifact inspection, trusted publishing, TestPyPI, and rollback.
- Obtain explicit approval before commit, tag, push, or release creation.
- Commit the accepted changes and create an annotated version tag.
- Push the commit and tag without force.
- Publish and verify the GitHub Release.
- Record commit SHA, tag, release URL, verification evidence, and WRITE
  inactivity in the final handoff report.
