# PyPI readiness report

Reviewed: 2026-08-06  
Package version: 0.2.2  
Upload performed: no

## Readiness decision

The package is technically buildable and both artifacts pass Twine metadata
and long-description validation. It should **not be uploaded to PyPI yet**
because the repository owner has not selected or documented a software
license. Publishing without a clear license would leave users without granted
reuse rights and would conflict with the project's intended open-source first
impression.

No license was guessed during this review. The owner should choose a license
(for example, a permissive or copyleft OSI-approved license), add the root
license file, and then add the corresponding PEP 639 metadata and classifier.

## Metadata review

### Complete

- normalized project name: `pfsense-mcp-server`;
- version prepared as `0.2.2`;
- concise package description;
- Markdown long description from `README.md`;
- Python requirement `>=3.11`;
- Python 3.11, 3.12, and 3.13 classifiers;
- development status, console environment, system-administrator audience,
  firewall topic, and typed-package classifiers;
- keywords for MCP, pfSense, networking, firewall, and observability;
- homepage, repository, issue tracker, changelog, and security-policy URLs;
- `pfsense-mcp-server` console entry point;
- PEP 561 `py.typed` marker included and verified in the wheel;
- Hatchling build backend with explicit wheel package and minimal sdist
  inclusion policy.

### Intentionally unresolved

- **License:** blocking owner decision; no license file or license metadata.
- **Author/maintainer metadata:** optional and omitted rather than inferring a
  legal name or email from workstation/repository identifiers. The owner may
  add the identity they want published publicly.
- **PyPI project ownership/name reservation:** not tested because no upload or
  account-authenticated operation was authorized.

## Dependency review

Runtime dependencies are focused and bounded by next-major versions:

- `mcp>=1.0.0,<2.0.0`;
- `httpx>=0.27,<1.0`;
- `pydantic>=2.0,<3.0`.

These match the server, transport, and model architecture. There are no
production-only extras or direct credential-management packages.

The `dev` extra contains test, lint, type, build, coverage, static-security,
and Twine tooling. Twine was added to make the documented readiness check
reproducible. Development dependencies are bounded by major version but not
locked; CI intentionally tests current compatible releases. A lockfile is not
required for library consumers, though a future constraints file could improve
CI reproducibility.

## Build configuration

- Backend: Hatchling.
- Wheel contents: only `src/pfsense_mcp` and distribution metadata.
- Sdist contents: `src`, core community/security documentation, README, and
  `pyproject.toml`.
- Excluded from the sdist by explicit inclusion: Git internals, GitHub
  workflows, tests, local reports, caches, build output, private paths, and
  fixture/proposal state.
- The repository distribution verifier rejects traversal, absolute paths,
  symlinks, unsafe tar members, credential/private/generated filenames,
  incomplete metadata, and missing console-entry-point metadata.

## Artifact results

### Wheel

- File: `pfsense_mcp_server-0.2.2-py3-none-any.whl`
- Size: 91,645 bytes
- Members: 115
- SHA-256: `5d7f31887aa5c323dd2d6597f0280f06657c4215754aa943f4bec586ccf18f7a`
- Distribution verifier: passed
- Clean-environment install: passed
- Installed import: passed
- Entry point without configuration: failed closed as expected, without a
  traceback
- `twine check`: passed

### Source distribution

- File: `pfsense_mcp_server-0.2.2.tar.gz`
- Size: 49,248 bytes
- Members: 119
- SHA-256: `8a1e2e93cbd79f4ff4f46677a2ab294e6706558f44194d7816fc7dcf5d3f8af7`
- Distribution verifier: passed
- Explicit private/generated-path scan: passed
- `twine check`: passed

Artifact hashes are local verification evidence and will change if any source
or documentation is changed before release.

## Commands executed

```console
.venv/bin/python -m pytest -q tests/test_verify_distribution.py
make package-check
.venv/bin/python -m twine check dist/*
```

Results: 11 targeted tests passed; build, archive inspection, clean wheel
installation, fail-closed entry point, and Twine checks all passed.

## Required next steps before upload

1. Owner selects and approves a license.
2. Add the license file and matching `pyproject.toml` metadata/classifier.
3. Rebuild artifacts from a clean tree.
4. Re-run full verification, artifact inspection, and `twine check`.
5. Review rendered metadata on TestPyPI if a separate upload is explicitly
   authorized.
6. Obtain explicit approval before any real PyPI upload.
