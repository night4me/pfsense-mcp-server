# Acceptance — v0.2.2

## Release scope

v0.2.2 is a project, packaging, documentation, and defense-in-depth hardening
release built on the accepted v0.2.1 security baseline. It preserves all 41
READ tools and their public contracts. It adds no MCP tool, endpoint,
capability, network transport, or Tier 1 mutation implementation.

## Accepted changes

- Public CI covers Python 3.11, 3.12, and 3.13, branch coverage, package
  construction/installation, Bandit, and offline architecture gates.
- CodeQL performs full Python analysis in private-repository analysis-only mode.
  `upload: never` avoids unavailable GitHub Code Scanning ingestion; workflow
  permissions are limited to read access for Actions, contents, and packages.
- Every READ tool carries the same non-authoritative MCP ToolAnnotations policy:
  `readOnlyHint=true`, `openWorldHint=true`, with destructive/idempotent hints
  omitted.
- `PFSENSE_ALLOWED_TOOLS` provides a fail-closed exact-name intersection after
  capability authorization and can only remove tools.
- API-key metadata validation and bounded reading use one non-following opened
  descriptor on supported Linux systems, eliminating pathname replacement
  between check and use.
- Response-envelope validation uses small typed private helpers while preserving
  endpoints, models, errors, parameters, and public behavior.
- Repeated logging setup replaces and closes only owned handlers; application
  cleanup covers failed bootstrap and preserves unrelated loggers.
- MIT licensing, first-user/client documentation, dependency policy, release
  procedures, API parity, and security abuse-case documentation are complete.
- Certificate fixtures use valid wholly synthetic X.509 material with only
  `.invalid` identities. No private key is committed.
- A deterministic public-contract snapshot binds every tool schema,
  description, annotation, capability, client method, and verified GET
  endpoint; `make validate` fails on drift.
- The Auditor profile uses the accepted supported-build READ set as its single
  activation source. Engineer remains empty.
- Offline release gates verify documentation examples/links, reproducible
  artifacts, artifact hashes/metadata, strict package metadata, and clean-tree
  release-state parity.
- Future Tier 1 has a separate formal Recovery Contract and fault-model
  specification; no runtime Tier 1 code is activated.

## CI evidence

GitHub Actions completed successfully on release-candidate baseline commit
`7da9ceced763d2c9ebb3a021824af98a1e5d6dc1`:

- [CI run 31174929355](https://github.com/night4me/pfsense-mcp-server/actions/runs/31174929355):
  Python 3.11/3.12/3.13, package, coverage, and Bandit jobs passed.
- [CodeQL run 31174929356](https://github.com/night4me/pfsense-mcp-server/actions/runs/31174929356):
  Python analysis completed successfully without Code Scanning upload.

The final release-state documentation commit must receive the same successful
CI and CodeQL results before tagging.

## Package verification

- Version metadata: `0.2.2`; Python 3.11+; supported production platform Linux;
  MIT `License-Expression`; Markdown README; typed-package marker.
- Hatchling builds one wheel and one sdist with the expected console entry point.
- Distribution verification requires the license, README, PyPI procedure,
  v0.2.2 acceptance document, package source, metadata, and entry point.
- Clean wheel installation/import and configuration-absent fail-closed startup
  pass through `make package-check`.
- Strict Twine checks pass for both artifact types.
- Artifacts exclude credentials, key/private-key files, `.env`, AI reports,
  local configuration, caches, fixtures, and temporary state.

## Security invariants

- Credential values and prohibited credential fields remain absent from MCP
  schemas, outputs, logs, errors, fixtures, documentation, and distributions.
- Production READ transport remains GET-only and independently endpoint-gated.
- Redirects and every other non-2xx response fail closed; transport exception
  details and upstream bodies remain sanitized.
- Capability profiles remain authoritative; annotations and tool restrictions
  cannot grant access.
- The Auditor profile contains 34 READ capabilities and registers exactly 41
  READ tools without restriction. Engineer contains zero capabilities.
- The WRITE endpoint allow-list is empty, all WRITE capabilities are inactive,
  no WRITE module enters production bootstrap, and zero WRITE tools register.
- Tier 0 WRITE infrastructure remains inert. Tier 1 is planning-only and blocked.
- Public CI uses no production configuration, credential, or live pfSense call.

## Verification evidence

- Full offline pytest, branch coverage, Ruff, mypy, `make quick`,
  `make validate`, `make package-check`, and `make release-check` pass on the
  release-state tree.
- Bandit, fixture safety, repository security, GET-only, WRITE import-absence,
  empty WRITE allow-list, and WRITE-capability inactivity checks pass.
- Fresh offline MCP enumeration confirms 41 READ tools, zero Engineer/WRITE
  tools, annotation parity, and zero prohibited credential schema properties.
- No live pfSense call, production credential access, or mutation was performed
  while preparing this release state.

## Compatibility

Public MCP tool names, inputs, outputs, schemas, endpoint set, capability set,
and semantics are unchanged from v0.2.1. Unsafe API-key file configurations may
fail earlier under descriptor-bound validation. Encoded/Unicode control
characters and non-2xx redirects now fail closed. Logging lifecycle cleanup is
an internal reliability correction.

## Known limitations

- The supported trust boundary is a local stdio MCP process controlled by a
  trusted launcher; there is no network MCP transport or per-message caller
  authentication.
- Linux is the supported production platform for descriptor-bound credential
  loading. Unsupported platforms fail closed rather than weakening guarantees.
- CodeQL SARIF is not uploaded to GitHub Code Scanning or retained in the
  Security tab because that backend is unavailable for this private repository.
- PyPI publication and Trusted Publisher configuration are separate external
  operations and are not completed by this acceptance document.
- Private live-safe READ acceptance was not repeated for this documentation
  commit. v0.2.1 remains the latest recorded live appliance baseline.
- Historical public certificate material remains in Git history; it contained
  no private key or secret and history was not rewritten.
- Tier 0 recovery infrastructure is incomplete and unsafe for mutation; Tier 1
  remains blocked pending all roadmap and owner-approval gates.

## Acceptance boundary

This document accepts the v0.2.2 release state after its exact commit passes
the required local and remote gates. It does not authorize a tag, push, GitHub
Release, TestPyPI/PyPI upload, live pfSense access, credential use, WRITE
activation, or mutation. Each external operation requires separate approval.
