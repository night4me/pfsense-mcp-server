# Contributing

Thank you for helping improve `pfsense-mcp-server`. This project prioritizes
security, explicit capability boundaries, and reviewable changes over feature
velocity.

## Before you begin

- Read [AGENTS.md](AGENTS.md), [the architecture overview](README.md#architecture),
  and [the security model](docs/SECURITY_MODEL.md).
- Search existing issues and discussions before proposing substantial work.
- Open an issue for public design discussion unless the subject is a security
  vulnerability. Report vulnerabilities privately through [SECURITY.md](SECURITY.md).
- Do not include credentials, real appliance details, raw responses, or
  unsanitized logs in an issue, pull request, fixture, or test.

## Development setup

Python 3.11 or newer is supported.

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

The public test suite is fully offline. It uses `MockTransport` and approved,
sanitized fixtures; no pfSense appliance or credential is required.

## Making a change

1. Keep the change focused and preserve the capability-gated architecture.
2. Do not add or activate a capability, MCP tool, or WRITE endpoint without
   explicit project approval.
3. Add tests for behavior and negative security properties.
4. Update public documentation when behavior or configuration changes.
5. Never weaken GET-only enforcement, credential non-disclosure, fixture
   safety, or WRITE-inactivity checks.

For new fixture work, use the proposal/audit workflow documented in the
Makefile. Never commit a direct capture from a real appliance.

## Verification

Run the fast feedback loop while developing:

```console
make quick
```

Before requesting review, run the authoritative local gate:

```console
make validate
```

For packaging, coverage, or security-sensitive changes, also run the relevant
targets:

```console
make coverage
make security-static
make package-check
```

Live private-infrastructure acceptance is maintainer-only, requires separate
approval, and is never a contributor or public CI requirement. See the
[release checklist](docs/RELEASE_CHECKLIST.md).

## Pull requests

A good pull request:

- explains the problem and the chosen scope;
- identifies compatibility and security impact;
- lists verification actually run;
- keeps unrelated formatting/refactoring out of the diff;
- includes no generated caches, reports containing private data, or build
  artifacts.

Use clear commit messages in the imperative mood. Maintainers may squash or
reword commits during review.

## Code style

- Prefer typed, explicit code over reflection or implicit registration.
- Keep MCP tool functions thin and preserve precise public signatures.
- Translate upstream shape failures into sanitized typed exceptions.
- Never log arguments, response bodies, exception messages, or credentials.
- Follow Ruff formatting/lint and mypy configuration in `pyproject.toml`.

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
