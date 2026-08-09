# Contributing

Thank you for helping improve `pfsense-mcp-server`. This project prioritizes
security, explicit capability boundaries, and reviewable changes over feature
velocity. Read this document before opening an issue or pull request — most
of it exists because a specific mistake is easy to make otherwise.

## Before you begin

- Read [AGENTS.md](AGENTS.md), [the architecture diagrams](docs/ARCHITECTURE_DIAGRAMS.md),
  and [the security model](docs/SECURITY_MODEL.md). See "Where to find things"
  below for the rest of the documentation map.
- Search existing issues and discussions before proposing substantial work —
  a design conversation is much cheaper before code exists than after.
- Open an issue for public design discussion unless the subject is a security
  vulnerability. Report vulnerabilities privately through [SECURITY.md](SECURITY.md) —
  never in a public issue or pull request.
- Do not include credentials, real appliance details, raw responses, or
  unsanitized logs in an issue, pull request, fixture, or test. Use the
  synthetic placeholders already established throughout this repository
  (`.invalid` hostnames, RFC 5737 documentation addresses) as the pattern to
  follow.

## Local setup

Linux is the supported production platform (secure credential loading
depends on descriptor-bound Unix file semantics); development on macOS or
WSL2 works for everything except the parts of the test suite that assert
Linux-specific filesystem behavior. Python 3.11 or newer is required.

```console
git clone https://github.com/night4me/pfsense-mcp-server.git
cd pfsense-mcp-server
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

The public test suite is fully offline. It uses `MockTransport` and approved,
sanitized fixtures; no pfSense appliance or credential is required to develop,
test, or review a change.

If you are working on documentation (`docs/*.md`, `mkdocs.yml`), also install
the docs extra: `.venv/bin/python -m pip install -e ".[docs]"`. See
"Documentation" under Verification below.

## Development workflow

1. Create a branch (or a fork, if you don't have write access) from `main`
   for your change. Keep branch names descriptive; there is no enforced
   naming convention.
2. Keep the change focused and preserve the capability-gated architecture —
   one logical change per pull request is much easier to review than several
   bundled together.
3. Do not add or activate a capability, MCP tool, or WRITE endpoint without
   explicit project approval. The v0.3.0 Tier 1 safety framework in
   particular is phase-gated by design (see
   [`docs/tier1/IMPLEMENTATION_ROADMAP.md`](docs/tier1/IMPLEMENTATION_ROADMAP.md));
   do not implement a phase or lift a gate on your own initiative.
4. Add tests for behavior and negative security properties, not just the
   happy path.
5. Update public documentation when behavior or configuration changes —
   `README.md`, `docs/API.md`, and the relevant `docs/*.md` file are usually
   the ones that matter; see "Where to find things" below.
6. Never weaken GET-only enforcement, credential non-disclosure, fixture
   safety, or WRITE-inactivity checks. If a change appears to require
   weakening one of these, stop and open an issue for discussion first —
   this is very likely a sign the approach needs to change, not the check.

For new fixture work, use the proposal/audit workflow documented in the
Makefile (`make capture-fixture`, `make audit-fixture`, `make approve-fixture`).
Never commit a direct capture from a real appliance.

## Testing workflow

Run the fast feedback loop while developing:

```console
make quick
```

This runs formatting, linting, type checking, the full offline test suite,
and the project's own architecture/security invariant checks (GET-only
enforcement, WRITE-inactivity, a repository-wide secret scan, and static
security analysis) in a few seconds.

Before requesting review, run the authoritative local gate — this is what CI
also runs, plus a few checks that are slow enough to skip in the fast loop:

```console
make validate
```

To run a single test file or a subset while iterating:

```console
.venv/bin/python -m pytest tests/test_config.py -q
.venv/bin/python -m pytest -k "fingerprint" -q
```

For packaging, coverage, or security-sensitive changes, also run the
relevant targets:

```console
make coverage
make security-static
make package-check
```

`lab/` (the disposable-lab harness for Tier 1 fault-scenario testing) is
intentionally excluded from `make quick`/`make validate`'s default pytest
run; its own offline test suite runs separately with `pytest lab/`.

Live private-infrastructure acceptance is maintainer-only, requires separate
approval, and is never a contributor or public CI requirement. See the
[release checklist](docs/RELEASE_CHECKLIST.md).

## Commit expectations

Use clear, focused commit messages in the imperative mood — "add X",
"fix Y", "refactor Z" rather than "added"/"fixed"/"adding". A short subject
line plus a body explaining *why* (not just what changed, which the diff
already shows) is more useful to a future reader than a long subject line
alone. Maintainers may squash or reword commits during review.

Avoid bundling unrelated changes (a formatting pass and a behavior change,
for example) into one commit — split them so each commit tells one story.

## Pull requests

Use the pull request template — it prompts for the information reviewers
actually need: compatibility/security impact, what verification was run,
and whether tests/documentation were updated. A good pull request:

- explains the problem and the chosen scope;
- identifies compatibility and security impact;
- lists verification actually run (not just "make quick" — the actual output
  or a summary of it, if anything failed and was fixed along the way);
- keeps unrelated formatting/refactoring out of the diff;
- includes no generated caches, reports containing private data, or build
  artifacts (`dist/`, `site/`, `.coverage`, `coverage.xml`, and similar are
  already `.gitignore`d — if your diff includes one of these, something
  went wrong).

CI runs automatically on every pull request: the full test matrix
(Python 3.11–3.13), branch coverage, package build/install verification,
static security analysis (bandit), documentation site build, CodeQL
analysis, and (for pull requests specifically) a dependency review checking
any newly introduced dependency for known vulnerabilities and license
compatibility. A red CI check on your pull request almost always needs to
be fixed before review can proceed — if you believe a failure is unrelated
to your change, say so explicitly in the pull request rather than leaving
it unaddressed.

## Troubleshooting

**`pip install -e ".[dev]"` fails or pulls unexpected versions.** Confirm
you activated a fresh virtual environment (`python -m venv .venv`) rather
than installing into a system or previously-populated environment — stale
or conflicting packages from an unrelated project are the most common cause.

**`make quick` fails on formatting/lint but the code looks fine.** Run
`.venv/bin/python -m ruff format .` to auto-fix formatting, then
`.venv/bin/python -m ruff check .` to see any remaining lint findings —
most are auto-fixable with `--fix`.

**mypy reports errors in files you didn't touch.** mypy's `files` scope in
`pyproject.toml` covers `src/pfsense_mcp`, `scripts`, and `lab` — run
`.venv/bin/python -m mypy src/pfsense_mcp scripts lab` directly to see the
full output outside the terser `make quick` summary. A stale
`.mypy_cache/` occasionally causes confusing results; deleting it and
re-running is a safe first troubleshooting step.

**A test fails only in CI, not locally.** Confirm your Python version
matches one of the CI matrix versions (3.11, 3.12, 3.13) and that you ran
`make validate`, not just `make quick` — a few checks (JUnit-based endpoint/
profile/GET-only verification, the public MCP contract snapshot, fixture
safety, documentation consistency) only run in the slower target.

**`make docs-build` fails with a broken-anchor or missing-link error.**
This means a Markdown heading was renamed, or a file was moved, without
updating every cross-reference to it — `scripts/validate_docs.py` (part of
`make validate`) and `mkdocs build --strict` (part of `make docs-build`)
both check this. Search the repository for the old heading text or file
path and update every reference; don't just silence the specific failing
line.

**bandit flags something in new code.** Read the finding rather than
adding a blanket suppression — this project has, more than once, found that
a bandit warning pointed at a real correctness issue (not just a style
preference), and fixed the underlying code rather than the symptom. If a
finding is genuinely a false positive for a specific, well-understood
reason, an existing narrow `[tool.bandit]` skip pattern in `pyproject.toml`
shows the expected style: scoped to the exact file/check, with a comment
explaining why.

**`make quick`/`make validate` fails with "git identity leak check".**
`scripts/git_identity_check.py` checks your configured `git config
user.name`/`user.email` and the most recent commits reachable from `HEAD`
against a small blocklist of known-leaked identity values (stored as
salted-free SHA-256 hashes, never plaintext, in the script itself). This
exists because a real personal email briefly reappeared in this
repository's history after an earlier remediation, undetected by any
other check, because nothing inspected commit *metadata* specifically.
If this fires on your own commit, it means your local `git config
user.name`/`user.email` matches one of those known-leaked values —
correct your local Git identity before committing; this is not a check
on your identity in general, only on the specific values already known
to have leaked from this project once.

## Where to find things

- [`README.md`](README.md) — project overview, installation, configuration,
  quick start, troubleshooting the *running* server (as opposed to the
  *development* troubleshooting above).
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) and
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what this project
  guarantees, what it explicitly does not, and why.
- [`docs/API.md`](docs/API.md) — the full MCP tool reference.
- [`docs/adr/`](docs/adr/README.md) — Architecture Decision Records; read the
  relevant one before proposing a change to something it governs.
- [`docs/tier1/`](docs/tier1/README.md) — the v0.3.0 Tier 1 safety framework's
  architecture, implementation roadmap, and subsystem specifications.
- A browsable version of most of `docs/` is also built (not yet publicly
  deployed) via `make docs-serve` for local preview.

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Code style

- Prefer typed, explicit code over reflection or implicit registration.
- Keep MCP tool functions thin and preserve precise public signatures.
- Translate upstream shape failures into sanitized typed exceptions.
- Never log arguments, response bodies, exception messages, or credentials.
- Follow Ruff formatting/lint and mypy configuration in `pyproject.toml`.
