# PyPI release procedure

This procedure prepares and publishes an authenticated Python distribution. It
does not replace the broader [release checklist](RELEASE_CHECKLIST.md), private
READ acceptance, Git tag, or GitHub Release process. Publication always
requires explicit owner approval.

## Versioning and prerequisites

- Follow Semantic Versioning. The version in `pyproject.toml`, changelog, tag,
  acceptance document, and release notes must agree.
- Never reuse a version already uploaded to PyPI or TestPyPI.
- Build from a clean, reviewed commit on the intended release branch.
- Require Python 3.11–3.13 CI, CodeQL, and all local offline gates to pass.
- Confirm the MIT `LICENSE` and `License-Expression: MIT` package metadata.
- Confirm 41 READ tools, zero WRITE tools, an empty WRITE allow-list, and no
  capability or endpoint expansion unless separately approved.

## Clean build

Start from the repository root with an isolated release environment. The
commands deliberately stop if `dist/` already exists so stale artifacts cannot
be uploaded accidentally.

```console
git status --short
test ! -e dist
python -m venv .release-venv
.release-venv/bin/python -m pip install --upgrade pip
.release-venv/bin/python -m pip install 'build>=1.2,<2.0' 'twine>=5.0,<7.0'
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  .release-venv/bin/python -m build --sdist --wheel
```

The Git status output must be empty. `.release-venv/` and `dist/` are local,
ignored build state and must never be committed.

## Artifact inspection

```console
.release-venv/bin/python scripts/verify_distribution.py dist
.release-venv/bin/python -m twine check --strict dist/*
sha256sum dist/*
```

Inspect wheel and sdist member names without extracting them. Confirm the
artifacts contain the package, entry point, README metadata, and license, and
exclude reports, `.env` files, key/private-key files, caches, fixtures, local
configuration, and temporary state. Install the wheel in a second clean virtual
environment, import `pfsense_mcp.server`, and verify the console entry point
fails closed without configuration; `make package-check` automates these
checks.

## Trusted publishing

PyPI trusted publishing with GitHub Actions OIDC is preferred over long-lived
API tokens. The owner must configure the exact PyPI project, repository,
workflow filename, and protected GitHub environment. The future publish job
should have `id-token: write` and otherwise minimal permissions, consume only
artifacts produced from the approved tag, and require environment approval.

Do not store a PyPI token in repository files, client configuration, logs, or
AI reports. Do not create a trusted publisher, environment, account, token, or
workflow until the owner approves those external settings.

## TestPyPI rehearsal

TestPyPI is optional and uses a separate project/account configuration. After
owner approval and authentication are in place:

```console
.release-venv/bin/python -m twine upload --repository testpypi dist/*
```

Verify the rendered project page and metadata, then install the exact version
from TestPyPI into a new environment. Dependency resolution may require the
normal PyPI index; do not weaken dependency verification merely to make the
rehearsal pass. TestPyPI does not authorize production publication.

## Production PyPI publication

After the commit, tag, GitHub Release, trusted-publisher settings, and explicit
publication approval are complete, publish the already inspected artifacts.
Prefer the approved OIDC workflow. If an owner explicitly authorizes a manual
upload instead, use Twine's interactive/secure credential mechanism without
placing credentials on the command line:

```console
.release-venv/bin/python -m twine upload dist/*
```

Verify the PyPI project page, hashes, metadata, and installation of the exact
version in a clean environment. Record only public artifact URLs and hashes in
the release report.

## Failure and rollback

PyPI releases are immutable: an uploaded file or version cannot be replaced.
If the wrong or unsafe artifact is published, stop further publication, yank
the affected version, publish a security notice when appropriate, fix the
problem in a new patch version, and preserve evidence without exposing secrets.
Deleting a release is not a normal rollback and does not make the version safe
to reuse. A Git tag or GitHub Release must not be moved to conceal a bad upload.

## Required final record

Record the commit SHA, tag, artifact SHA-256 values, PyPI URL, verification
results, compatibility impact, security changes, and confirmation that WRITE
remained inactive. Never record credentials, private paths, or appliance data.
