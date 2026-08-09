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

Before tagging, also require two isolated builds from the same commit to be
byte-identical:

```console
make reproducible-build
```

This target derives `SOURCE_DATE_EPOCH` from `HEAD`, builds twice in temporary
directories, compares artifact names and SHA-256 values, and removes its
temporary files. It never uploads an artifact.

`make artifact-manifest` emits the version, source commit, source-date epoch,
Python requirement, filenames, sizes, and SHA-256 values for the local wheel
and sdist. Save that output in the external release record after final approval;
the command contains no host-specific paths or credentials.

Inspect wheel and sdist member names without extracting them. Confirm the
artifacts contain the package, entry point, README metadata, and license, and
exclude reports, `.env` files, key/private-key files, caches, fixtures, local
configuration, and temporary state. Install the wheel in a second clean virtual
environment, import `pfsense_mcp.server`, and verify the console entry point
fails closed without configuration; `make package-check` automates these
checks.

## Trusted publishing

`.github/workflows/publish.yml` uses GitHub Actions OIDC trusted publishing;
there is no PyPI API token or repository secret. A build job checks out the
release tag, proves that it matches the `pyproject.toml` version, builds and
verifies the wheel/sdist, and passes only those artifacts to the publish job.
Only the publish job receives `id-token: write`; all other permissions are
read-only. The pinned publishing action is configured to create PEP 740
attestations for the uploaded distributions; disabling attestations requires a
separate reviewed workflow change.

Publishing is disabled by default. Before the first upload, the owner must
configure all of the following externally:

1. In PyPI, create the `pfsense-mcp-server` project or a pending Trusted
   Publisher with owner `night4me`, repository `pfsense-mcp-server`, workflow
   filename `publish.yml`, and environment `pypi`.
2. In GitHub, create the `pypi` environment. It is mandatory because its exact
   name is part of the PyPI Trusted Publisher identity. Do not add a PyPI
   secret. Environment Required Reviewers are not available for this private
   repository under the current plan and are not the release approval control.
3. Only after PyPI and GitHub configuration is reviewed, create repository
   variable `PYPI_TRUSTED_PUBLISHING_ENABLED` with exact value `true`.

Until that variable exists, both release and manual workflow invocations skip
the build/publish chain. This prevents a published GitHub Release from
attempting PyPI access before the external trust relationship is ready.
Concurrent attempts for the same tag are serialized and never cancel an
in-progress publication.

Do not store a PyPI token in repository files, GitHub secrets, client
configuration, logs, or AI reports. Trusted Publisher, environment protection,
and the enabling repository variable remain explicit owner-controlled settings.

## Owner Approval Gate

The permanent human release gate is immediately before creation of the
immutable version tag. Before reaching it, complete the full preflight and
report the exact commit SHA, exact-SHA CI and CodeQL status, release-check,
artifact verification and hashes, Trusted Publisher identity, `pypi`
environment, exact enable-variable value, final MCP tool counts, and WRITE
inactivity.

Ask exactly: "Approve creation of immutable tag vX.Y.Z and production
release?" Do not create or move the tag, push it, create the GitHub Release, or
permit the publish workflow to execute without that explicit approval. The
approval authorizes only the stated version on the reported SHA. Immediately
after approval, fetch again and prove that local HEAD and `origin/main` still
equal that SHA; any drift stops the release and requires a new preflight and
approval.

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

After the commit, tag, trusted-publisher settings, and explicit publication
approval are complete, publish the GitHub Release. Its `published` event starts
the OIDC workflow. A manual dispatch is a recovery mechanism and requires an
existing tag name; it rebuilds from that tag and refuses a tag/version mismatch.

```console
gh workflow run publish.yml --ref main \
  -f tag=v0.3.0 \
  -f confirm=publish-pfsense-mcp-server
```

Do not dispatch manually when the release event is already running. The
exact confirmation phrase prevents an accidental manual click from starting
the build chain. The publish job must retain the `pypi` environment identity.
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
