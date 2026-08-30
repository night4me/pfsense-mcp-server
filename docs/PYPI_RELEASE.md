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
- Confirm the accepted READ-tool count against the live registry
  (`KNOWN_READ_TOOL_NAMES` / `make validate`'s `public_contract` check —
  95 as of this candidate), zero WRITE tools, an empty WRITE allow-list,
  and no capability or endpoint expansion unless separately approved.

## Terminology (precise, not interchangeable)

Adopted 2026-08-30 after the v1.1.0 publication ceremony found this
project's own claims had been imprecise about what its checks actually
proved:

- **Deterministic build**: the same source, built the same way, always
  produces the same output *within a single fixed environment*. Does not
  by itself say anything about a different environment.
- **Same-environment reproducible build**: two builds run back-to-back in
  the same environment (same machine, same already-installed tool
  versions) produce byte-identical artifacts. This is what `make
  reproducible-build` alone proves.
- **Cross-environment reproducible build**: a build in one environment
  (e.g. a local machine) produces byte-identical artifacts to a build of
  the same source in a *different* environment (e.g. the GitHub Actions
  runner). This project achieves this by pinning `SOURCE_DATE_EPOCH` to
  the exact commit timestamp and hatchling's build-dependency closure to
  exact versions (`scripts/build-constraints.txt`), verified end to end by
  the release build rehearsal workflow.
- **Source provenance**: cryptographic proof (Sigstore, via PyPI's Trusted
  Publishing attestations) that a published artifact was built by a
  specific, named CI workflow from a specific, named commit. Says nothing
  about whether that artifact's *bytes* match anything built anywhere
  else -- only that its origin is what it claims to be.
- **Artifact provenance**: the specific published file's own recorded
  digest, attested alongside source provenance. Ties a hash to an origin,
  not to any other build.
- **Content equivalence**: two archives (e.g. a local build and a
  published one) contain byte-identical *extracted* files, even if the
  outer archive container bytes (and therefore the outer SHA-256) differ.
  Established by extracting both and diffing recursively -- not by
  comparing archive hashes.
- **Exact byte identity**: two archives are identical at the SHA-256
  level, including the outer container. The strongest, most specific
  claim; everything above it is necessary but not sufficient to establish
  it on its own.

The v1.1.0 published artifacts had content equivalence and valid source
provenance, but not exact byte identity with the RC hashes an earlier local
build had produced -- because that local build skipped the cross-
environment reproducibility steps documented below. The hardening in this
document exists to make exact byte identity the normal, verified outcome
for every release from v1.1.0 onward, not merely an occasional coincidence.

## Clean build

Start from the repository root with an isolated release environment.
`scripts/build_release_artifact.py` is the **one canonical build path** --
used identically here, by `make package-check`, by `make
reproducible-build`, by the safe `release-rehearsal.yml` dry-run workflow,
and by the real `.github/workflows/publish.yml`. Never invoke `python -m
build` directly for a release artifact; every direct invocation is a
distinct, unverified build path that can silently diverge from what the
other three actually produce (this is exactly what happened during the
v1.1.0 publication ceremony, 2026-08-30 -- see
`reports-ai/POST_V1_1_RELEASE_REPRODUCIBILITY_HARDENING.md`).

```console
git status --short
python -m venv .release-venv
.release-venv/bin/python -m pip install --upgrade pip
.release-venv/bin/python -m pip install 'build>=1.2,<2.0' 'twine>=5.0,<7.0'
.release-venv/bin/python scripts/build_release_artifact.py --outdir dist
```

The Git status output must be empty. The script itself refuses to build if
`dist/` already exists, derives `SOURCE_DATE_EPOCH` from the exact commit
checked out at `HEAD` (never from wall-clock "now"), and pins `hatchling`'s
own build-dependency closure to exact versions via
`scripts/build-constraints.txt` -- removing both sources of nondeterminism
found during the v1.1.0 incident. `.release-venv/` and `dist/` are local,
ignored build state and must never be committed.

## Release build rehearsal (verify against the real build environment)

Before asking for owner approval, trigger a real GitHub Actions build of
the exact reviewed commit -- not merely a local approximation of one --
using the safe, non-publishing `release-rehearsal.yml` workflow:

```console
gh workflow run release-rehearsal.yml --ref main -f ref=<exact RC SHA or tag>
```

It checks out that exact ref, builds via the identical
`scripts/build_release_artifact.py` path, and prints the resulting
wheel/sdist SHA-256 hashes to the run's job summary -- the *actual* bytes a
real `publish.yml` run from the same ref would produce, since both use the
same canonical build path, the same pinned build-dependency closure, and
the same `SOURCE_DATE_EPOCH` derivation. This workflow carries no
publication capability whatsoever (no `id-token: write`, no `pypi`
environment, no publish step) -- it cannot upload anything under any input.
Compare its reported hashes against the locally-built ones from the
previous section; they must match exactly. Report *these* hashes -- not
merely a local build's -- in the owner approval request below.

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

This target uses the same canonical `scripts/build_release_artifact.py`
path, builds twice in temporary directories, compares artifact names and
SHA-256 values, and removes its temporary files. It never uploads an
artifact. A passing result proves this build path is internally
deterministic in the current environment -- it is not, by itself, proof
that a *different* environment (the actual GitHub Actions runner) will
produce the same bytes; that is what the release build rehearsal above is
for.

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
checks (via the same canonical build path).

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
artifact verification and hashes -- **from the release build rehearsal
workflow run against that exact commit, not only from a local build** (see
above) -- Trusted Publisher identity, `pypi` environment, exact
enable-variable value, final MCP tool counts, and WRITE inactivity.

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
  -f tag=v0.4.0 \
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
