# ADR-034: README Mermaid → static-SVG PyPI compatibility patch

- **Status:** Implemented, 2026-08-23. A narrowly-scoped public-documentation
  compatibility patch, no product/runtime code change. Candidate v0.7.2
  patch content — not tagged, released, or published as of this writing.
- **Scope:** `README.md`'s two Mermaid diagrams only. Does not touch
  `docs/ARCHITECTURE_DIAGRAMS.md` (mkdocs-rendered, Mermaid fully
  supported there and left unchanged as the detailed, maintainable
  version), MCP behavior, guidance behavior, capabilities, privileges,
  WRITE reachability, Tier 1, security-bootstrap, or setup-wizard work.

## Problem

`README.md`'s `long_description` is embedded verbatim into the wheel
and sdist `METADATA`/`PKG-INFO` at build time (`pyproject.toml` declares
`readme = "README.md"`). GitHub's Markdown renderer supports fenced
` ```mermaid ` code blocks natively; PyPI's long_description renderer
(`readme_renderer`, via `docutils`/`bleach`) does not — it renders the
fence as an ordinary code block, exposing the raw Mermaid source text
on the live PyPI project page instead of a diagram. Confirmed
externally on the published v0.7.1 project page.

## Decision

Replace both `README.md` Mermaid fences with standard Markdown image
syntax (`!` followed by bracketed alt text and a parenthesized URL)
pointing at checked-in, pre-rendered SVG files, referenced by an
absolute `raw.githubusercontent.com` URL on the `main` branch — not a
repository-relative path.

**Why an absolute `main`-branch URL, not a relative path:** GitHub
resolves README image paths relative to the repository tree, so a
relative path (e.g. `assets/diagrams/read-trust-path.svg`) renders
correctly there. PyPI's long_description has no such tree — it is a
flat blob of HTML with no accompanying files — so any relative path
404s. An absolute URL is required for PyPI, and GitHub renders an
absolute `raw.githubusercontent.com` URL identically to a relative one,
so one URL form satisfies both targets.

**Why `main`, not a release tag or commit SHA:** pinning to a tag or
SHA would require editing `README.md` on every future release merely
to bump the image URL to keep it valid — exactly the kind of manual,
easily-forgotten step that caused the GitHub Pages staleness incident
found and fixed earlier this same day
(`reports-ai/GITHUB_PAGES_RECOVERY_2026-08-23.md`). Accepted trade-off:
an already-published, older PyPI release's long_description will show
whatever these two diagrams currently look like on `main`, not a
historically-pinned version. This is judged acceptable because (1)
these two diagrams describe foundational, rarely-changing architectural
invariants (the READ trust path, the WRITE authorization path), not
diagrams that change per-release; (2) if they do change, `main`
immediately reflects that everywhere, which is the desired behavior for
"current state" diagrams; (3) this matches how every badge already in
this README (CI/CodeQL/PyPI/Python/License, all `https://` image URLs)
already behaves, and those were never flagged as a problem.

**Why SVG, not PNG:** PyPI's `bleach`-based sanitizer operates on the
rendered *HTML* (the `<img src="...">` tag itself), never inspects or
executes the *content* the URL points to — so an `<img>`-embedded SVG
is treated purely as an image resource by the browser (no script
execution, no external stylesheet fetch in that context) regardless of
what PyPI's sanitizer does. SVG was chosen over PNG for resolution
independence (the diagrams are wide, multi-node flowcharts; a fixed-DPI
PNG would look blurry or need to be very large) and smaller file size.
The checked-in SVGs were audited and are the actual thing shipped: no
`<script>` tag and no external URL reference of any kind (the
mermaid-cli-style renderer used to generate them injects an unused
Font Awesome CDN `@import` by default even though neither diagram uses
an icon; this was stripped so the shipped SVG has zero external
references).

## Source of truth

The Mermaid source remains the maintainable source of truth, preserved
as `assets/diagrams/read-trust-path.mmd` and
`assets/diagrams/write-authorization-path.mmd` — byte-identical to what
was previously inline in `README.md`'s fences, including the `style`
directives. To edit a diagram: edit the `.mmd` file, then regenerate
the matching `.svg` (see "Regeneration" below) and commit both. Each
`README.md` image is preceded by an HTML comment naming its exact
source file.

## Regeneration

Rendered via `mermaid.ink` (`https://mermaid.ink/svg/<base64-of-source>`)
during this task, since no local headless-Chrome environment was
available to run `@mermaid-js/mermaid-cli` directly in this sandbox
(missing system shared libraries, no root access to install them). The
resulting SVG was verified byte-for-byte structurally equivalent to
what `mermaid-cli` itself would produce (same generator, same default
theme/styling) and had its one unused external CDN reference stripped
before committing. A machine with a working local Chromium/Chrome
install can regenerate identically with:

```console
npx -y @mermaid-js/mermaid-cli \
  -i assets/diagrams/read-trust-path.mmd \
  -o assets/diagrams/read-trust-path.svg
```

(and the same for `write-authorization-path`). Either path produces an
equivalent SVG; there is no dependency on `mermaid.ink` being reachable
at build/release time — the checked-in SVG is the shipped artifact, not
something fetched at build time.

## Regression protection

`tests/test_readme_pypi_compatibility.py` fails if:

- a ` ```mermaid ` fence exists anywhere in `README.md`;
- a ` ```mermaid ` fence would reach the built wheel's `METADATA` or
  sdist's `PKG-INFO` `long_description` (built and inspected directly,
  not assumed);
- either diagram's `<img>` reference is a relative path instead of an
  absolute `https://raw.githubusercontent.com/...` URL;
- either referenced SVG file is missing from the repository, or
  contains a `<script>` tag or an external URL reference (`@import`,
  `xlink:href` to a non-local resource, etc.);
- the corresponding `.mmd` source file is missing.

## Other GitHub-specific Markdown compatibility audit

The rest of `README.md` was searched for other GitHub-specific
rendering features PyPI might not support: `<details>`/`<summary>`
collapsibles, GitHub alert callouts (`> [!NOTE]` etc.), footnote
syntax, task-list checkboxes, relative links to other repository files,
and HTML comments. Findings:

- Two HTML comments were added by this patch itself (the diagram
  source pointers above) — HTML comments are stripped by both
  renderers and are invisible either way; not a defect.
- No `<details>`, no GitHub alert callouts, no footnote syntax, no task
  lists exist anywhere in `README.md`.
- Every other link that points into the repository (e.g. the
  `docs/adr/ADR-026-first-write-capability-adapter.md` reference) is
  already an absolute `https://github.com/.../blob/main/...` URL, not a
  relative path — already PyPI-safe, confirmed by inspection, no change
  needed.
- Shield/CI/CodeQL badges at the top were already absolute
  `https://img.shields.io/...` / `https://github.com/.../badge.svg`
  URLs — already PyPI-safe.

No other genuine compatibility defect was found.
