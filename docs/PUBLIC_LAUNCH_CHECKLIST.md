# Public launch checklist

This records exact, ready-to-apply values and a completion checklist for
the repository-local and platform-level steps involved in eventually
making this repository public. Nothing on this page has been applied —
every platform-level action here (repository visibility, GitHub Pages,
GitHub About/topics) requires explicit owner action, taken deliberately
and separately from this document existing. Repository-local content is
already done; this page exists so applying the remaining platform steps
is a copy-paste operation, not a re-derivation.

## Repository-local — already done

- [x] README rewritten as a concise, positioning-forward landing page
      (public positioning, security claim discipline, example prompts,
      an architecture diagram distinguishing current production from
      the future inert WRITE framework).
- [x] `CONTRIBUTING.md`/`SECURITY.md` reviewed from an external
      contributor's / security researcher's perspective.
- [x] `SUPPORT.md`, `.editorconfig`, issue/PR templates, dependency
      review CI.
- [x] MkDocs documentation site — builds strictly in CI, organized
      navigation (Getting Started → Security → API → Architecture →
      Tier 1 → Release/contributing → Acceptance records).
- [x] Package metadata (`pyproject.toml`): accurate description,
      `Homepage`/`Repository`/`Issues`/`Changelog`/`Security`/
      `Documentation` URLs, `security` keyword added.
- [x] PyPI project page — `readme = "README.md"` means the PyPI page
      already reflects everything above once the next version publishes;
      no separate PyPI-specific content needed.

## Platform-level — recorded, not applied

### GitHub About description

Exact recommended text for the repository's "About" field (GitHub's
description field; keep it short, it's what shows in search results and
repository listings):

```text
A security-first MCP server for pfSense — READ-only today by design; WRITE is staged behind explicit safety architecture, not a feature flag.
```

(145 characters.)

### GitHub topics

Exact recommended topic list (lowercase, hyphenated, GitHub convention):

```text
mcp
mcp-server
model-context-protocol
pfsense
firewall
network-security
security
ai-tools
llm
python
```

Rationale: `mcp`/`mcp-server`/`model-context-protocol` cover how someone
searching for MCP tooling would find this; `pfsense`/`firewall`/
`network-security` cover the domain; `security` and `ai-tools`/`llm`
reflect the project's actual positioning (a security-first AI tool
integration, not a generic firewall management script); `python` is the
implementation language. All ten are accurate today — none imply a
capability (like `automation` or `firewall-management`) this project
doesn't yet have.

### GitHub Pages / documentation site URL

`mkdocs.yml`'s `site_url` is already set to the standard predicted URL
for a Pages deployment from this repository with no custom domain:

```text
https://night4me.github.io/pfsense-mcp-server/
```

Once Pages is enabled (a separate, explicit owner decision — see
`reports-ai`'s "Push authorization" note, which explicitly reserves
this), no `mkdocs.yml` change is needed; the existing `site_url` is
already correct. At that point:

- [ ] Enable GitHub Pages (owner decision, not covered here).
- [ ] Update `pyproject.toml`'s `Documentation` URL from the current
      `docs/` source-tree link to the deployed site URL above.
- [ ] Update the README's "Documentation" section note ("A browsable
      version... is built (not yet publicly deployed)") to drop the
      "not yet" qualifier and link the live site directly.
- [ ] Update `docs/index.md`'s equivalent note.
- [ ] Set the repository's "Website" field (GitHub repo settings) to
      the deployed site URL, so it appears alongside the About
      description.

### Making the repository public

Not evaluated here beyond noting it is explicitly reserved to the owner
(see `AGENTS.md`'s approval boundaries and `reports-ai`'s standing push-
authorization note, which lists "making the repository public" as
explicitly not delegated). When it happens:

- [ ] Re-run `make validate`/`security_scan.py` immediately before
      flipping visibility, as a final confirmation no private data has
      landed since the last check (routine — every commit already passes
      this, but a launch moment is worth one more explicit confirmation).
- [ ] Apply the About description and topics above.
- [ ] Consider whether `dependabot.yml`'s `open-pull-requests-limit: 5`
      and weekly schedule are still the right cadence for a now-public,
      possibly higher-traffic repository (not evaluated here — a
      judgment call at the time, not a correctness issue today).

## Non-goals of this document

This is not a release checklist (see
[`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) for that — versioned
package releases are a separate, already-established process) and does
not itself authorize any of the platform-level actions it records
recommended values for.
