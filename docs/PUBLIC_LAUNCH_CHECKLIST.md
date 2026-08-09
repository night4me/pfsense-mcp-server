# Public launch checklist

**Status: complete (2026-08-09).** The repository is public, GitHub
Pages is live, and the About description/topics below are applied
exactly as recorded. This page is kept as a historical record of the
exact values used and the reasoning behind them, not as a forward-looking
plan — the checkboxes below reflect what was actually done, not what
remains to do. For current live state, see `reports-ai/latest.md`, not
this page.

This originally recorded exact, ready-to-apply values and a completion
checklist for the repository-local and platform-level steps involved in
making this repository public, so that applying the platform steps would
be a copy-paste operation, not a re-derivation.

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

## Platform-level — applied

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

Pages was enabled 2026-08-09; no `mkdocs.yml` change was needed, since
the `site_url` above was already correct at the time. Deployment
mechanism actually used: `mkdocs gh-deploy` (builds and pushes a
`gh-pages` branch — GitHub auto-enabled Pages on detecting that branch
on the now-public repo). Redeployment after a docs change is still
manual; nothing currently automates re-running `mkdocs gh-deploy`.

- [x] Enable GitHub Pages.
- [x] Update `pyproject.toml`'s `Documentation` URL from the `docs/`
      source-tree link to the deployed site URL above.
- [x] Update the README's "Documentation" section to drop the "not yet"
      qualifier and link the live site directly.
- [x] `docs/index.md` checked — it had no equivalent stale note, so no
      change was needed there.
- [x] Set the repository's "Website" field (GitHub repo settings) to
      the deployed site URL.

### Making the repository public

Done 2026-08-09, under explicit owner authorization (see
`AGENTS.md`'s approval boundaries — this was never standing-delegated,
and still is not for any future visibility change).

- [x] Re-ran `make validate`/`security_scan.py` immediately before
      flipping visibility, as a final confirmation no private data had
      landed since the last check.
- [x] Applied the About description and topics above.
- [ ] Whether `dependabot.yml`'s `open-pull-requests-limit: 5` and
      weekly schedule are still the right cadence for a now-public,
      real-traffic repository remains a genuinely open, unresolved
      judgment call — not evaluated as part of the launch itself.

## Non-goals of this document

This is not a release checklist (see
[`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) for that — versioned
package releases are a separate, already-established process) and does
not itself authorize any of the platform-level actions it records
recommended values for.
