"""Off-host, operator-only signing tooling for the ADR-028 first-WRITE
product surface (`set_firewall_alias_description_v1`).

Not packaged (excluded from both the wheel and sdist by pyproject.toml's
explicit include lists -- neither lists `signing/`), not collected by
pytest's default run (`pyproject.toml`'s `addopts` ignores this
directory; run its offline tests explicitly via `pytest signing/`), and
never imported by `src/pfsense_mcp` or `tests/` (see
`tests/test_signing_tool_isolation.py`).

This package exists entirely outside the MCP server's process and
security boundary, per ADR-028's "Signing-side CLI trust boundary" and
`docs/tier1/specs/confirmation_authority.md`'s G3 ("the signing key
never resides on the host running the MCP server process"). It holds
the ONLY private Ed25519 signing key material anywhere in this
repository's own source tree -- production (`src/pfsense_mcp`) loads
only public verification keys, and never imports anything from here.

W3 Slice 5 status (2026-08-15): `sign-confirmation` is implemented and
tested. `sign-authorization` is deliberately NOT implemented -- a
genuine, reproducible defect in `security_plan.py`'s capability-posture
step generation makes it structurally impossible to build correctly
today; see `reports-ai/handoff/` for the exact reproduction and the
required fix, which is out of this package's own scope (it lives in
shared security-plan machinery, not signing tooling).
"""
