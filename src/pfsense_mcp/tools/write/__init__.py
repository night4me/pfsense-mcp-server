"""Mutating MCP tools. Contains exactly one tool
(`set_firewall_alias_description.py`, W3 Slice 4's accepted first-WRITE
product surface), imported from exactly one place --
`pfsense_mcp.tools.registry` -- enforced by `scripts/tools_write_check.py`.
Any additional WRITE tool beyond the single accepted alias-description
operation is explicitly post-v0.4.0 work requiring a new, separate,
explicit owner decision (see `reports-ai/AI_CONTEXT.md`'s durable
roadmap ceiling)."""
