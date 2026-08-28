# Claude Code

Claude Code supports local stdio MCP servers via the `claude mcp add` CLI
command (Anthropic's own documented, recommended way to register a server —
see [Claude Code's MCP documentation][claude-code-mcp]), or by editing
`.mcp.json` (project scope, shared via version control) or `~/.claude.json`
(personal/user scope) directly.

## Installation

Install the project in a virtual environment as described in the
[README](../README.md#quick-start).

## Configuration

The recommended approach is the CLI command — it writes the correct file for
your chosen scope without you having to construct JSON by hand:

```console
claude mcp add --scope project --transport stdio pfsense \
  --env PFSENSE_API_URL=https://pfsense.example.invalid \
  --env PFSENSE_IDENTITY=api-mcp-admin \
  --env PFSENSE_API_KEY_FILE=/absolute/private/path/pfsense-api.key \
  --env PFSENSE_TLS_MODE=strict \
  -- /absolute/path/to/pfsense-mcp-server/.venv/bin/pfsense-mcp-server
```

Use `--scope project` for a team-shared `.mcp.json` you commit to version
control (never commit the actual key file, only its path), or `--scope user`
(the default if `--scope` is omitted) to make the server available across all
your projects.

If you prefer to edit the file directly, the same server entry looks like
this in either `.mcp.json` or `~/.claude.json`'s `mcpServers` object:

```json
{
  "mcpServers": {
    "pfsense": {
      "type": "stdio",
      "command": "/absolute/path/to/pfsense-mcp-server/.venv/bin/pfsense-mcp-server",
      "env": {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": "/absolute/private/path/pfsense-api.key",
        "PFSENSE_TLS_MODE": "strict"
      }
    }
  }
}
```

## Expected behaviour

Claude Code spawns the server as a child process and discovers 95 READ tools
plus 2 guidance tools under the default (`auditor`) profile; no WRITE tool is
available. Project-scoped servers require workspace trust approval before
first use in an interactive session.

## Troubleshooting

- Run `claude mcp list` to confirm the server is registered, and `claude mcp
  get pfsense` to inspect its exact configuration.
- If the server doesn't appear inside a session, run `/mcp` to see its
  connection status.
- If configuration is rejected, check the HTTPS URL, key-file ownership and
  permissions, and TLS mode without displaying the key.
- `claude mcp remove pfsense` cleanly removes the entry if you need to start
  over.

[claude-code-mcp]: https://code.claude.com/docs/en/mcp
