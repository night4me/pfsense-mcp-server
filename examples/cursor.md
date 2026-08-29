# Cursor

Cursor supports local stdio MCP servers through project or user configuration.

## Installation

Follow the project [installation guide](../README.md#quick-start), then choose
one configuration scope:

- project: `.cursor/mcp.json` (share the structure, never private paths or data);
- user: `~/.cursor/mcp.json` (recommended for appliance-specific configuration).

## Configuration

```json
{
  "mcpServers": {
    "pfsense": {
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

This is the same `mcpServers` JSON shape Claude Desktop uses — if you've
already run `pfsense-mcp-security setup write-client-config --client
claude-desktop --config-path <path>` (see [Connect your MCP
client](../docs/MCP_CLIENT_CONFIGURATION.md)) to preview or generate this
block, the exact same content is valid here; only the file path differs.

See Cursor's [MCP documentation][cursor-mcp] for current configuration scopes
and controls.

## Expected behaviour

After Cursor reloads the MCP configuration, the `pfsense` server should show 95
READ tools. Approving a tool lets the local process query the configured
appliance. No WRITE tool is registered.

## Troubleshooting

- Reload Cursor after changing `mcp.json`.
- Validate the JSON and use absolute paths.
- Run the entry point with the same environment in a private terminal to inspect
  sanitized startup errors; do not print the key or request headers.
- Keep machine-specific configuration out of version control.

[cursor-mcp]: https://cursor.com/docs/mcp
