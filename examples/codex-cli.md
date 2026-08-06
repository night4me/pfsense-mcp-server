# OpenAI Codex CLI

Codex CLI supports local stdio MCP servers and shares its MCP configuration
with the ChatGPT desktop app and Codex IDE extension on the same host.

## Installation

Install this project from source using the [main guide](../README.md#installation-from-source),
and install Codex CLI according to OpenAI's documentation. Absolute paths make
the setup independent of Codex's working directory.

## Configuration

Add this table to `~/.codex/config.toml` (or to `.codex/config.toml` in a
trusted project):

```toml
[mcp_servers.pfsense]
command = "/absolute/path/to/pfsense-mcp-server/.venv/bin/pfsense-mcp-server"
required = true

[mcp_servers.pfsense.env]
PFSENSE_API_URL = "https://pfsense.example.invalid"
PFSENSE_IDENTITY = "api-mcp-admin"
PFSENSE_API_KEY_FILE = "/absolute/private/path/pfsense-api.key"
PFSENSE_TLS_MODE = "strict"
```

The equivalent CLI form is available through `codex mcp add`, but editing TOML
avoids placing appliance metadata in shell history. Never pass the API-key value
through `--env`; this server accepts only a key-file path.

## Expected behaviour

Run `codex mcp list`, then use `/mcp` in the Codex TUI to inspect the server.
With no tool restriction, it registers 41 READ tools and zero WRITE tools.

## Troubleshooting and limitations

- If startup is marked failed, verify the absolute executable path and the
  key-file ownership/mode without reading its contents.
- A project-scoped `.codex/config.toml` is loaded only for trusted projects.
- This is a stdio configuration. Do not add a URL: the project exposes no HTTP
  MCP transport.
- Codex-side tool filters are client policy only; use
  `PFSENSE_ALLOWED_TOOLS` for the server's monotonic exact-name restriction.

See OpenAI's current [MCP documentation][openai-mcp] for the complete Codex
configuration reference.

[openai-mcp]: https://learn.chatgpt.com/docs/extend/mcp
