# ChatGPT desktop app

## Compatibility

The current ChatGPT desktop app can use local stdio MCP servers through its
shared Codex-host configuration. ChatGPT on the web does not read local Codex
configuration; hosted web use requires a separately designed remote plugin or
MCP service, which this project does not provide.

## Installation

Install this project (from PyPI or from source) using the
[README's quick start](../README.md#quick-start), or
[build from source](../CONTRIBUTING.md#local-setup) for development.
The executable and key file must be accessible to the local desktop process.

## Configuration

Open **Settings → MCP servers**, select **Add server**, choose **STDIO**, and
provide this absolute command:

```text
/absolute/path/to/pfsense-mcp-server/.venv/bin/pfsense-mcp-server
```

Configure these environment variables without placing the API-key value in the
application:

```text
PFSENSE_API_URL=https://pfsense.example.invalid
PFSENSE_IDENTITY=api-mcp-admin
PFSENSE_API_KEY_FILE=/absolute/private/path/pfsense-api.key
PFSENSE_TLS_MODE=strict
```

Save and restart the desktop app. The same server can instead be defined in
`~/.codex/config.toml` as shown in the [Codex CLI guide](codex-cli.md); the
desktop app, Codex CLI, and Codex IDE extension share that configuration on the
same host.

## Expected behaviour

Use `/mcp` in the composer to inspect connected servers. The unrestricted
Auditor profile exposes 84 READ tools and zero WRITE tools. No browser-accessible
endpoint is created.

## Troubleshooting and limitations

- ChatGPT web does not connect to this local stdio server.
- If the server is absent, restart the desktop app and inspect its sanitized MCP
  startup status.
- Verify absolute paths, key-file ownership/mode, and TLS trust without
  displaying the credential.
- Do not expose the stdio process through an ad hoc network bridge.

See OpenAI's current [MCP documentation][openai-mcp] for product availability
and configuration details.

[openai-mcp]: https://learn.chatgpt.com/docs/extend/mcp
