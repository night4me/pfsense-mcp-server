# ChatGPT

## Compatibility

ChatGPT cannot connect directly to a local stdio MCP server. The current
`pfsense-mcp-server` supports local stdio only, so there is no supported ChatGPT
configuration for this release.

OpenAI's current documentation requires a remote MCP server or its secure
tunnelling workflow for private servers. Converting this project to a remotely
reachable service would add authentication, authorization, transport, and
deployment requirements that are outside the supported architecture. Do not
expose the stdio process through an ad hoc network bridge.

See OpenAI's [developer mode and MCP connector documentation][openai-mcp] for
current product availability and connection requirements.

## Installation

You may install the server using the main [installation guide](../README.md#installation),
but installation alone does not make it compatible with ChatGPT. Use one of the
local stdio clients in the [examples index](README.md) for the current release.

## Configuration

None. This repository does not ship a remote MCP endpoint, OAuth support, or a
ChatGPT connector configuration.

## Expected behaviour

The server will not appear in ChatGPT's connector list. This is an intentional
transport boundary, not a server fault.

## Troubleshooting

- Do not enter the pfSense API key into ChatGPT or a connector form.
- Do not make the server publicly reachable to work around the stdio boundary.
- If remote MCP support is added in a future release, follow that release's
  threat model and deployment guide rather than this page.

[openai-mcp]: https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt-beta
