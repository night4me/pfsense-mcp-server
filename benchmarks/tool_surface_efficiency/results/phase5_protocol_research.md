# Phase 5 — MCP protocol + client capability research

Researched via WebFetch against authoritative sources during the POST-v1.0 PRIORITY #2
tool-surface-efficiency benchmark. Every claim below is sourced; anything not confirmed
is explicitly flagged undetermined rather than assumed.

## Q1 — Can available tools change during a session?

**Yes, per spec.** `ServerCapabilities.tools.listChanged: boolean` declares support; the
server sends `notifications/tools/list_changed` (a JSON-RPC notification, no `id`, no
response expected) when the list changes.

Source: `modelcontextprotocol.io/specification/2025-06-18/server/tools` — "When the list
of available tools changes, servers that declared the `listChanged` capability **SHOULD**
send a notification." Confirmed in the installed SDK: `mcp/types.py:1372-1378`
(`ToolListChangedNotification`, method `"notifications/tools/list_changed"`).

## Q2 — Is `tools/list` cached by clients?

Client-dependent; real evidence found only for Claude Code. It caches remote-server tool
lists across sessions via a "discovery cache" (off by default, `MCP_DISCOVERY_CACHE=1`
to enable): *"A remote HTTP or SSE server you've used before can show a `cached` status...
Claude Code loaded the server's tool list from its discovery cache, saved in a previous
session, instead of connecting at startup."* For local stdio servers (this project's
transport), discovery happens once at server-connect time each session (`tools/list`
sent right after connect), not per-turn.

Source: `code.claude.com/docs/en/mcp`. No equivalent finding located for Codex CLI or
generic clients — **undetermined, not found**.

## Q3 — Is list-changed actually honored in practice by real clients?

**Yes for Claude Code**, concretely and beyond spec theory: *"Claude Code supports MCP
`list_changed` notifications... Claude Code automatically refreshes the available
capabilities from that server."* Its v2 runtime holds a stream open specifically to
receive these.

Source: `code.claude.com/docs/en/mcp`. **Not verified for Claude Desktop or Codex CLI** —
no direct doc evidence found in this research pass.

## Q4 — Can a server expose fewer tools now, more later?

Mechanically yes per spec — that is exactly what `listChanged` + the notification exist
for; no other precondition is specified beyond declaring the capability.

Source: same spec page as Q1.

## Q5 — Will Codex/Claude clients "re-read the tool list correctly"?

Confirmed for Claude Code (see Q3 quotes — automatic refresh on notification).
**Undetermined for Codex CLI / Claude Desktop specifically** — flagged rather than
guessed; no direct doc evidence found for those two clients in this pass.

## Q6 — Stale-client / security-state risk from dynamic exposure?

Reasoned from spec mechanics, not directly documented as a risk statement: if a client
caches a stale list and calls a since-removed tool, the JSON-RPC error path applies
(an "Unknown tool"-style protocol error per the Tools spec's Error Handling section) —
not silent failure or misrouting. The real risk is a client that never listens for the
notification (or drops the stream) and retains a stale, possibly over-privileged tool
list until manual reconnect. This is a genuine auditability concern for Phase 7, not
resolved by the protocol itself.

## Q7 — Client-side filtering instead of full injection every turn? Is the full schema
really re-sent every turn?

**No, not literally every turn** — the naive "N tools = N schemas resent every turn"
mental model is **not accurate for the Claude API**. Anthropic's prompt-caching docs
confirm tool definitions are cacheable (`cache_control` on the last `tools[]` entry
caches the whole prefix); subsequent turns hit `cache_read_input_tokens`, not full-price
reprocessing.

Source: `platform.claude.com/docs/en/build-with-claude/prompt-caching` — "Tools: Tool
definitions in the `tools` array" are cacheable; cache order is `tools`, `system`,
`messages`.

Separately, and importantly: **Claude Code itself already implements client-side
progressive/on-demand tool exposure today** — this is not hypothetical. Quote: *"With
tool search enabled... Claude Code lists the server's tool names to Claude... Claude can
then search for and call those tools without waiting."* (`code.claude.com/docs/en/mcp`,
"Scale with MCP tool search" section.) This is the exact `ToolSearch` mechanism visible
in this very session's own tool list (deferred tools loaded on demand by name/keyword
search) — direct, first-party confirmation that large tool surfaces are already handled
by client-side deferred loading in a real deployed client, independent of anything this
project would build server-side.

The official MCP docs (`modelcontextprotocol.io/docs/develop/clients/client-best-practices`,
"Progressive Tool Discovery") describe the identical pattern as a first-class,
MCP-blessed host pattern: a `search_tools` meta-tool, staged catalog→inspect→execute,
with explicit guidance to switch to progressive discovery once tool definitions exceed
**1-5% of the context window**, and an explicit warning that this pattern **must
preserve prompt-cache stability** (append new definitions after the cache breakpoint;
don't re-sort `tools[]`; route through a stable meta-tool if using dynamic sets).

**Caveat on source currency**: that client-best-practices page and its linked spec pages
are stamped `2026-07-28` and describe a newer protocol shape (`server/discover`,
`subscriptions/listen`, `ttlMs`/`cacheScope`) than what is actually implemented in this
project's installed `mcp` Python SDK, whose `LATEST_PROTOCOL_VERSION = "2025-11-25"`
(per `mcp/types.py`) still uses the simpler unsolicited-push
`notifications/tools/list_changed` model with no discovery-caching hints. Treat the
progressive-discovery *pattern description* as authoritative (it matches Claude Code's
real, current, documented behavior), but do not assume the newer wire-format details
(`ttlMs`, `cacheScope`, `server/discover`) apply to what this server or its installed
SDK actually speaks today.

## FastMCP dynamic-registration finding

The installed `mcp.server.fastmcp.FastMCP` class **does** expose `add_tool()` /
`remove_tool()` (`.venv/lib/python3.12/site-packages/mcp/server/fastmcp/server.py:400-447`,
backed by `ToolManager.add_tool`/`remove_tool`), and the underlying session has
`send_tool_list_changed()` (`mcp/server/session.py:489-491`). **However**: neither
`FastMCP.add_tool` nor `FastMCP.remove_tool` calls `send_tool_list_changed()`
automatically — grepped both files, zero call sites. A production dynamic-exposure
design in this codebase would need to explicitly call
`ctx.session.send_tool_list_changed()` (or equivalent) itself after any registration
change; this doesn't happen out of the box. There is no dynamic reconfiguration in the
current registry — confirmed no other change is needed for today's static-97-tool
registration to keep working.

## Practical cost-model summary

The "97 tools = 97 schemas paid every single turn" framing overstates the real cost for
the Claude-API-backed clients this project targets:

1. Tool definitions are cacheable prefix content, so steady-state turns pay cache-read
   price, not full price, for an unchanged tool set.
2. Claude Code, the project's most-verified client, already does client-side on-demand
   tool loading (`ToolSearch`/tool-search) independent of anything the MCP server does.
3. MCP itself has a first-party "progressive discovery" pattern recommending action only
   once tool definitions exceed ~1-5% of context window — a concrete, sourced threshold
   Phase 1's byte/token measurements should be checked against rather than assumed to
   already be a problem.

## Sources consulted

- `modelcontextprotocol.io/specification/2025-06-18/server/tools`
- `modelcontextprotocol.io/docs/develop/clients/client-best-practices`
- `code.claude.com/docs/en/mcp`
- `platform.claude.com/docs/en/build-with-claude/prompt-caching`
- Installed SDK source: `mcp/types.py`, `mcp/server/fastmcp/server.py`,
  `mcp/server/session.py` (local `.venv`)
