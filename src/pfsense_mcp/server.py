"""pfSense MCP server entrypoint. All logic lives in Application.

Handles `--help`/`--version` directly, before touching `Application` at
all, so a user who runs this binary with no MCP client attached (or asks
for help) gets an immediate, useful answer instead of either silence or
a bare configuration-error stack. This is the intended front door for
"how do I even start" -- see docs/GETTING_STARTED.md.
"""

from __future__ import annotations

import sys
import warnings

_HELP_TEXT = """\
pfsense-mcp-server -- the MCP server itself.

This process speaks the Model Context Protocol over stdio; it takes no
interactive input and expects to be launched BY an MCP client (Claude
Desktop, Claude Code, Codex, or any other MCP-compatible client), not
run directly by hand in a normal terminal session.

Not configured yet?

  pfsense-mcp-security setup

runs a short guided wizard: it asks a few questions about your pfSense
firewall, verifies the connection, and prints the exact configuration
to paste into your MCP client. Nothing below needs to be typed by hand.

Options:
  -h, --help     Show this message and exit.
  --version      Show the installed package version and exit.

Documentation: https://night4me.github.io/pfsense-mcp-server/
"""


def _print_version() -> None:
    import importlib.metadata

    try:
        version = importlib.metadata.version("pfsense-mcp-server")
    except importlib.metadata.PackageNotFoundError:
        version = "unknown (not installed as a package)"
    print(f"pfsense-mcp-server {version}")


def main() -> None:
    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv:
        print(_HELP_TEXT, end="")
        return
    if "--version" in argv:
        _print_version()
        return

    # mcp's own FastMCP constructor emits a known-benign upstream
    # pydantic-settings warning (an unresolved forward reference on its
    # internal `lifespan` field) on every construction, including this
    # early-exit help/version path avoiding it entirely above. Filtered
    # here narrowly -- by exact upstream class, not a blanket
    # `warnings.filterwarnings("ignore")` -- so a real warning from this
    # project's own code is never silently hidden alongside it.
    from pydantic_settings.exceptions import IncompleteFieldDefinitionWarning

    warnings.filterwarnings("ignore", category=IncompleteFieldDefinitionWarning)

    from .application import Application

    Application().run()


if __name__ == "__main__":
    main()
