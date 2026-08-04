"""pfSense MCP server entrypoint. All logic lives in Application."""

from __future__ import annotations

from .application import Application


def main() -> None:
    Application().run()


if __name__ == "__main__":
    main()
