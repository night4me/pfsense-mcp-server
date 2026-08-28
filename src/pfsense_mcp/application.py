"""Application — owns startup, dependency construction, and lifecycle.

server.py's only responsibility is to construct and run this class.
"""

from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP

from .config import load_api_key, load_config, load_logging_config
from .diagnostics import build_diagnostics_report
from .errors import ConfigurationError
from .factory import build_pfsense_client
from .logging_setup import DEFAULT_LOG_DIR as LOG_DIR
from .logging_setup import configure_logging, shutdown_logging
from .tier1_anchor_check import run_anchor_startup_check
from .tools.registry import ToolRegistry
from .transport.http import HttpTransport


def _print_configuration_error(exc: ConfigurationError) -> None:
    # This process (the MCP server itself) is not meant to be configured
    # by hand -- any ConfigurationError here means the guided wizard
    # either hasn't been run yet or an existing environment has drifted,
    # and in both cases the same next step applies. stdout is left
    # untouched (still just the "configuration error:" line an
    # automated caller might parse); this is an additive second line.
    print(f"pfsense-mcp-server: configuration error: {exc}", file=sys.stderr)
    print("Run 'pfsense-mcp-security setup' for guided configuration.", file=sys.stderr)


class Application:
    def __init__(self) -> None:
        self._mcp = FastMCP("pfsense-mcp-server")
        self._transport: HttpTransport | None = None

    def run(self) -> None:
        try:
            self._bootstrap()
            self._mcp.run()
        finally:
            self.shutdown()

    def _bootstrap(self) -> None:
        try:
            log_max_bytes, log_backup_count = load_logging_config()
        except ConfigurationError as exc:
            _print_configuration_error(exc)
            raise SystemExit(1) from None

        redaction_filter = configure_logging(LOG_DIR, max_bytes=log_max_bytes, backup_count=log_backup_count)
        logger = logging.getLogger("pfsense_mcp")

        # Read-only, opt-in, log-only Tier 1 anti-rollback anchor
        # verification -- independent of, and never gating, the pfSense
        # bootstrap below. Never raises; see tier1_anchor_check.py's own
        # module docstring for the full scope and rationale. Runs before
        # the pfSense-specific bootstrap so its outcome is visible in
        # logs even if that bootstrap later fails.
        run_anchor_startup_check(logger)

        try:
            config = load_config()
            api_key = load_api_key(config)
            redaction_filter.register_secret(api_key)

            transport, pfsense_client = build_pfsense_client(config, api_key)
            self._transport = transport

            registry = ToolRegistry(
                self._mcp,
                pfsense_client,
                config.identity,
                config.profile.capabilities,
                allowed_tools=config.allowed_tools,
                profile_name=config.profile.name,
            )
            registry.register_all()
        except ConfigurationError as exc:
            logger.error("startup_failed: %s", exc)
            _print_configuration_error(exc)
            raise SystemExit(1) from None

        report = build_diagnostics_report(config, type(self._transport).__name__)
        logger.info(
            "startup_ok identity=%s profile=%s capabilities=%s tls_mode=%s api_version=%s transport=%s",
            report.identity,
            report.profile_name,
            ",".join(report.capabilities),
            report.tls_mode,
            report.api_version,
            report.transport_type,
        )

    def shutdown(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        shutdown_logging()
