"""Application — owns startup, dependency construction, and lifecycle.

server.py's only responsibility is to construct and run this class.
"""

from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP

from .config import ConfigurationError, load_api_key, load_config, load_logging_config
from .diagnostics import build_diagnostics_report
from .factory import build_pfsense_client
from .logging_setup import DEFAULT_LOG_DIR as LOG_DIR
from .logging_setup import configure_logging
from .tools.registry import ToolRegistry
from .transport.http import HttpTransport


class Application:
    def __init__(self) -> None:
        self._mcp = FastMCP("pfsense-mcp-server")
        self._transport: HttpTransport | None = None

    def run(self) -> None:
        self._bootstrap()
        try:
            self._mcp.run()
        finally:
            self.shutdown()

    def _bootstrap(self) -> None:
        try:
            log_max_bytes, log_backup_count = load_logging_config()
        except ConfigurationError as exc:
            print(f"pfsense-mcp-server: configuration error: {exc}", file=sys.stderr)
            raise SystemExit(1) from None

        redaction_filter = configure_logging(LOG_DIR, max_bytes=log_max_bytes, backup_count=log_backup_count)
        logger = logging.getLogger("pfsense_mcp")

        try:
            config = load_config()
            api_key = load_api_key(config)
            redaction_filter.register_secret(api_key)

            transport, pfsense_client = build_pfsense_client(config, api_key)
            self._transport = transport

            registry = ToolRegistry(self._mcp, pfsense_client, config.identity, config.profile.capabilities)
            registry.register_all()
        except ConfigurationError as exc:
            logger.error("startup_failed: %s", exc)
            print(f"pfsense-mcp-server: configuration error: {exc}", file=sys.stderr)
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
