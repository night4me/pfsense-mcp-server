"""Sanitized, redaction-filtered logging for the pfSense MCP server.

Logs are written locally only, outside this repository and never
committed. A redaction filter scans every formatted log message for
any registered secret value and masks it — defense-in-depth against a
future logging mistake elsewhere in the codebase. Rotation size and
retention count are configuration-driven, not hardcoded.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path

DEFAULT_LOG_DIR = Path.home() / ".local" / "state" / "pfsense-mcp-server"
_OWNED_HANDLER_MARKER = "_pfsense_mcp_owned"


class SecretRedactionFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._secrets: list[str] = []

    def register_secret(self, value: str) -> None:
        if value:
            self._secrets.append(value)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for secret in self._secrets:
            if secret in message:
                message = message.replace(secret, "[REDACTED]")
        record.msg = message
        record.args = ()
        return True


def _ensure_log_dir(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(log_dir, 0o700)


def _ensure_log_file(log_file: Path) -> None:
    fd = os.open(log_file, os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    os.chmod(log_file, 0o600)


def configure_logging(
    log_dir: Path, *, max_bytes: int, backup_count: int, level: int = logging.INFO
) -> SecretRedactionFilter:
    _ensure_log_dir(log_dir)
    log_file = log_dir / "pfsense-mcp-server.log"
    _ensure_log_file(log_file)

    redaction_filter = SecretRedactionFilter()
    root = logging.getLogger("pfsense_mcp")
    shutdown_logging()
    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    setattr(handler, _OWNED_HANDLER_MARKER, True)
    handler.addFilter(redaction_filter)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False

    # Dependency loggers are noisy at INFO (e.g. httpx logs every request
    # line) and must not spam stderr during normal operation.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    return redaction_filter


def shutdown_logging() -> None:
    """Close only handlers created by :func:`configure_logging`."""
    logger = logging.getLogger("pfsense_mcp")
    for handler in list(logger.handlers):
        if getattr(handler, _OWNED_HANDLER_MARKER, False):
            logger.removeHandler(handler)
            handler.close()
