"""Write-audit logging: a separate, structured (JSON-lines) log file
distinct from the existing plain-text server log, so write activity is
trivially greppable/alertable on independent of ordinary read traffic.

Never includes a Recovery Contract's pre_state_snapshot content or a
MutationPlan's payload values in any logged line — only the fact and
shape of each event (identity, capability, endpoint_symbol, contract_id,
dry_run, duration_ms, outcome), consistent with errors.py's "no raw
response body" rule.

Deliberately self-contained: configure_write_audit_logging() is not
called anywhere in this build (Application._bootstrap() never imports
this module — see Design Principle 1 in the Tier 0 spec), so this stays
unreachable/unused unless a future tier explicitly wires it in.
"""

from __future__ import annotations

import functools
import json
import logging
import logging.handlers
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from .errors import PfSenseMCPError
from .logging_setup import SecretRedactionFilter

logger = logging.getLogger("pfsense_mcp.write_audit")

F = TypeVar("F", bound=Callable[..., object])


def _ensure_log_dir(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(log_dir, 0o700)


def _ensure_log_file(log_file: Path) -> None:
    fd = os.open(log_file, os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    os.chmod(log_file, 0o600)


def configure_write_audit_logging(log_dir: Path, *, max_bytes: int, backup_count: int) -> SecretRedactionFilter:
    _ensure_log_dir(log_dir)
    log_file = log_dir / "pfsense-mcp-server-write-audit.log"
    _ensure_log_file(log_file)

    redaction_filter = SecretRedactionFilter()
    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    handler.addFilter(redaction_filter)
    # Bare message formatter: each logged message is already a complete
    # JSON object, so the line itself stays valid, parseable JSON.
    handler.setFormatter(logging.Formatter("%(message)s"))

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False

    return redaction_filter


def _log_event(event: str, *, identity: str, outcome: str, duration_ms: float, **extra: object) -> None:
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "identity": identity,
        "outcome": outcome,
        "duration_ms": round(duration_ms, 1),
        **extra,
    }
    logger.info(json.dumps(payload, sort_keys=True))


def write_audit_logged(event_name: str) -> Callable[[F], F]:
    """Decorates a PfSenseWriteClient/WriteApiClient bound method. The
    wrapped instance must expose an `_identity: str` attribute (the same
    convention RestApiClient/WriteApiClient already use)."""

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(self: object, *args: object, **kwargs: object) -> object:
            identity = getattr(self, "_identity", "unknown")
            start = time.monotonic()
            _log_event(f"{event_name}_requested", identity=identity, outcome="requested", duration_ms=0.0)
            try:
                result = fn(self, *args, **kwargs)
            except PfSenseMCPError as exc:
                duration_ms = (time.monotonic() - start) * 1000
                _log_event(
                    f"{event_name}_failed",
                    identity=identity,
                    outcome="failed",
                    duration_ms=duration_ms,
                    error=type(exc).__name__,
                )
                raise
            duration_ms = (time.monotonic() - start) * 1000
            _log_event(f"{event_name}_completed", identity=identity, outcome="completed", duration_ms=duration_ms)
            return result

        return wrapper  # type: ignore[return-value]

    return decorator
