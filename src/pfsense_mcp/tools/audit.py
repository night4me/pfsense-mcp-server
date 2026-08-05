"""Tool-level audit logging: tool name, identity, outcome, duration.
Distinct from RestApiClient's own per-HTTP-call logging."""

from __future__ import annotations

import functools
import logging
import time
from typing import Callable, TypeVar

from ..errors import PfSenseMCPError

logger = logging.getLogger("pfsense_mcp.tools")

F = TypeVar("F", bound=Callable[..., object])


def audit_logged(tool_name: str, identity: str) -> Callable[[F], F]:
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            start = time.monotonic()
            logger.info("tool_invoked tool=%s identity=%s", tool_name, identity)
            try:
                result = fn(*args, **kwargs)
            except PfSenseMCPError as exc:
                duration_ms = (time.monotonic() - start) * 1000
                logger.warning(
                    "tool_failed tool=%s identity=%s duration_ms=%.1f error=%s",
                    tool_name,
                    identity,
                    duration_ms,
                    type(exc).__name__,
                )
                raise
            duration_ms = (time.monotonic() - start) * 1000
            logger.info("tool_succeeded tool=%s identity=%s duration_ms=%.1f", tool_name, identity, duration_ms)
            return result

        return wrapper  # type: ignore[return-value]

    return decorator
