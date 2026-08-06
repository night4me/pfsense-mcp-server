"""Tool-level audit logging: tool name, identity, outcome, duration.
Distinct from RestApiClient's own per-HTTP-call logging."""

from __future__ import annotations

import functools
import inspect
import logging
import time
from typing import Callable, TypeVar

from ..errors import PfSenseMCPError

logger = logging.getLogger("pfsense_mcp.tools")

F = TypeVar("F", bound=Callable[..., object])


def audit_logged(tool_name: str, identity: str) -> Callable[[F], F]:
    def decorator(fn: F) -> F:
        signature = inspect.signature(fn)
        sensitive_metadata_supported = "include_identifying_metadata" in signature.parameters

        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            start = time.monotonic()
            sensitive_metadata_requested = False
            if sensitive_metadata_supported:
                bound = signature.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                sensitive_metadata_requested = bound.arguments.get("include_identifying_metadata") is True
            audit_context = (
                "tool=%s upstream_identity=%s sensitive_metadata_supported=%s sensitive_metadata_requested=%s"
            )
            audit_values = (tool_name, identity, sensitive_metadata_supported, sensitive_metadata_requested)
            logger.info(
                "tool_invoked " + audit_context + " failure_class=none exception_class=none",
                *audit_values,
            )
            try:
                result = fn(*args, **kwargs)
            except PfSenseMCPError as exc:
                duration_ms = (time.monotonic() - start) * 1000
                logger.warning(
                    "tool_failed " + audit_context + " duration_ms=%.1f failure_class=domain exception_class=%s",
                    *audit_values,
                    duration_ms,
                    type(exc).__name__,
                )
                raise
            except Exception as exc:
                duration_ms = (time.monotonic() - start) * 1000
                logger.warning(
                    "tool_failed " + audit_context + " duration_ms=%.1f failure_class=unexpected exception_class=%s",
                    *audit_values,
                    duration_ms,
                    type(exc).__name__,
                )
                raise
            duration_ms = (time.monotonic() - start) * 1000
            logger.info(
                "tool_succeeded " + audit_context + " duration_ms=%.1f failure_class=none exception_class=none",
                *audit_values,
                duration_ms,
            )
            return result

        return wrapper  # type: ignore[return-value]

    return decorator
