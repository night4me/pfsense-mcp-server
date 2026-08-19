"""Typed exception hierarchy for the pfSense MCP server.

No exception in this module may include a credential value, a raw
HTTP header dict, or a raw response body in its message. Code that
catches a lower-level exception must construct a new, sanitized
message rather than propagate the original exception's own string
representation.
"""


class PfSenseMCPError(Exception):
    """Base class for all errors raised by this package."""


class ConfigurationError(PfSenseMCPError):
    """Raised when configuration or credential loading fails."""


class PfSenseConnectionError(PfSenseMCPError):
    """Raised when the pfSense host cannot be reached or times out."""


class PfSenseAuthError(PfSenseMCPError):
    """Raised on HTTP 401/403 from the pfSense API."""


class PfSenseAPIError(PfSenseMCPError):
    """Raised for any other non-2xx pfSense API response. Carries the
    HTTP status code and a sanitized message only."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"pfSense API error (HTTP {status_code}): {message}")


class UnsupportedOperationError(PfSenseMCPError):
    """Raised when a call requests an HTTP method, path, or API
    version not permitted by this build."""


class PfSenseResponseShapeError(PfSenseMCPError):
    """Raised when a pfSense API response does not match the shape
    expected for the endpoint being parsed (missing/wrong-typed
    fields). Never includes the raw response body or field values."""


class PfSenseRequestValidationError(PfSenseMCPError):
    """Raised when caller-supplied arguments are invalid before any
    request is made to pfSense (e.g. an out-of-range limit)."""


class WriteNotAllowedError(PfSenseMCPError):
    """Raised when a mutation is refused because it targets an endpoint
    not present in the write allow-list (WriteEndpoints), or lacks a
    valid, open Recovery Contract. Never includes the rejected payload
    or any pre-state snapshot content in its message."""


class BootstrapProvisioningError(PfSenseMCPError):
    """Raised by ADR-033 bootstrap/recovery code for a refused invariant
    or any non-2xx response from its closed, enumerated HTTP operations.
    Never includes the request payload
    (which may contain a generated password), the response body, or any
    API-key value -- only the HTTP status code and the named operation
    that failed.

    `status_code` is populated only for the non-2xx-response case
    (`security_bootstrap_client.py`'s `_check_response()`); it is `None`
    for a refused invariant or a malformed/unparseable response shape,
    where there is no HTTP status to classify. This is the minimum
    typed distinction `security_auth_transition.py`'s bounded
    observation-retry logic needs to tell a transient upstream response
    (e.g. 502/503/504 during a settings-triggered reload) apart from a
    definite, non-retryable failure -- added 2026-08-19 as a narrow,
    observation-only hardening slice; it does not change this
    exception's message/`str()` behavior for any existing caller."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)
