import logging

import pytest

from pfsense_mcp.errors import PfSenseMCPError
from pfsense_mcp.tools.audit import audit_logged


@pytest.fixture(autouse=True)
def _capture_tool_audit_records(caplog: pytest.LogCaptureFixture):
    """Capture audit records even if another test disables logger propagation."""
    logger = logging.getLogger("pfsense_mcp.tools")
    logger.addHandler(caplog.handler)
    try:
        yield
    finally:
        logger.removeHandler(caplog.handler)


def _messages(caplog):
    return [record.getMessage() for record in caplog.records if record.name == "pfsense_mcp.tools"]


def test_audit_records_default_sensitive_metadata_choice(caplog):
    @audit_logged("example", "upstream-service")
    def tool(include_identifying_metadata: bool = False):
        return "result-that-must-not-be-logged"

    with caplog.at_level(logging.INFO, logger="pfsense_mcp.tools"):
        tool()

    messages = _messages(caplog)
    assert all("upstream_identity=upstream-service" in message for message in messages)
    assert all("sensitive_metadata_supported=True" in message for message in messages)
    assert all("sensitive_metadata_requested=False" in message for message in messages)
    assert all("result-that-must-not-be-logged" not in message for message in messages)


def test_audit_never_logs_argument_values(caplog):
    sentinel = "SENTINEL-ARGUMENT-VALUE"

    @audit_logged("example", "upstream-service")
    def tool(query: str):
        return None

    with caplog.at_level(logging.INFO, logger="pfsense_mcp.tools"):
        tool(sentinel)

    assert all(sentinel not in message for message in _messages(caplog))


@pytest.mark.parametrize("invocation", [lambda fn: fn(True), lambda fn: fn(include_identifying_metadata=True)])
def test_audit_binds_positional_and_keyword_sensitive_metadata_choice(caplog, invocation):
    @audit_logged("example", "upstream-service")
    def tool(include_identifying_metadata: bool = False):
        return None

    with caplog.at_level(logging.INFO, logger="pfsense_mcp.tools"):
        invocation(tool)

    assert all("sensitive_metadata_requested=True" in message for message in _messages(caplog))


def test_audit_records_domain_failure_without_message(caplog):
    sentinel = "SENTINEL-EXCEPTION-MESSAGE"

    @audit_logged("example", "upstream-service")
    def tool():
        raise PfSenseMCPError(sentinel)

    with caplog.at_level(logging.INFO, logger="pfsense_mcp.tools"), pytest.raises(PfSenseMCPError):
        tool()

    failed = next(message for message in _messages(caplog) if message.startswith("tool_failed"))
    assert "failure_class=domain" in failed
    assert "exception_class=PfSenseMCPError" in failed
    assert sentinel not in failed


def test_audit_records_unexpected_failure_and_reraises_same_object(caplog):
    error = RuntimeError("SENTINEL-UNEXPECTED-MESSAGE")

    @audit_logged("example", "upstream-service")
    def tool():
        raise error

    with caplog.at_level(logging.INFO, logger="pfsense_mcp.tools"), pytest.raises(RuntimeError) as excinfo:
        tool()

    assert excinfo.value is error
    failed = next(message for message in _messages(caplog) if message.startswith("tool_failed"))
    assert "failure_class=unexpected" in failed
    assert "exception_class=RuntimeError" in failed
    assert "SENTINEL-UNEXPECTED-MESSAGE" not in failed


def test_audit_does_not_catch_base_exception(caplog):
    @audit_logged("example", "upstream-service")
    def tool():
        raise KeyboardInterrupt

    with caplog.at_level(logging.INFO, logger="pfsense_mcp.tools"), pytest.raises(KeyboardInterrupt):
        tool()

    assert not any(message.startswith("tool_failed") for message in _messages(caplog))
