import json
import logging

import pytest

from pfsense_mcp.errors import PfSenseAuthError
from pfsense_mcp.write_audit import configure_write_audit_logging, logger, write_audit_logged


class _FakeWriteClient:
    def __init__(self) -> None:
        self._identity = "api-mcp-admin"

    @write_audit_logged("dry_run")
    def dry_run(self, payload):
        return {"ok": True}

    @write_audit_logged("execute")
    def execute(self, payload):
        raise PfSenseAuthError("auth failed")


def _read_json_lines(log_file):
    lines = log_file.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.fixture
def write_audit_log(tmp_path):
    redaction_filter = configure_write_audit_logging(tmp_path, max_bytes=1_000_000, backup_count=1)
    log_file = tmp_path / "pfsense-mcp-server-write-audit.log"
    try:
        yield redaction_filter, log_file
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()


def test_configure_creates_a_separate_log_file(write_audit_log):
    _redaction_filter, log_file = write_audit_log
    assert log_file.is_file()


def test_successful_call_logs_requested_and_completed_events(write_audit_log):
    _redaction_filter, log_file = write_audit_log

    client = _FakeWriteClient()
    client.dry_run({"secret_payload": "should-never-appear"})

    events = [entry["event"] for entry in _read_json_lines(log_file)]
    assert "dry_run_requested" in events
    assert "dry_run_completed" in events


def test_failing_call_logs_failed_event_with_error_type_only(write_audit_log):
    _redaction_filter, log_file = write_audit_log

    client = _FakeWriteClient()
    with pytest.raises(PfSenseAuthError):
        client.execute({"secret_payload": "should-never-appear"})

    entries = _read_json_lines(log_file)
    failed = [e for e in entries if e["event"] == "execute_failed"]
    assert len(failed) == 1
    assert failed[0]["error"] == "PfSenseAuthError"


def test_no_logged_line_ever_contains_payload_content(write_audit_log):
    _redaction_filter, log_file = write_audit_log

    client = _FakeWriteClient()
    client.dry_run({"secret_payload": "should-never-appear"})

    raw_text = log_file.read_text(encoding="utf-8")
    assert "should-never-appear" not in raw_text


def test_redaction_filter_masks_registered_secrets(write_audit_log):
    redaction_filter, log_file = write_audit_log
    redaction_filter.register_secret("api-mcp-admin")

    log = logging.getLogger("pfsense_mcp.write_audit")
    log.info('{"event": "test", "identity": "api-mcp-admin"}')

    raw_text = log_file.read_text(encoding="utf-8")
    assert "api-mcp-admin" not in raw_text
    assert "[REDACTED]" in raw_text
