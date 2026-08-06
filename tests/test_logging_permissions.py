import logging
import stat

from pfsense_mcp.logging_setup import configure_logging, shutdown_logging


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _reset_logger() -> None:
    logger = logging.getLogger("pfsense_mcp")
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def test_configure_logging_creates_dir_and_file_with_restrictive_permissions(tmp_path):
    log_dir = tmp_path / "state"
    configure_logging(log_dir, max_bytes=1_000_000, backup_count=1)
    try:
        assert _mode(log_dir) == 0o700
        assert _mode(log_dir / "pfsense-mcp-server.log") == 0o600
    finally:
        _reset_logger()


def test_configure_logging_corrects_preexisting_loose_permissions(tmp_path):
    log_dir = tmp_path / "state"
    log_dir.mkdir(mode=0o755)
    log_file = log_dir / "pfsense-mcp-server.log"
    log_file.write_text("")
    log_file.chmod(0o644)

    configure_logging(log_dir, max_bytes=1_000_000, backup_count=1)
    try:
        assert _mode(log_dir) == 0o700
        assert _mode(log_file) == 0o600
    finally:
        _reset_logger()


def test_configure_logging_sets_dependency_loggers_to_warning(tmp_path):
    configure_logging(tmp_path / "state", max_bytes=1_000_000, backup_count=1)
    try:
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("httpcore").level == logging.WARNING
    finally:
        _reset_logger()


def test_repeated_configuration_replaces_and_closes_owned_handler(tmp_path):
    logger = logging.getLogger("pfsense_mcp")
    configure_logging(tmp_path / "state", max_bytes=1_000_000, backup_count=1)
    try:
        first = next(handler for handler in logger.handlers if hasattr(handler, "_pfsense_mcp_owned"))

        configure_logging(tmp_path / "state", max_bytes=1_000_000, backup_count=1)

        owned = [handler for handler in logger.handlers if hasattr(handler, "_pfsense_mcp_owned")]
        assert len(owned) == 1
        assert first.stream is None
    finally:
        _reset_logger()


def test_shutdown_closes_owned_handler_without_removing_unrelated_handler(tmp_path):
    logger = logging.getLogger("pfsense_mcp")
    unrelated = logging.NullHandler()
    logger.addHandler(unrelated)
    configure_logging(tmp_path / "state", max_bytes=1_000_000, backup_count=1)
    try:
        owned = next(handler for handler in logger.handlers if hasattr(handler, "_pfsense_mcp_owned"))

        shutdown_logging()

        assert owned.stream is None
        assert unrelated in logger.handlers
    finally:
        _reset_logger()
