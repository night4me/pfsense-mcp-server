import logging

from pfsense_mcp.logging_setup import SecretRedactionFilter


def test_redaction_filter_masks_registered_secret(caplog):
    logger = logging.getLogger("test.redaction")
    logger.setLevel(logging.INFO)
    redaction_filter = SecretRedactionFilter()
    redaction_filter.register_secret("super-secret-value")
    logger.addFilter(redaction_filter)

    with caplog.at_level(logging.INFO, logger="test.redaction"):
        logger.info("debug dump: super-secret-value was used")

    assert "super-secret-value" not in caplog.text
    assert "[REDACTED]" in caplog.text
