from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "docs" / "SECURITY_TEST_CATALOG.md"
TEST_REFERENCE = re.compile(r"`(?P<name>[a-z0-9_*]+\.py)`")


def test_security_catalog_references_existing_executable_checks():
    references = set(TEST_REFERENCE.findall(CATALOG.read_text(encoding="utf-8")))

    assert references
    for reference in references:
        matches = list((ROOT / "tests").glob(reference)) + list((ROOT / "scripts").glob(reference))
        assert matches, f"security catalog references missing executable check: {reference}"
