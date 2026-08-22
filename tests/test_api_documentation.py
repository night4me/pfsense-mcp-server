import re
from pathlib import Path

from pfsense_mcp.tools.registry import KNOWN_GUIDANCE_TOOL_NAMES, KNOWN_READ_TOOL_NAMES

API_REFERENCE = Path(__file__).parents[1] / "docs" / "API.md"
TOOL_HEADING = re.compile(r"^### `(?P<name>pfsense_[a-z0-9_]+)`$", re.MULTILINE)


def test_api_reference_documents_every_known_read_tool_exactly_once():
    documented = TOOL_HEADING.findall(API_REFERENCE.read_text(encoding="utf-8"))

    assert len(documented) == len(set(documented))
    assert set(documented) == KNOWN_READ_TOOL_NAMES


def test_api_reference_declares_current_registration_count():
    text = API_REFERENCE.read_text(encoding="utf-8")

    expected = (
        f"Registered tools: {len(KNOWN_READ_TOOL_NAMES)} READ, "
        f"{len(KNOWN_GUIDANCE_TOOL_NAMES)} guidance, 0 WRITE"
    )
    assert expected in text
