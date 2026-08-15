from pathlib import Path

from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
from pfsense_mcp.write_endpoints import WriteEndpoints


def test_production_source_cannot_import_lab_stage3_binding():
    production = Path("src/pfsense_mcp")
    imported = []
    for path in production.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "lab.stage3" in text or "lab.reconciliation" in text or "from lab" in text:
            imported.append(path)
    assert imported == []


def test_stage3_binding_does_not_activate_public_write():
    # W3 Slice 4 added the one accepted first-WRITE WriteEndpoints entry,
    # unrelated to the lab/stage3 binding this test guards against --
    # asserts the exact accepted scope, not that WriteEndpoints is empty.
    assert WriteEndpoints.active_entries() == ["FIREWALL_ALIAS_DESCRIPTION"]
    assert Capability.ALIAS_WRITE not in SUPPORTED_CAPABILITIES_THIS_BUILD
    assert Capability.FIREWALL_WRITE not in SUPPORTED_CAPABILITIES_THIS_BUILD
    assert Capability.SERVICE_WRITE not in SUPPORTED_CAPABILITIES_THIS_BUILD
