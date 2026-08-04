import json
from pathlib import Path

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.mock import MockTransport

FIXTURE = Path(__file__).parent / "fixtures" / "system_status_response.json"


def _client_with_fixture() -> PfSenseClient:
    transport = MockTransport()
    body = json.loads(FIXTURE.read_text())
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client)


def test_get_system_status_excludes_netgate_id_by_default():
    client = _client_with_fixture()
    status = client.get_system_status()
    assert status.netgate_id is None
    assert status.platform == "Netgate pfSense Plus"
    assert status.cpu_count == 4


def test_get_system_status_includes_netgate_id_when_requested():
    client = _client_with_fixture()
    status = client.get_system_status(include_identifying_metadata=True)
    assert status.netgate_id == "ANONYMIZED0000000000"
