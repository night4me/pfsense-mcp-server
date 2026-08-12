import pytest

from lab.fault_proxy import NETWORK_INJECTABLE_SCENARIOS, FaultProxy, FaultScenario
from pfsense_mcp.transport.base import TransportConnectionError, TransportTimeoutError
from pfsense_mcp.transport.mock import MockTransport


def _proxy():
    transport = MockTransport()
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    return FaultProxy(transport), transport


def test_clean_passthrough_reaches_the_inner_transport():
    proxy, transport = _proxy()
    proxy.install(FaultScenario.CLEAN_PASSTHROUGH)

    response = proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    assert response.status_code == 200
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]


def test_connection_reset_scenario_raises_before_reaching_inner_transport():
    proxy, transport = _proxy()
    proxy.install(FaultScenario.CONNECTION_RESET_DURING_UPLOAD)

    with pytest.raises(TransportConnectionError):
        proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    assert transport.calls == []


def test_timeout_during_response_occurs_after_one_inner_send():
    proxy, transport = _proxy()
    proxy.install(FaultScenario.TIMEOUT_DURING_RESPONSE)

    with pytest.raises(TransportTimeoutError):
        proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    assert transport.calls == [("PATCH", "/api/v2/synthetic")]
    assert proxy.send_attempts == 1


def test_timeout_during_readback_raises_before_inner_transport():
    proxy, transport = _proxy()
    proxy.install(FaultScenario.TIMEOUT_DURING_READBACK)

    with pytest.raises(TransportTimeoutError):
        proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    assert transport.calls == []
    assert proxy.send_attempts == 1


def test_response_dropped_after_commit_raises_transport_timeout_error():
    """The scenario where pfSense processes the request but the response
    never arrives must be indistinguishable, at the transport boundary,
    from a timeout -- proving the executor's AMBIGUOUS classification
    (not a false success or false failure) is what actually gets driven."""

    proxy, transport = _proxy()
    proxy.install(FaultScenario.RESPONSE_DROPPED_AFTER_COMMIT)

    with pytest.raises(TransportTimeoutError):
        proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    assert transport.calls == [("PATCH", "/api/v2/synthetic")]
    assert proxy.send_attempts == 1


def test_fault_only_triggers_once_per_install():
    proxy, transport = _proxy()
    proxy.install(FaultScenario.CONNECTION_RESET_DURING_UPLOAD)

    with pytest.raises(TransportConnectionError):
        proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    # The second call after the fault has already triggered once reaches
    # the inner transport normally -- proving install() arms exactly one
    # occurrence, not a permanent failure mode.
    response = proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")
    assert response.status_code == 200
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]


def test_reinstalling_resets_the_trigger():
    proxy, transport = _proxy()
    proxy.install(FaultScenario.CONNECTION_RESET_DURING_UPLOAD)
    with pytest.raises(TransportConnectionError):
        proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    proxy.install(FaultScenario.CONNECTION_RESET_DURING_UPLOAD)
    with pytest.raises(TransportConnectionError):
        proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    assert transport.calls == []


@pytest.mark.parametrize(
    "scenario",
    [
        member
        for member in FaultScenario
        if member not in NETWORK_INJECTABLE_SCENARIOS and member is not FaultScenario.CLEAN_PASSTHROUGH
    ],
)
def test_non_network_scenarios_are_passthrough_at_the_transport_boundary(scenario):
    """Store/process-level and target/state-level scenarios are not this
    proxy's concern (I3) -- installing one must never silently swallow or
    alter a request at the transport boundary."""

    proxy, transport = _proxy()
    proxy.install(scenario)

    response = proxy.request("PATCH", "/api/v2/synthetic", body=b"{}")

    assert response.status_code == 200
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]


def test_every_tier1_lab_plan_fault_scenario_has_a_member():
    """Line-by-line cross-check against docs/TIER1_LAB_PLAN.md's "Fault
    scenarios" list (10 bullet points; two -- "timeout during response
    and during read-back" and "process restart in EXECUTING and
    ROLLING_BACK" -- each bundle two distinct sub-scenarios, expanded
    into 12 FaultScenario members below) -- nothing on that list is
    silently dropped when building the harness."""

    plan_scenarios = {
        "crash before durable acquisition": FaultScenario.CRASH_BEFORE_DURABLE_ACQUISITION,
        "crash after EXECUTING but before send": FaultScenario.CRASH_AFTER_EXECUTING_BEFORE_SEND,
        "connection reset during request upload": FaultScenario.CONNECTION_RESET_DURING_UPLOAD,
        "pfSense commits while response is dropped": FaultScenario.RESPONSE_DROPPED_AFTER_COMMIT,
        "timeout during response": FaultScenario.TIMEOUT_DURING_RESPONSE,
        "timeout during read-back": FaultScenario.TIMEOUT_DURING_READBACK,
        "process restart in EXECUTING": FaultScenario.PROCESS_RESTART_DURING_EXECUTING,
        "process restart in ROLLING_BACK": FaultScenario.PROCESS_RESTART_DURING_ROLLING_BACK,
        "target changed/reordered/deleted/duplicated between prepare and execute": (
            FaultScenario.TARGET_CHANGED_BETWEEN_PREPARE_AND_EXECUTE
        ),
        "conflicting operator edit after verification and before rollback": (
            FaultScenario.CONFLICTING_EDIT_AFTER_VERIFICATION
        ),
        "rollback response loss and partial compound compensation": FaultScenario.ROLLBACK_RESPONSE_LOST,
        "unavailable/corrupt config history and corrupt/replayed local store": (
            FaultScenario.CORRUPT_OR_REPLAYED_LOCAL_STORE
        ),
    }
    assert len(plan_scenarios) == 12
    assert len(set(plan_scenarios.values())) == 12
