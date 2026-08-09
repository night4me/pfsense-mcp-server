from pfsense_mcp import server


def test_main_constructs_application_and_runs_it(monkeypatch):
    calls: list[str] = []

    class _StubApplication:
        def __init__(self) -> None:
            calls.append("constructed")

        def run(self) -> None:
            calls.append("run")

    monkeypatch.setattr(server, "Application", _StubApplication)

    server.main()

    assert calls == ["constructed", "run"]
