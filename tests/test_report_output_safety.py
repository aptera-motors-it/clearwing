import asyncio
from types import SimpleNamespace

from clearwing.agent.tools.meta import reporting_tools, sourcehunt_tools
from clearwing.reporting import ReportGenerator


def _stub_sourcehunt(monkeypatch):
    created = []

    class FakeProviderManager:
        @classmethod
        def for_endpoint(cls, endpoint):
            return object()

    class FakeRunner:
        def __init__(self, **kwargs):
            created.append(kwargs)

        def run(self):
            return SimpleNamespace(
                session_id="test",
                repo_url="repo",
                findings=[],
                verified_findings=[],
                output_paths={},
                files_ranked=0,
                files_hunted=0,
                critical_count=0,
                high_count=0,
                cost_usd=0,
            )

    monkeypatch.setattr("clearwing.providers.ProviderManager", FakeProviderManager)
    monkeypatch.setattr("clearwing.providers.resolve_llm_endpoint", lambda: object())
    monkeypatch.setattr("clearwing.sourcehunt.runner.SourceHuntRunner", FakeRunner)
    return created


def test_save_report_confines_model_selected_path(tmp_path, monkeypatch):
    reports_dir = tmp_path / "reports"
    outside = tmp_path / "outside.txt"
    monkeypatch.setattr(
        reporting_tools,
        "default_results_dir",
        lambda _: str(reports_dir),
        raising=False,
    )

    result = asyncio.run(
        reporting_tools.save_report.with_resume_decision(True)(
            {
                "filepath": str(outside),
                "format": "text",
                "scan_data": {"target": "example.test"},
            }
        )
    )

    assert "outside reports" in result.lower()
    assert not outside.exists()


def test_hunt_source_code_enforces_finite_positive_budget(tmp_path, monkeypatch):
    sourcehunt_dir = tmp_path / "sourcehunt"
    monkeypatch.setattr(
        sourcehunt_tools,
        "default_results_dir",
        lambda _: str(sourcehunt_dir),
        raising=False,
    )
    created = _stub_sourcehunt(monkeypatch)
    arguments = {
        "repo_url_or_path": str(tmp_path),
        "depth": "standard",
        "output_dir": str(sourcehunt_dir / "run"),
    }

    for invalid_budget in (0.0, float("nan")):
        asyncio.run(
            sourcehunt_tools.hunt_source_code.with_resume_decision(True)(
                {**arguments, "budget_usd": invalid_budget}
            )
        )
        assert created == []

    asyncio.run(
        sourcehunt_tools.hunt_source_code.with_resume_decision(True)(
            {**arguments, "budget_usd": 5.0}
        )
    )
    assert created[0]["budget_usd"] == 5.0


def test_quick_source_hunt_rejects_outside_output_dir(tmp_path, monkeypatch):
    sourcehunt_dir = tmp_path / "sourcehunt"
    outside = tmp_path / "outside"
    monkeypatch.setattr(
        sourcehunt_tools,
        "default_results_dir",
        lambda _: str(sourcehunt_dir),
        raising=False,
    )
    created = _stub_sourcehunt(monkeypatch)

    asyncio.run(
        sourcehunt_tools.hunt_source_code.with_resume_decision(True)(
            {
                "repo_url_or_path": str(tmp_path),
                "depth": "quick",
                "budget_usd": 5.0,
                "output_dir": str(outside),
            }
        )
    )

    assert created == []


def test_attack_graph_escapes_script_breakout_and_tooltip_html():
    payload = "</script><script>window.__XSS_BREAKOUT=1</script><script>"
    graph = {
        "nodes": [
            {
                "id": payload,
                "entity_type": "target",
                "properties": {"banner": "<img src=x onerror=window.__XSS_TOOLTIP=1>"},
            }
        ],
        "links": [],
    }

    html = ReportGenerator().generate_attack_graph(graph)

    assert payload not in html
    assert "\\u003c/script\\u003e" in html
    assert "tooltip.html(" not in html
