from types import SimpleNamespace

import pytest
from rich.console import Console

import clearwing.ui.commands.interactive as interactive
from clearwing.agent.graph import build_react_graph
from clearwing.agent.tooling import interrupt, tool
from clearwing.data.memory.session_store import SessionStore


class ScriptedLLM:
    provider_name = "stub"
    context_budget_tokens = None

    def __init__(self, script):
        self.script = list(script)
        self.seen = []

    async def achat_stream(self, messages, system, tools, on_text_delta=None):
        self.seen.append(list(messages))
        text, calls = self.script.pop(0) if self.script else ("done", [])
        return SimpleNamespace(
            first_text=text,
            texts=[text],
            usage=None,
            tool_calls=calls,
            provider_model_name="stub",
        )


def _call(name, call_id, **args):
    return SimpleNamespace(fn_name=name, call_id=call_id, fn_arguments=args)


def _graph(llm, tools=()):
    return build_react_graph(
        llm,
        list(tools),
        lambda state: "system",
        enable_cost_tracker=False,
        enable_episodic_memory=False,
        enable_audit=False,
        enable_knowledge_graph=False,
        enable_context_summarizer=False,
    )


def _args(**overrides):
    values = {
        "resume": None,
        "target": None,
        "model": "claude-sonnet-4-6",
        "no_tui": True,
        "base_url": None,
        "api_key": None,
        "cost_limit": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_legacy_resume_restores_conversation(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
    session = SessionStore().create("", "claude-sonnet-4-6")
    session.messages = [
        {"role": "user", "content": "remember bluebird"},
        {"role": "assistant", "content": "noted"},
    ]
    SessionStore().save(session)
    llm = ScriptedLLM([("answered", [])])
    monkeypatch.setattr(interactive, "create_agent", lambda **kwargs: _graph(llm))
    answers = iter(["what should you remember?", "quit"])
    monkeypatch.setattr(interactive.Prompt, "ask", lambda *args, **kwargs: next(answers))

    interactive._run_interactive_legacy(
        SimpleNamespace(console=Console(width=120)),
        _args(),
        SessionStore().load(session.session_id),
    )

    contents = [str(message.content) for message in llm.seen[0]]
    assert contents == ["remember bluebird", "noted", "what should you remember?"]


def test_unknown_session_prints_not_found(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    console = Console(record=True)

    interactive.handle(SimpleNamespace(console=console), _args(resume="deadbeef"))

    assert "Session deadbeef not found." in console.export_text()


def test_corrupt_session_prints_clean_message(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    store = SessionStore()
    (store.BASE_DIR / "deadbeef.json").write_text("{broken", encoding="utf-8")
    console = Console(record=True)

    interactive.handle(SimpleNamespace(console=console), _args(resume="deadbeef"))

    assert "Session deadbeef is corrupt." in console.export_text()


@pytest.mark.parametrize("cancel_error", [KeyboardInterrupt, EOFError])
def test_cancelled_approval_is_consumed(cancel_error, monkeypatch):
    ran = []

    @tool
    def risky(label: str) -> dict:
        """A test action that requires approval."""
        approved = interrupt(f"Approve {label}?")
        if approved:
            ran.append(label)
        return {"approved": approved}

    llm = ScriptedLLM(
        [
            ("", [_call("risky", "call-1", label="DROP")]),
            ("cancelled", []),
        ]
    )
    graph = _graph(llm, [risky])
    monkeypatch.setattr(interactive, "create_agent", lambda **kwargs: graph)
    answers = iter(["go", "quit"])
    monkeypatch.setattr(interactive.Prompt, "ask", lambda *args, **kwargs: next(answers))

    def cancel(*args, **kwargs):
        raise cancel_error

    monkeypatch.setattr(interactive.Confirm, "ask", cancel)
    interactive._run_interactive_legacy(
        SimpleNamespace(console=Console(width=120)),
        _args(),
    )

    state = graph.get_state({"configurable": {"thread_id": "interactive-session"}})
    assert ran == []
    assert not state.next


def test_session_id_cannot_escape_store(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
    store = SessionStore()
    session = store.create("", "m")
    session.session_id = "../outside/leaked"

    with pytest.raises(ValueError):
        store.save(session)
    with pytest.raises(ValueError):
        store.load("../outside/leaked")
    with pytest.raises(ValueError):
        store.delete("../outside/leaked")


def test_tui_exit_does_not_clobber_saved_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
    store = SessionStore()
    session = store.create("", "m")

    class FakeApp:
        def __init__(self, **kwargs):
            pass

        def run(self):
            latest = SessionStore().load(session.session_id)
            latest.vulnerabilities = [{"title": "saved during TUI run"}]
            SessionStore().save(latest)

    monkeypatch.setattr(interactive, "ClearwingApp", FakeApp)
    interactive._run_tui(SimpleNamespace(), _args(model="m", no_tui=False), session)

    saved = store.load(session.session_id)
    assert saved.status == "completed"
    assert saved.vulnerabilities == [{"title": "saved during TUI run"}]
