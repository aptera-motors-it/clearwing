"""TUI approval queue, pause, and resume-findings regressions."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

import clearwing.agent.graph as graph_mod
from clearwing.data.memory.session_store import SessionStore
from clearwing.ui.tui.app import ClearwingApp
from clearwing.ui.tui.components.activity_feed import ActivityFeed


class _Msg:
    def __init__(self, content, type_="ai"):
        self.content = content
        self.type = type_
        self.tool_calls = None


class FakeGraph:
    """Streams scripted events; optionally ends a turn on an approval interrupt."""

    def __init__(self, events=None, interrupt=False, values=None):
        self.events = events or [{"messages": [_Msg("one")]}]
        self.interrupt = interrupt
        self.values = values or {}
        self.astream_calls = []
        self.resume_values = []
        self.pulled = 0
        self.turn_started = asyncio.Event()

    async def astream(self, inp, config, stream_mode=None):
        self.astream_calls.append(inp)
        if hasattr(inp, "resume"):
            self.resume_values.append(inp.resume)
            self.interrupt = False
            yield {"messages": [_Msg("done")]}
            return
        self.turn_started.set()
        for ev in self.events:
            self.pulled += 1
            yield ev
            await asyncio.sleep(0)

    def get_state(self, config):
        if self.interrupt:
            task = SimpleNamespace(interrupts=[SimpleNamespace(value="run nmap?")])
            return SimpleNamespace(next=("tools",), tasks=[task], values=self.values)
        return SimpleNamespace(next=(), tasks=[], values=self.values)


async def _settle(n=20):
    for _ in range(n):
        await asyncio.sleep(0.01)


def _app(monkeypatch, graph, session_id=None):
    monkeypatch.setattr(graph_mod, "create_agent", lambda **kw: graph)
    return ClearwingApp(target="10.0.0.1", session_id=session_id)


@pytest.mark.asyncio
async def test_chat_yes_while_streaming_is_not_an_approval(monkeypatch):
    graph = FakeGraph(
        events=[{"messages": [_Msg("a")]}, {"messages": [_Msg("a"), _Msg("b")]}],
        interrupt=True,
    )
    app = _app(monkeypatch, graph)
    async with app.run_test() as pilot:
        app.submit_input("scan it")
        await asyncio.wait_for(graph.turn_started.wait(), 2)
        app.submit_input("yes")
        await _settle()
        assert graph.resume_values == []
        app.submit_input("yes")
        await _settle()
        assert graph.resume_values == [True]
        await pilot.pause()


@pytest.mark.asyncio
async def test_pause_stops_the_loop_until_resumed(monkeypatch):
    graph = FakeGraph(events=[{"messages": [_Msg("1")]}, {"messages": [_Msg("1"), _Msg("2")]}])
    app = _app(monkeypatch, graph)
    async with app.run_test() as pilot:
        app.action_toggle_pause()
        app.submit_input("scan it")
        await _settle()
        assert graph.astream_calls == []
        app.action_toggle_pause()
        await _settle()
        assert len(graph.astream_calls) == 1
        assert graph.pulled == 2
        await pilot.pause()


@pytest.mark.asyncio
async def test_pause_mid_stream_stops_further_steps(monkeypatch):
    graph = FakeGraph(events=[{"messages": [_Msg(str(i))] * (i + 1)} for i in range(5)])
    app = _app(monkeypatch, graph)
    async with app.run_test() as pilot:
        app.submit_input("scan it")
        await asyncio.wait_for(graph.turn_started.wait(), 2)
        app.action_toggle_pause()
        await _settle()
        pulled = graph.pulled
        await _settle()
        assert graph.pulled == pulled < 5
        app.action_toggle_pause()
        await _settle()
        assert graph.pulled == 5
        assert app.query_one(ActivityFeed) is not None
        await pilot.pause()


@pytest.mark.asyncio
async def test_resume_keeps_findings(monkeypatch, tmp_path):
    monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
    store = SessionStore()
    session = store.create(target="10.0.0.1", model="m")
    found = [{"port": 22}]

    graph = FakeGraph(values={"open_ports": found})
    app = _app(monkeypatch, graph, session.session_id)
    async with app.run_test():
        app.submit_input("scan it")
        await _settle()
    assert store.load(session.session_id).open_ports == found

    graph2 = FakeGraph()
    app2 = _app(monkeypatch, graph2, session.session_id)
    async with app2.run_test():
        app2.submit_input("continue")
        await _settle()
    assert graph2.astream_calls[0]["open_ports"] == found
