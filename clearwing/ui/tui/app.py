"""Main Textual TUI application for Clearwing."""

from __future__ import annotations

import asyncio
import json
import logging

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header

from clearwing.core.events import EventBus, EventType
from clearwing.data.memory.session_store import SessionStore

from .components.activity_feed import ActivityFeed
from .components.input_bar import InputBar
from .components.progress_panel import ProgressPanel
from .components.status_bar import StatusBar
from .screens.help_screen import HelpScreen
from .screens.quit_screen import QuitScreen

logger = logging.getLogger(__name__)

_FINDING_KEYS = (
    "open_ports",
    "services",
    "vulnerabilities",
    "exploit_results",
    "os_info",
    "flags_found",
)


class ClearwingApp(App):
    """Textual TUI for the Clearwing autonomous agent."""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 1;
        grid-rows: auto 1fr auto auto auto;
    }
    ActivityFeed {
        height: 1fr;
        border: solid $accent;
        scrollbar-gutter: stable;
    }
    StatusBar {
        height: 3;
        dock: bottom;
    }
    InputBar {
        height: auto;
        dock: bottom;
    }
    """

    BINDINGS = [
        Binding("ctrl+p", "toggle_pause", "Pause/Resume"),
        Binding("ctrl+q", "request_quit", "Quit"),
        Binding("f1", "show_help", "Help"),
        Binding("up", "feed_scroll_up", "Scroll Up", show=False, priority=True),
        Binding("down", "feed_scroll_down", "Scroll Down", show=False, priority=True),
        Binding("pageup", "feed_page_up", "Page Up", show=False, priority=True),
        Binding("pagedown", "feed_page_down", "Page Down", show=False, priority=True),
        Binding("home", "feed_home", "Scroll Top", show=False, priority=True),
        Binding("end", "feed_end", "Scroll Bottom", show=False, priority=True),
    ]

    def __init__(
        self, target=None, model="claude-sonnet-4-6", session_id=None, base_url=None, api_key=None
    ):
        super().__init__()
        self.target = target
        self.model = model
        self.session_id = session_id
        self.base_url = base_url
        self.api_key = api_key
        self.paused = False
        self._user_input_queue: asyncio.Queue[str] = asyncio.Queue()
        self._approval_queue: asyncio.Queue[str] = asyncio.Queue()
        self._agent_graph = None
        self._awaiting_approval = False
        self._conversation: list[dict] = []
        self._resume_gate = asyncio.Event()
        self._resume_gate.set()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield ActivityFeed()
        yield ProgressPanel()
        yield StatusBar(target=self.target, session_id=self.session_id)
        yield InputBar()
        yield Footer()

    def on_mount(self) -> None:
        """Subscribe to EventBus events and start the agent loop."""
        self._bus_mounted = True
        self.query_one(InputBar).focus()

        # Create the agent graph and start the background loop
        from clearwing.agent.graph import create_agent

        self._agent_graph = create_agent(
            model_name=self.model,
            session_id=self.session_id,
            base_url=self.base_url,
            api_key=self.api_key,
        )
        self._agent_config = {"configurable": {"thread_id": self.session_id or "tui-session"}}

        feed = self.query_one(ActivityFeed)
        if self.target:
            feed.add_message(f"Target: {self.target}", "info")
        feed.add_message(f"Model: {self.model}", "info")
        feed.add_message("Agent ready. Type a message to begin.", "success")

        self.run_worker(self._agent_loop(), exclusive=True)

        bus = EventBus()
        bus.subscribe(EventType.MESSAGE, self._on_bus_message)
        bus.subscribe(EventType.TOOL_START, self._on_bus_tool_start)
        bus.subscribe(EventType.TOOL_RESULT, self._on_bus_tool_result)
        bus.subscribe(EventType.FLAG_FOUND, self._on_bus_flag_found)
        bus.subscribe(EventType.COST_UPDATE, self._on_bus_cost_update)
        bus.subscribe(EventType.ERROR, self._on_bus_error)
        bus.subscribe(EventType.APPROVAL_NEEDED, self._on_bus_approval_needed)
        bus.subscribe(EventType.CAMPAIGN_PROGRESS, self._on_bus_campaign_progress)
        bus.subscribe(EventType.SOURCEHUNT_STAGE, self._on_bus_sourcehunt_stage)
        bus.subscribe(EventType.HUNT_PROGRESS, self._on_bus_hunt_progress)
        bus.subscribe(EventType.VALIDATION_RESULT, self._on_bus_validation_result)
        bus.subscribe(EventType.DISCLOSURE_UPDATE, self._on_bus_disclosure_update)
        bus.subscribe(EventType.BENCHMARK_PROGRESS, self._on_bus_benchmark_progress)
        bus.subscribe(EventType.EVAL_PROGRESS, self._on_bus_eval_progress)
        bus.subscribe(EventType.FINDING_RECORDED, self._on_bus_finding_recorded)

    def on_unmount(self) -> None:
        """Unsubscribe from EventBus before the app tears down."""
        self._save_findings()
        self._bus_mounted = False
        bus = EventBus()
        bus.unsubscribe(EventType.MESSAGE, self._on_bus_message)
        bus.unsubscribe(EventType.TOOL_START, self._on_bus_tool_start)
        bus.unsubscribe(EventType.TOOL_RESULT, self._on_bus_tool_result)
        bus.unsubscribe(EventType.FLAG_FOUND, self._on_bus_flag_found)
        bus.unsubscribe(EventType.COST_UPDATE, self._on_bus_cost_update)
        bus.unsubscribe(EventType.ERROR, self._on_bus_error)
        bus.unsubscribe(EventType.APPROVAL_NEEDED, self._on_bus_approval_needed)
        bus.unsubscribe(EventType.CAMPAIGN_PROGRESS, self._on_bus_campaign_progress)
        bus.unsubscribe(EventType.SOURCEHUNT_STAGE, self._on_bus_sourcehunt_stage)
        bus.unsubscribe(EventType.HUNT_PROGRESS, self._on_bus_hunt_progress)
        bus.unsubscribe(EventType.VALIDATION_RESULT, self._on_bus_validation_result)
        bus.unsubscribe(EventType.DISCLOSURE_UPDATE, self._on_bus_disclosure_update)
        bus.unsubscribe(EventType.BENCHMARK_PROGRESS, self._on_bus_benchmark_progress)
        bus.unsubscribe(EventType.EVAL_PROGRESS, self._on_bus_eval_progress)
        bus.unsubscribe(EventType.FINDING_RECORDED, self._on_bus_finding_recorded)

    # ------------------------------------------------------------------
    # Event handlers — bridge from background threads into the TUI
    # ------------------------------------------------------------------

    def _safe_call_from_thread(self, callback, data):
        if not getattr(self, "_bus_mounted", False):
            return
        try:
            self.call_from_thread(callback, data)
        except RuntimeError:
            pass

    def _on_bus_message(self, data):
        self._safe_call_from_thread(self._handle_message, data)

    def _on_bus_tool_start(self, data):
        self._safe_call_from_thread(self._handle_tool_start, data)

    def _on_bus_tool_result(self, data):
        self._safe_call_from_thread(self._handle_tool_result, data)

    def _on_bus_flag_found(self, data):
        self._safe_call_from_thread(self._handle_flag_found, data)

    def _on_bus_cost_update(self, data):
        self._safe_call_from_thread(self._handle_cost_update, data)

    def _on_bus_error(self, data):
        self._safe_call_from_thread(self._handle_error, data)

    def _on_bus_approval_needed(self, data):
        self._safe_call_from_thread(self._handle_approval, data)

    def _on_bus_campaign_progress(self, data):
        self._safe_call_from_thread(self._handle_campaign_progress, data)

    def _on_bus_sourcehunt_stage(self, data):
        self._safe_call_from_thread(self._handle_sourcehunt_stage, data)

    def _on_bus_hunt_progress(self, data):
        self._safe_call_from_thread(self._handle_hunt_progress, data)

    def _on_bus_validation_result(self, data):
        self._safe_call_from_thread(self._handle_validation_result, data)

    def _on_bus_disclosure_update(self, data):
        self._safe_call_from_thread(self._handle_disclosure_update, data)

    def _on_bus_benchmark_progress(self, data):
        self._safe_call_from_thread(self._handle_benchmark_progress, data)

    def _on_bus_eval_progress(self, data):
        self._safe_call_from_thread(self._handle_eval_progress, data)

    def _on_bus_finding_recorded(self, data):
        self._safe_call_from_thread(self._handle_finding_recorded, data)

    # ------------------------------------------------------------------
    # Actual UI update methods (run on the Textual event loop thread)
    # ------------------------------------------------------------------

    def _handle_message(self, data):
        feed = self.query_one(ActivityFeed)
        msg_type = data.get("msg_type", "info") if isinstance(data, dict) else "info"
        content = data.get("content", str(data)) if isinstance(data, dict) else str(data)
        feed.add_message(content, msg_type)

    def _handle_tool_start(self, data):
        feed = self.query_one(ActivityFeed)
        tool_name = data.get("tool_name", "unknown") if isinstance(data, dict) else "unknown"
        feed.add_tool_start(tool_name, data)

    def _handle_tool_result(self, data):
        feed = self.query_one(ActivityFeed)
        tool_name = data.get("tool_name", "unknown") if isinstance(data, dict) else "unknown"
        feed.add_tool_result(tool_name, data)

    def _handle_flag_found(self, data):
        feed = self.query_one(ActivityFeed)
        flag = data.get("flag", str(data)) if isinstance(data, dict) else str(data)
        context = data.get("context", "") if isinstance(data, dict) else ""
        feed.add_flag(flag, context)

    def _handle_cost_update(self, data):
        bar = self.query_one(StatusBar)
        if isinstance(data, dict):
            bar.update_cost(data.get("tokens", 0), data.get("cost_usd", 0.0))

    def _handle_error(self, data):
        feed = self.query_one(ActivityFeed)
        content = data.get("content", str(data)) if isinstance(data, dict) else str(data)
        feed.add_message(content, "error")

    def _handle_approval(self, data):
        feed = self.query_one(ActivityFeed)
        prompt = data.get("prompt", str(data)) if isinstance(data, dict) else str(data)
        feed.add_message(f"APPROVAL NEEDED: {prompt}", "warning")

    def _payload_dict(self, data) -> dict:
        if isinstance(data, dict):
            return data
        try:
            from dataclasses import asdict
            return asdict(data)
        except Exception:
            return {}

    def _handle_campaign_progress(self, data):
        self.query_one(ProgressPanel).update_campaign(data)

    def _handle_sourcehunt_stage(self, data):
        self.query_one(ProgressPanel).update_sourcehunt(data)

    def _handle_hunt_progress(self, data):
        self.query_one(ProgressPanel).update_hunt(data)

    def _handle_validation_result(self, data):
        d = self._payload_dict(data)
        self.query_one(ActivityFeed).add_validation(d)

    def _handle_disclosure_update(self, data):
        d = self._payload_dict(data)
        action = d.get("action", "update")
        fid = d.get("finding_id", "?")
        detail = d.get("detail", "")
        self.query_one(ActivityFeed).add_message(
            f"[DISCLOSURE] {fid}: {action}" + (f" — {detail}" if detail else ""),
            "warning",
        )

    def _handle_benchmark_progress(self, data):
        self.query_one(ProgressPanel).update_benchmark(data)

    def _handle_eval_progress(self, data):
        self.query_one(ProgressPanel).update_eval(data)

    def _handle_finding_recorded(self, data):
        self.query_one(ActivityFeed).add_finding(data)

    # ------------------------------------------------------------------
    # Agent loop — runs as a Textual worker in the background
    # ------------------------------------------------------------------

    async def _agent_loop(self) -> None:
        """Read from the input queue, drive the agent, display responses."""
        from clearwing.agent.runtime import Command
        from clearwing.llm.chat import extract_text_content

        initial_state: dict = {}
        if self.target:
            initial_state["target"] = self.target
        initial_state.update(self._saved_findings())
        self._conversation = self._saved_conversation()
        prior_messages = list(self._conversation)

        while True:
            user_text = await self._user_input_queue.get()
            await self._resume_gate.wait()

            feed = self.query_one(ActivityFeed)
            feed.add_message(f"You: {user_text}", "info")
            feed.add_message("Thinking...", "warning")

            new_message = {"role": "user", "content": user_text}
            self._conversation.append(new_message)
            input_msg: dict = {"messages": [*prior_messages, new_message]}
            prior_messages = []
            input_msg.update(initial_state)
            initial_state = {}

            try:
                got_response = False
                last_msg_count = 0
                async for event in self._gated(
                    self._agent_graph.astream(input_msg, self._agent_config, stream_mode="values")
                ):
                    msgs = event.get("messages", [])
                    if len(msgs) <= last_msg_count:
                        continue
                    last_msg_count = len(msgs)
                    last = msgs[-1]
                    if (
                        hasattr(last, "content")
                        and last.content
                        and getattr(last, "type", None) == "ai"
                        and not getattr(last, "tool_calls", None)
                    ):
                        text = extract_text_content(last.content)
                        if text:
                            feed.add_message(text, "success")
                            self._conversation.append({"role": "assistant", "content": text})
                            got_response = True

                if not got_response:
                    feed.add_message("(no response from agent)", "warning")

                # Drain pending approvals; the agent can chain them (each
                # resume may surface another interrupt). Re-check state after
                # every resume so subsequent interrupts are prompted instead
                # of leaking a dangling tool_use when the outer loop consumes
                # the next keystroke.
                while True:
                    state = self._agent_graph.get_state(self._agent_config)
                    if not (state.next and state.tasks):
                        break
                    for task in state.tasks:
                        if hasattr(task, "interrupts") and task.interrupts:
                            for intr in task.interrupts:
                                prompt = str(intr.value)
                                feed.add_message(
                                    f"APPROVAL NEEDED: {prompt}  (type 'yes' or 'no')",
                                    "warning",
                                )
                                self._awaiting_approval = True
                                try:
                                    answer = await self._approval_queue.get()
                                finally:
                                    self._awaiting_approval = False
                                approved = answer.strip().lower() in ("yes", "y", "approve")
                                await self._resume_gate.wait()
                                resume_input = Command(resume=approved)
                                resume_msg_count = 0
                                async for ev in self._gated(
                                    self._agent_graph.astream(resume_input, self._agent_config)
                                ):
                                    msgs = ev.get("messages", [])
                                    if len(msgs) <= resume_msg_count:
                                        continue
                                    resume_msg_count = len(msgs)
                                    last = msgs[-1]
                                    if (
                                        hasattr(last, "content")
                                        and last.content
                                        and getattr(last, "type", None) == "ai"
                                        and not getattr(last, "tool_calls", None)
                                    ):
                                        text = extract_text_content(last.content)
                                        if text:
                                            feed.add_message(text, "success")
                                            self._conversation.append(
                                                {"role": "assistant", "content": text}
                                            )

                self._save_findings()
            except Exception as exc:
                logger.exception("Agent loop error")
                feed.add_message(f"Error: {exc}", "error")

    # ------------------------------------------------------------------
    # Key binding actions
    # ------------------------------------------------------------------

    async def _gated(self, stream):
        """Yield from *stream*, waiting out any pause before each pull."""
        events = aiter(stream)
        while True:
            await self._resume_gate.wait()
            try:
                yield await anext(events)
            except StopAsyncIteration:
                return

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused
        if self.paused:
            self._resume_gate.clear()
        else:
            self._resume_gate.set()
        bar = self.query_one(StatusBar)
        bar.update_pause(self.paused)
        feed = self.query_one(ActivityFeed)
        if self.paused:
            feed.add_message("Agent PAUSED. Type instructions or Ctrl+P to resume.", "warning")
        else:
            feed.add_message("Agent RESUMED.", "info")

    def action_feed_scroll_up(self) -> None:
        self.query_one(ActivityFeed).scroll_up(animate=False)

    def action_feed_scroll_down(self) -> None:
        self.query_one(ActivityFeed).scroll_down(animate=False)

    def action_feed_page_up(self) -> None:
        feed = self.query_one(ActivityFeed)
        feed.scroll_relative(y=-feed.size.height, animate=False)

    def action_feed_page_down(self) -> None:
        feed = self.query_one(ActivityFeed)
        feed.scroll_relative(y=feed.size.height, animate=False)

    def action_feed_home(self) -> None:
        self.query_one(ActivityFeed).scroll_home(animate=False)

    def action_feed_end(self) -> None:
        self.query_one(ActivityFeed).scroll_end(animate=False)

    def action_request_quit(self) -> None:
        self.push_screen(QuitScreen())

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    # ------------------------------------------------------------------
    # Public helpers for the agent loop
    # ------------------------------------------------------------------

    async def get_user_input(self) -> str:
        """Called by agent loop to get next user input."""
        return await self._user_input_queue.get()

    def submit_input(self, text: str) -> None:
        """Called by InputBar when user submits."""
        if self._awaiting_approval:
            self._approval_queue.put_nowait(text)
        else:
            self._user_input_queue.put_nowait(text)

    def _saved_findings(self) -> dict:
        if not self.session_id:
            return {}
        try:
            session = SessionStore().load(self.session_id)
        except Exception:
            logger.debug("Could not load session %s", self.session_id, exc_info=True)
            return {}
        return {key: getattr(session, key) for key in _FINDING_KEYS}

    def _conversation_path(self):
        # Not *.json: SessionStore.list_sessions globs that pattern.
        return SessionStore().BASE_DIR / f"{self.session_id}.conversation"

    def _saved_conversation(self) -> list[dict]:
        if not self.session_id:
            return []
        try:
            return json.loads(self._conversation_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []

    def _save_findings(self) -> None:
        if not (self.session_id and self._agent_graph):
            return
        try:
            if self._conversation:
                self._conversation_path().write_text(
                    json.dumps(self._conversation), encoding="utf-8"
                )
            values = self._agent_graph.get_state(self._agent_config).values
            store = SessionStore()
            session = store.load(self.session_id)
            for key in _FINDING_KEYS:
                if key in values:
                    setattr(session, key, values[key])
            store.save(session)
        except Exception:
            logger.debug("Failed to save findings", exc_info=True)
