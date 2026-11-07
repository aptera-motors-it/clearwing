"""Lightweight message model shared by the agent runtime and the ChatModel facade.

These dataclasses (``BaseMessage`` / ``HumanMessage`` / ``SystemMessage`` /
``AIMessage`` / ``ToolMessage``) are the *internal* message representation the
native agent runtime keeps in ``state["messages"]``. They deliberately mirror
the small slice of LangChain's message surface that Clearwing relied on
(``.content``, ``.type``, ``.tool_calls``, ``extract_text_content``) so the
runtime, operator, TUI, and specialist agents keep working without a LangChain
dependency.

The coercion helpers (``_message_to_chat_message`` / ``_coerce_chat_messages``)
translate this internal model into genai ``ChatMessage`` objects at the LLM
boundary. They live here (not in ``chat.py``) so they survive the eventual
deletion of the ``ChatModel`` facade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from genai_pyo3 import ChatMessage


def extract_text_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type in {"text", "text-plain"}:
                text = item.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
            elif item_type == "reasoning":
                reasoning = item.get("reasoning")
                if isinstance(reasoning, str) and reasoning:
                    parts.append(reasoning)
        return "\n".join(part for part in parts if part)
    return str(content)


@dataclass(slots=True)
class BaseMessage:
    content: Any
    name: str | None = None
    tool_calls: list[Any] = field(default_factory=list)
    tool_call_id: str | None = None
    role: str = field(init=False, default="user")
    type: str = field(init=False, default="base")

    @property
    def text(self) -> str:
        return extract_text_content(self.content)


@dataclass(slots=True)
class HumanMessage(BaseMessage):
    role: str = field(init=False, default="user")
    type: str = field(init=False, default="human")


@dataclass(slots=True)
class SystemMessage(BaseMessage):
    role: str = field(init=False, default="system")
    type: str = field(init=False, default="system")


@dataclass(slots=True)
class AIMessage:
    content: Any
    name: str | None = None
    tool_calls: list[Any] = field(default_factory=list)
    tool_call_id: str | None = None
    response_metadata: dict[str, Any] = field(default_factory=dict)
    type: str = field(init=False, default="ai")

    @property
    def text(self) -> str:
        return extract_text_content(self.content)


@dataclass(slots=True)
class ToolMessage(BaseMessage):
    role: str = field(init=False, default="tool")
    type: str = field(init=False, default="tool")


def _normalize_role(role: str) -> str:
    """Map a history message role onto a chat role.

    ``system`` is demoted to ``user``: history (session summaries, restored
    sessions, tool-derived text) must never reach the provider's system
    prompt, which carries only the product prompt passed separately.
    """
    normalized = role.strip().lower()
    if normalized in {"human", "user", "system"}:
        return "user"
    if normalized in {"ai", "assistant"}:
        return "assistant"
    if normalized in {"tool"}:
        return "tool"
    return normalized or "user"


def _tool_calls_to_chat_payload(tool_calls: Any) -> list[Any]:
    """Normalize an assistant message's ``tool_calls`` for ``ChatMessage``.

    Assistant turns can carry either raw genai ``ToolCall`` objects (the native
    response shape stored by the runtime) or LangChain-style dicts
    (``{"id","name","args"}``) left over from older/dict-shaped callers.
    ``ChatMessage.from_python`` accepts ``{"call_id","fn_name","fn_arguments"}``
    dicts, so translate the LangChain dict form and pass genai objects through
    untouched — preserving the ``call_id`` so tool-result turns can be paired.
    """
    normalized: list[Any] = []
    for call in tool_calls or []:
        if isinstance(call, dict):
            if "fn_name" in call or "call_id" in call:
                normalized.append(call)
            else:
                normalized.append(
                    {
                        "call_id": call.get("id", ""),
                        "fn_name": call.get("name", ""),
                        "fn_arguments": call.get("args", {}) or {},
                    }
                )
        else:
            normalized.append(call)
    return normalized


def _message_to_chat_message(message: Any) -> ChatMessage:
    if isinstance(message, str):
        return ChatMessage.from_python(message)

    if isinstance(message, ChatMessage):
        if message.role == "system":
            return ChatMessage("user", message.content)
        return message

    if isinstance(message, dict):
        normalized = dict(message)
        normalized["role"] = _normalize_role(str(message.get("role", "user")))
        normalized["content"] = extract_text_content(message.get("content", ""))
        return ChatMessage.from_python(normalized)

    if isinstance(message, AIMessage):
        payload: dict[str, Any] = {
            "role": "assistant",
            "content": message.text,
        }
        tool_calls = _tool_calls_to_chat_payload(message.tool_calls)
        if tool_calls:
            payload["tool_calls"] = tool_calls
        return ChatMessage.from_python(payload)

    payload = {
        "role": _normalize_role(getattr(message, "role", getattr(message, "type", "user"))),
        "content": extract_text_content(getattr(message, "content", message)),
        "tool_response_call_id": getattr(
            message,
            "tool_response_call_id",
            getattr(message, "tool_call_id", None),
        ),
        "tool_calls": _tool_calls_to_chat_payload(getattr(message, "tool_calls", [])),
    }
    return ChatMessage.from_python(payload)


def _coerce_chat_messages(messages: Any) -> list[ChatMessage]:
    if isinstance(messages, str | AIMessage | ChatMessage | dict):
        messages = [messages]
    return [_message_to_chat_message(message) for message in messages or []]
