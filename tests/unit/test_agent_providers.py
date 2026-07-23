"""The vendor-neutral translation in demo/agent_reformulation.py.

The demo agent runs on Anthropic or any OpenAI-compatible endpoint. What makes that work is one
neutral conversation history translated to each provider's wire format every turn - and the two
formats disagree in exactly the place a tool-use loop lives: Anthropic carries tool results in a
following user turn, OpenAI carries them in dedicated `tool` messages. These tests pin both
translations and the provider-selection logic; the live API calls are out of scope here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "demo" / "agent_reformulation.py"


@pytest.fixture
def agent():
    spec = importlib.util.spec_from_file_location("agent_reformulation", _PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Register before exec: a slotted dataclass under `from __future__ import annotations` resolves
    # its field types via sys.modules[cls.__module__], which must exist while the class body runs.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _conversation(agent):
    """A history with the shape the loop produces: user -> assistant(tool_call) -> tool_result."""
    h = agent.History()
    h.user("find customer by ssn")
    call = agent.ToolCall(id="call_1", name="warehouse_run_query", arguments={"sql": "SELECT ssn"})
    h.assistant(agent.Turn(text="I'll query that.", tool_calls=[call]))
    h.tool(call, '{"status": "denied"}')
    return h, call


def test_anthropic_puts_tool_results_in_a_following_user_turn(agent) -> None:
    history, _ = _conversation(agent)
    msgs = agent._to_anthropic(history)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    # the assistant turn carries text + a tool_use block
    kinds = [b["type"] for b in msgs[1]["content"]]
    assert "text" in kinds and "tool_use" in kinds
    # the tool result rides the trailing user turn as a tool_result, keyed to the call id
    result = msgs[2]["content"][0]
    assert result["type"] == "tool_result"
    assert result["tool_use_id"] == "call_1"


def test_anthropic_collapses_parallel_tool_results_into_one_user_turn(agent) -> None:
    # Two tool results in a row must become one user message with two blocks, or the API rejects
    # the ordering.
    h = agent.History()
    h.user("q")
    a = agent.ToolCall(id="a", name="t", arguments={})
    b = agent.ToolCall(id="b", name="t", arguments={})
    h.assistant(agent.Turn(text="", tool_calls=[a, b]))
    h.tool(a, "ra")
    h.tool(b, "rb")
    msgs = agent._to_anthropic(h)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assert len(msgs[2]["content"]) == 2  # both results in one user turn


def test_openai_uses_dedicated_tool_messages(agent) -> None:
    history, _ = _conversation(agent)
    msgs = agent._to_openai(history)
    assert [m["role"] for m in msgs] == ["user", "assistant", "tool"]
    # the assistant message carries an OpenAI tool_calls array with JSON-encoded arguments
    tool_call = msgs[1]["tool_calls"][0]
    assert tool_call["function"]["name"] == "warehouse_run_query"
    assert '"sql"' in tool_call["function"]["arguments"]
    # the tool result is keyed to the same id
    assert msgs[2]["tool_call_id"] == "call_1"


def test_load_args_tolerates_bad_json(agent) -> None:
    assert agent._load_args('{"sql": "x"}') == {"sql": "x"}
    assert agent._load_args("not json") == {}
    assert agent._load_args(None) == {}
    assert agent._load_args("[1, 2]") == {}  # a non-object is not usable tool input


def test_provider_autodetects_anthropic_from_its_key(agent, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
    monkeypatch.delenv("AIRLOCK_AGENT_PROVIDER", raising=False)
    monkeypatch.setattr(agent, "AnthropicProvider", _fake_provider("anthropic"))
    assert agent._choose_provider(None, None).label == "anthropic"


def test_provider_autodetects_openai_from_a_base_url(agent, monkeypatch) -> None:
    # A local Ollama/vLLM server: no cloud key, just an endpoint.
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AIRLOCK_AGENT_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AIRLOCK_AGENT_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setattr(agent, "OpenAIProvider", _fake_provider("openai"))
    assert agent._choose_provider(None, "llama3").label == "openai"


def test_openai_provider_requires_a_model(agent, monkeypatch) -> None:
    for var in ("ANTHROPIC_API_KEY", "AIRLOCK_AGENT_MODEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-xxx")
    with pytest.raises(SystemExit, match="model"):
        agent._choose_provider("openai", None)


def test_no_provider_configured_is_a_named_exit(agent, monkeypatch) -> None:
    for var in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AIRLOCK_AGENT_API_KEY",
        "AIRLOCK_AGENT_BASE_URL",
        "AIRLOCK_AGENT_PROVIDER",
    ):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(SystemExit, match="No LLM provider"):
        agent._choose_provider(None, None)


def _fake_provider(label: str):
    class _Fake:
        def __init__(self, **_kwargs: object) -> None:
            self.label = label
            self.model = "test"

    return _Fake
