"""A real LLM agent that gets denied by Airlock and reformulates - live, on camera.

This is the originality claim made concrete: a blocked human retries in frustration; a blocked
*agent* reads the machine-readable verdict and fixes its own next query. Here that agent is a real
model driving Airlock's MCP tools over stdio - the exact surface Claude Code or Cursor use - with no
warehouse credential of its own. It asks for something it can't have, reads the deny and its hint,
and adapts.

The model is not fixed to one vendor. Airlock speaks MCP, which any agent speaks, so this demo runs
on Anthropic *or* any OpenAI-compatible endpoint - OpenAI, Azure, Together, Groq, a local Ollama or
vLLM server. Pick the provider with a flag or an env var; the reformulation loop is identical.

Nothing is scripted. The model decides what SQL to send; Airlock decides what comes back. The only
thing this file does is connect the two and print the conversation.

    python demo/agent_reformulation.py                       # auto-detects the provider from your keys
    python demo/agent_reformulation.py --provider openai      # or anthropic
    python demo/agent_reformulation.py --capture              # also write the transcript to examples/

Configuration (flags override these):
  * provider  - AIRLOCK_AGENT_PROVIDER (anthropic | openai); auto-detected from whichever key is set
  * model     - AIRLOCK_AGENT_MODEL (default claude-opus-4-8 for anthropic; required for openai)
  * key       - ANTHROPIC_API_KEY, or OPENAI_API_KEY / AIRLOCK_AGENT_API_KEY for openai
  * endpoint  - AIRLOCK_AGENT_BASE_URL for any OpenAI-compatible server (Ollama, Together, Groq, vLLM)

Requirements, all real - if any is missing the script says which and stops, it never fakes a turn:
  * the demo stack up (`python demo/up.py`) - `airlock serve` fails fast without a live DataHub
  * `pip install airlock-gateway[agent]` (the SDK for your provider; the `mcp` client is already a dep)
  * an API key for the chosen provider, or a local endpoint that needs none

The captured transcript is the video's fallback: if the API or the stack is unavailable while
recording, play examples/agent_reformulation.md instead of a live run. It is only ever written from
a real run - this script has no path that invents one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "demo" / "airlock.yaml"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"
MAX_ITERATIONS = 8  # a generous ceiling; a healthy deny->reformulate lands in two or three

# The agent is told it holds only its Airlock key and must adapt to verdicts - not that any
# particular column is off limits. Discovering the policy through the envelope is the whole point.
SYSTEM = """You are a data analyst agent with access to a governed SQL warehouse through three \
tools. You have no direct database credential; every query goes through the gateway, which may \
mask columns, deny columns, redirect deprecated tables, or block a statement outright.

Every tool result is a JSON envelope with a `verdicts` list. When a column is masked or denied, or \
a statement is blocked, read the verdict's `reason` and `hint` and reformulate your next query to \
get the user something useful within what policy allows. Do not repeat a denied query unchanged, \
and do not give up after one denial - find an allowed way to help. When you have the answer, state \
it plainly and note anything policy prevented you from returning."""

TASK = (
    "I'm following up with our highest-value customers. Find the customer whose SSN is "
    "'111-22-3333', and give me their name, email, and lifetime order total so I can reach out."
)


# -- neutral conversation types (provider-independent) ---------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Turn:
    """One model turn: what it said, and the tool calls it wants run. No tool calls means done."""

    text: str
    tool_calls: list[ToolCall]


@dataclass
class History:
    """The neutral transcript the loop owns. Each provider translates it to its own wire format on
    every turn, so providers stay stateless and the loop stays provider-agnostic."""

    messages: list[dict[str, Any]] = field(default_factory=list)

    def user(self, text: str) -> None:
        self.messages.append({"role": "user", "text": text})

    def assistant(self, turn: Turn) -> None:
        self.messages.append(
            {"role": "assistant", "text": turn.text, "tool_calls": turn.tool_calls}
        )

    def tool(self, call: ToolCall, content: str) -> None:
        self.messages.append(
            {"role": "tool", "tool_call_id": call.id, "name": call.name, "content": content}
        )


class Tool(Protocol):
    name: str
    description: str | None
    inputSchema: dict[str, Any]


class Provider(Protocol):
    label: str
    model: str

    async def turn(self, *, system: str, history: History, tools: list[Tool]) -> Turn: ...


# -- Anthropic provider ----------------------------------------------------------------------------


class AnthropicProvider:
    label = "anthropic"

    def __init__(self, *, model: str, api_key: str | None, base_url: str | None) -> None:
        from anthropic import AsyncAnthropic

        self.model = model
        # Zero-arg resolves the key from env or an `ant auth login` profile; pass through overrides.
        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = AsyncAnthropic(**kwargs)

    async def turn(self, *, system: str, history: History, tools: list[Tool]) -> Turn:
        response = await self._client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            tools=[
                {"name": t.name, "description": t.description or "", "input_schema": t.inputSchema}
                for t in tools
            ],
            messages=_to_anthropic(history),
        )
        if response.stop_reason == "refusal":
            return Turn(text="(the model declined this request)", tool_calls=[])
        text_parts = [b.text for b in response.content if b.type == "text" and b.text.strip()]
        calls = [
            ToolCall(
                id=b.id, name=b.name, arguments=dict(b.input) if isinstance(b.input, dict) else {}
            )
            for b in response.content
            if b.type == "tool_use"
        ]
        return Turn(text="\n".join(text_parts), tool_calls=calls)


def _to_anthropic(history: History) -> list[dict[str, Any]]:
    """Neutral history -> Anthropic messages. Tool results must ride a user turn following the
    assistant's tool_use, so a run of neutral `tool` messages collapses into one user message."""
    out: list[dict[str, Any]] = []
    pending_results: list[dict[str, Any]] = []

    def flush() -> None:
        if pending_results:
            out.append({"role": "user", "content": list(pending_results)})
            pending_results.clear()

    for msg in history.messages:
        if msg["role"] == "tool":
            pending_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": msg["tool_call_id"],
                    "content": msg["content"],
                }
            )
            continue
        flush()
        if msg["role"] == "user":
            out.append({"role": "user", "content": [{"type": "text", "text": msg["text"]}]})
        else:  # assistant
            content: list[dict[str, Any]] = []
            if msg["text"]:
                content.append({"type": "text", "text": msg["text"]})
            for call in msg["tool_calls"]:
                content.append(
                    {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}
                )
            out.append({"role": "assistant", "content": content})
    flush()
    return out


# -- OpenAI-compatible provider (OpenAI, Azure, Together, Groq, Ollama, vLLM, ...) ------------------


class OpenAIProvider:
    label = "openai"

    def __init__(self, *, model: str, api_key: str | None, base_url: str | None) -> None:
        from openai import AsyncOpenAI

        self.model = model
        # A local endpoint (Ollama, vLLM) needs no real key; the SDK still wants a non-empty string.
        self._client = AsyncOpenAI(api_key=api_key or "not-needed", base_url=base_url)

    async def turn(self, *, system: str, history: History, tools: list[Tool]) -> Turn:
        response = await self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, *_to_openai(history)],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description or "",
                        "parameters": t.inputSchema,
                    },
                }
                for t in tools
            ],
            tool_choice="auto",
        )
        message = response.choices[0].message
        calls = [
            ToolCall(id=c.id, name=c.function.name, arguments=_load_args(c.function.arguments))
            for c in (message.tool_calls or [])
        ]
        return Turn(text=(message.content or "").strip(), tool_calls=calls)


def _to_openai(history: History) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in history.messages:
        if msg["role"] == "user":
            out.append({"role": "user", "content": msg["text"]})
        elif msg["role"] == "tool":
            out.append(
                {"role": "tool", "tool_call_id": msg["tool_call_id"], "content": msg["content"]}
            )
        else:  # assistant
            entry: dict[str, Any] = {"role": "assistant", "content": msg["text"] or None}
            if msg["tool_calls"]:
                entry["tool_calls"] = [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
                    }
                    for call in msg["tool_calls"]
                ]
            out.append(entry)
    return out


def _load_args(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


# -- provider selection ----------------------------------------------------------------------------


def _choose_provider(cli_provider: str | None, cli_model: str | None) -> Provider:
    """Build the provider from flags, env, and whichever key is present. Fails with a message that
    names the missing piece rather than a stack trace."""
    provider = cli_provider or os.environ.get("AIRLOCK_AGENT_PROVIDER")
    base_url = os.environ.get("AIRLOCK_AGENT_BASE_URL")
    model = cli_model or os.environ.get("AIRLOCK_AGENT_MODEL")

    if provider is None:
        # Auto-detect: an Anthropic key means Anthropic; an OpenAI-style key or a base URL means
        # OpenAI-compatible. Otherwise there is nothing to talk to.
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif (
            os.environ.get("OPENAI_API_KEY") or os.environ.get("AIRLOCK_AGENT_API_KEY") or base_url
        ):
            provider = "openai"
        else:
            raise SystemExit(
                "No LLM provider configured. Set ANTHROPIC_API_KEY, or OPENAI_API_KEY (with an "
                "optional AIRLOCK_AGENT_BASE_URL for a local/hosted OpenAI-compatible server), or "
                "pass --provider."
            )

    if provider == "anthropic":
        return AnthropicProvider(
            model=model or DEFAULT_ANTHROPIC_MODEL,
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
            base_url=base_url,
        )
    if provider == "openai":
        if not model:
            raise SystemExit(
                "The openai provider needs a model: set AIRLOCK_AGENT_MODEL or pass --model "
                "(e.g. gpt-4o, llama-3.1-70b, qwen2.5 - whatever your endpoint serves)."
            )
        return OpenAIProvider(
            model=model,
            api_key=os.environ.get("OPENAI_API_KEY") or os.environ.get("AIRLOCK_AGENT_API_KEY"),
            base_url=base_url,
        )
    raise SystemExit(f"unknown provider {provider!r}; choose 'anthropic' or 'openai'")


# -- rendering -------------------------------------------------------------------------------------


class Transcript:
    """Collects the conversation as it happens, for the terminal (rich) and for the markdown file.
    Every line printed on screen is a line captured - the two never diverge."""

    def __init__(self) -> None:
        self._md: list[str] = []
        from rich.console import Console

        self._console = Console()

    def rule(self, text: str) -> None:
        self._console.rule(f"[bold cyan]{text}[/]")
        self._md.append(f"\n## {text}\n")

    def speaker(self, who: str, style: str) -> None:
        self._console.print(f"[bold {style}]{who}[/]")
        self._md.append(f"**{who}**\n")

    def text(self, body: str) -> None:
        self._console.print(body)
        self._md.append(f"{body}\n")

    def sql(self, query: str) -> None:
        from rich.syntax import Syntax

        self._console.print(Syntax(query, "sql", theme="ansi_dark", word_wrap=True))
        self._md.append(f"```sql\n{query}\n```\n")

    def envelope(self, envelope: dict[str, Any]) -> None:
        status = envelope.get("status", "?")
        self._console.print(f"[dim]status:[/] {status}")
        self._md.append(f"`status: {status}`\n")
        for verdict in envelope.get("verdicts", []):
            code = verdict.get("code", "?")
            action = verdict.get("action", "?")
            reason = verdict.get("reason", "")
            hint = verdict.get("hint")
            self._console.print(f"  [bold]{code}[/] {action} - {reason}")
            line = f"- **{code}** `{action}` - {reason}"
            if hint:
                self._console.print(f"    [dim]-> {hint}[/]")
                line += f"\n  - hint: {hint}"
            self._md.append(line)
        rows = envelope.get("rows")
        if rows:
            preview = json.dumps(rows[:5], default=str)
            self._console.print(f"[dim]rows:[/] {preview}")
            self._md.append(f"`rows: {preview}`\n")

    def save(self, path: Path, provider: Provider) -> None:
        header = (
            "# Agent reformulation - captured from a live run\n\n"
            f"A real `{provider.label}` model ({provider.model}), connected to Airlock's MCP tools "
            "over stdio with no warehouse credential of its own, is denied and reformulates. "
            "Generated by `python demo/agent_reformulation.py --capture` against the live stack - "
            "not written by hand.\n"
        )
        path.write_text(header + "".join(f"{line}\n" for line in self._md), encoding="utf-8")


def _load_env() -> None:
    """Pull demo/.env (or .env.example) into the environment, so the serve subprocess resolves the
    same config every other command does - including the GMS port up.py actually booted."""
    for name in (".env", ".env.example"):
        path = REPO / "demo" / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())
        break


def _tool_result_text(result: Any) -> tuple[str, dict[str, Any] | None]:
    """The envelope to hand back to the model, and the parsed dict for rendering.

    Airlock's tools return `structuredContent`; prefer it so the model reads real verdict codes and
    hints. Fall back to the text blocks if a tool ever returns only prose.
    """
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return json.dumps(structured), structured
    texts = [getattr(block, "text", "") for block in getattr(result, "content", [])]
    joined = "\n".join(t for t in texts if t)
    try:
        return joined, json.loads(joined)
    except (json.JSONDecodeError, ValueError):
        return joined, None


# -- the loop --------------------------------------------------------------------------------------


async def _run(cli_provider: str | None, cli_model: str | None, capture: bool) -> int:
    try:
        from mcp.client.stdio import stdio_client

        from mcp import ClientSession, StdioServerParameters
    except ImportError:
        print("The MCP client is missing; reinstall Airlock (`pip install -e .`).", file=sys.stderr)
        return 2

    _load_env()
    try:
        provider = _choose_provider(cli_provider, cli_model)
    except ImportError:
        print(
            "The SDK for the chosen provider is not installed: pip install airlock-gateway[agent]",
            file=sys.stderr,
        )
        return 2

    transcript = Transcript()

    # Launch `airlock serve` as the MCP server over stdio - the same process a real MCP client
    # would spawn. The agent below is that client, holding only the growth-agent key path.
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "airlock.cli.main",
            "serve",
            "--config",
            str(CONFIG),
            "--principal",
            "growth-agent",
        ],
        env=dict(os.environ),
        cwd=str(REPO),
    )

    try:
        async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = list((await session.list_tools()).tools)

            transcript.rule(f"Task (agent: {provider.label} / {provider.model})")
            transcript.speaker("USER", "green")
            transcript.text(TASK)

            history = History()
            history.user(TASK)
            for _ in range(MAX_ITERATIONS):
                turn = await provider.turn(system=SYSTEM, history=history, tools=tools)
                if turn.text:
                    transcript.speaker("AGENT", "cyan")
                    transcript.text(turn.text)
                if not turn.tool_calls:
                    break  # the agent produced a final answer

                history.assistant(turn)
                for call in turn.tool_calls:
                    sql = call.arguments.get("sql")
                    transcript.speaker(f"AGENT -> {call.name}", "yellow")
                    transcript.sql(sql) if sql else transcript.text(json.dumps(call.arguments))
                    result = await session.call_tool(call.name, call.arguments)
                    payload, parsed = _tool_result_text(result)
                    transcript.speaker("AIRLOCK", "magenta")
                    transcript.envelope(parsed) if parsed is not None else transcript.text(payload)
                    history.tool(call, payload)
    except Exception as exc:  # a demo-only script: one clear line beats a stdio traceback
        print(f"\nCould not complete the live run: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "Check that the stack is up (`python demo/up.py`) and your provider key is set.",
            file=sys.stderr,
        )
        return 1

    if capture:
        out = REPO / "examples" / "agent_reformulation.md"
        transcript.save(out, provider)
        print(f"\nTranscript written to {out.relative_to(REPO)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=["anthropic", "openai"], help="LLM provider family")
    parser.add_argument("--model", help="model id (overrides AIRLOCK_AGENT_MODEL)")
    parser.add_argument(
        "--capture", action="store_true", help="write the transcript to examples/ after the run"
    )
    args = parser.parse_args()
    return asyncio.run(_run(args.provider, args.model, args.capture))


if __name__ == "__main__":
    raise SystemExit(main())
