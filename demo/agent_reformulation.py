"""A real LLM agent that gets denied by Airlock and reformulates - live, on camera.

This is the originality claim made concrete: a blocked human retries in frustration; a blocked
*agent* reads the machine-readable verdict and fixes its own next query. Here that agent is a real
Claude model driving Airlock's MCP tools over stdio - the exact surface Claude Code or Cursor use -
with no warehouse credential of its own. It asks for something it can't have, reads the deny and its
hint, and adapts.

Nothing is scripted. The model decides what SQL to send; Airlock decides what comes back. The only
thing this file does is connect the two and print the conversation.

    python demo/agent_reformulation.py            # run it live (needs the stack + an API key)
    python demo/agent_reformulation.py --capture   # also write the transcript to examples/

Requirements, all real - if any is missing the script says which and stops, it never fakes a turn:
  * the demo stack up (`python demo/up.py`) - `airlock serve` fails fast without a live DataHub
  * `pip install airlock-gateway[agent]` for the Anthropic SDK (the `mcp` client is already a dep)
  * an Anthropic API key on the environment (ANTHROPIC_API_KEY) or an `ant auth login` profile

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
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "demo" / "airlock.yaml"
MODEL = "claude-opus-4-8"
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

    def save(self, path: Path) -> None:
        header = (
            "# Agent reformulation - captured from a live run\n\n"
            "A real Claude model, connected to Airlock's MCP tools over stdio with no warehouse "
            "credential of its own, is denied and reformulates. Generated by "
            "`python demo/agent_reformulation.py --capture` against the live stack - not written "
            "by hand.\n"
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


async def _run(capture: bool) -> int:
    try:
        from anthropic import AsyncAnthropic
        from mcp.client.stdio import stdio_client

        from mcp import ClientSession, StdioServerParameters
    except ImportError:
        print(
            "This demo needs the Anthropic SDK: pip install airlock-gateway[agent]\n"
            "(the MCP client ships with Airlock already).",
            file=sys.stderr,
        )
        return 2

    _load_env()
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

    client = AsyncAnthropic()  # resolves the key from env or an `ant auth login` profile
    try:
        async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = [
                {"name": t.name, "description": t.description or "", "input_schema": t.inputSchema}
                for t in listed.tools
            ]

            transcript.rule("The task the agent was given")
            transcript.speaker("USER", "green")
            transcript.text(TASK)

            messages: list[dict[str, Any]] = [{"role": "user", "content": TASK}]
            for _ in range(MAX_ITERATIONS):
                response = await client.messages.create(
                    model=MODEL, max_tokens=4096, system=SYSTEM, tools=tools, messages=messages
                )
                if response.stop_reason == "refusal":
                    transcript.speaker("AGENT", "red")
                    transcript.text("(the model declined this request)")
                    break

                for block in response.content:
                    if block.type == "text" and block.text.strip():
                        transcript.speaker("AGENT", "cyan")
                        transcript.text(block.text.strip())

                tool_uses = [b for b in response.content if b.type == "tool_use"]
                if not tool_uses:
                    break  # end_turn: the agent has its final answer

                messages.append({"role": "assistant", "content": response.content})
                results: list[dict[str, Any]] = []
                for use in tool_uses:
                    sql = use.input.get("sql") if isinstance(use.input, dict) else None
                    transcript.speaker(f"AGENT -> {use.name}", "yellow")
                    if sql:
                        transcript.sql(sql)
                    else:
                        transcript.text(json.dumps(use.input))
                    result = await session.call_tool(use.name, dict(use.input))
                    payload, parsed = _tool_result_text(result)
                    transcript.speaker("AIRLOCK", "magenta")
                    if parsed is not None:
                        transcript.envelope(parsed)
                    else:
                        transcript.text(payload)
                    results.append(
                        {"type": "tool_result", "tool_use_id": use.id, "content": payload}
                    )
                messages.append({"role": "user", "content": results})
    except Exception as exc:  # a demo-only script: one clear line beats a stdio traceback
        print(f"\nCould not complete the live run: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "Check that the stack is up (`python demo/up.py`) and an Anthropic API key is set.",
            file=sys.stderr,
        )
        return 1

    if capture:
        out = REPO / "examples" / "agent_reformulation.md"
        transcript.save(out)
        print(f"\nTranscript written to {out.relative_to(REPO)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--capture", action="store_true", help="write the transcript to examples/ after the run"
    )
    args = parser.parse_args()
    return asyncio.run(_run(args.capture))


if __name__ == "__main__":
    raise SystemExit(main())
