"""One MCP tool call against a live `airlock serve`, for driving the gateway a turn at a time.

`demo/agent_reformulation.py` runs an autonomous loop against a hosted or local model. This is the
manual counterpart: it performs exactly one tool call over the real MCP stdio protocol and prints the
envelope, so a caller can read the verdicts, decide what to send next, and call again. That is the
same loop an agent runs, with the model's turn taken by whoever is driving.

    python demo/_mcp_turn.py warehouse_list_tables
    python demo/_mcp_turn.py warehouse_describe_table '{"name": "dim_users"}'
    python demo/_mcp_turn.py warehouse_run_query '{"sql": "SELECT ..."}'

Nothing is simulated: the server is the real one, the transport is real MCP, and the JSON printed is
what the gateway returned.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = str(REPO / "demo" / "airlock.yaml")


def call(tool: str, arguments: dict[str, object]) -> dict[str, object]:
    """Spawn the MCP server, initialize, invoke one tool, and return its structured result."""
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "manual-turn", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    call_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "airlock.cli.main",
            "serve",
            "--config",
            CONFIG,
            "--principal",
            "growth-agent",
        ],
        cwd=str(REPO),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    assert proc.stdin and proc.stdout
    for request in requests:
        proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    time.sleep(9)  # the server compiles a policy snapshot from live DataHub before it serves
    proc.stdin.write(json.dumps(call_request) + "\n")
    proc.stdin.flush()

    result: dict[str, object] = {}
    deadline = time.time() + 60
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("id") == 2:
            result = message.get("result", {}).get("structuredContent", {})
            break
    proc.stdin.close()
    proc.terminate()
    return result


if __name__ == "__main__":
    tool_name = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    print(json.dumps(call(tool_name, args), indent=2))
