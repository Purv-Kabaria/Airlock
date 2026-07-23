"""Emit the MCP-client config block that points a harness at this Airlock.

Wiring a gateway into Claude Code, Cursor, Claude Desktop, Antigravity, or any MCP client is the
same three facts every time: the interpreter that has Airlock installed, the `serve` invocation
with an absolute config path, and the environment the config's `${VAR}` references need. Getting one
of them wrong is a silent "server failed to start" with no hint. This prints the exact block, filled
in for the machine it runs on, so integration is a copy-paste rather than a debugging session.

The config path is always absolute, so a client without a working-directory setting (Claude Desktop)
still resolves it; `cwd` is emitted only for clients that support and benefit from it.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

_SERVER_NAME = "airlock-warehouse"
_ENV_REF = re.compile(r"\$\{(\w+)\}")

# Clients that accept a working-directory key in their server entry. Claude Desktop does not, so its
# block omits cwd and leans on the absolute --config path instead.
_SUPPORTS_CWD = frozenset({"claude-code", "cursor", "antigravity", "generic"})

CLIENTS = ("claude-code", "cursor", "claude-desktop", "antigravity", "generic")

_WHERE: dict[str, str] = {
    "claude-code": "Save as .mcp.json in your project root (shared), or add to ~/.claude.json "
    "(personal). Or run the `claude mcp add` command printed below.",
    "cursor": "Add to .cursor/mcp.json in your project, or ~/.cursor/mcp.json for every project.",
    "claude-desktop": "Merge into claude_desktop_config.json "
    "(Settings -> Developer -> Edit Config), then restart Claude Desktop.",
    "antigravity": "Add through the MCP settings of your client (Antigravity: MCP servers -> add). "
    "The mcpServers shape below is what it expects.",
    "generic": "Merge into your MCP client's server config under the mcpServers key.",
}


@dataclass(frozen=True, slots=True)
class ServerEntry:
    command: str
    args: list[str]
    cwd: str
    env: dict[str, str]


def referenced_env_vars(config_path: Path) -> list[str]:
    """The `${VAR}` names the config references, in first-seen order. These are what the client must
    pass through for the gateway to resolve its config the way `airlock serve` would."""
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return []
    seen: dict[str, None] = {}
    for match in _ENV_REF.finditer(text):
        seen.setdefault(match.group(1), None)
    return list(seen)


def build_entry(
    *, config: Path, principal: str | None, transport: str, env: dict[str, str]
) -> ServerEntry:
    args = ["-m", "airlock.cli.main", "serve", "--config", str(config.resolve())]
    if transport == "http":
        args += ["--transport", "http"]
    elif principal:
        # stdio: one process serves one agent, so the principal is fixed here. Over http each
        # request authenticates itself with X-Airlock-Key, so no principal is baked in.
        args += ["--principal", principal]
    return ServerEntry(command=sys.executable, args=args, cwd=str(Path.cwd()), env=env)


def _entry_json(client: str, entry: ServerEntry) -> dict[str, object]:
    body: dict[str, object] = {"command": entry.command, "args": entry.args}
    if client == "claude-code":
        body = {"type": "stdio", **body}  # Claude Code labels the transport explicitly
    if client in _SUPPORTS_CWD:
        body["cwd"] = entry.cwd
    if entry.env:
        body["env"] = entry.env
    return body


def render(client: str, entry: ServerEntry, *, transport: str, missing: list[str]) -> str:
    """The full, paste-ready guidance for one client: where it goes, the JSON block, and - for
    Claude Code - the equivalent one-liner. Human-readable; `--json` prints just the block."""
    block = {"mcpServers": {_SERVER_NAME: _entry_json(client, entry)}}
    lines = [_WHERE.get(client, _WHERE["generic"]), "", json.dumps(block, indent=2)]

    if client == "claude-code" and transport == "stdio":
        env_flags = " ".join(f'--env {k}="{v}"' for k, v in entry.env.items())
        cmd = f"claude mcp add {_SERVER_NAME} --scope project"
        if env_flags:
            cmd += f" {env_flags}"
        cmd += " -- " + entry.command + " " + " ".join(entry.args)
        lines += ["", "Or, equivalently:", "", cmd]

    if transport == "http":
        lines += [
            "",
            "This serves over HTTP; each request authenticates with an X-Airlock-Key header "
            "carrying the agent's key. Set the port with --port and send the header from the client.",
        ]
    if missing:
        lines += [
            "",
            "Note: these referenced variables are unset in your current shell, so their values "
            f"above are blank: {', '.join(missing)}. Set them (or run `python demo/up.py` for the "
            "demo) before the client starts the server.",
        ]
    return "\n".join(lines)
