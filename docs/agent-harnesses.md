# Using Airlock with an agent harness

Airlock is an MCP server. Any MCP client — Claude Code, Cursor, Claude Desktop, Antigravity, or a
framework that speaks the protocol — points at it the same way it points at any other server, and
from then on the agent's warehouse access runs through the gateway: parsed, governed, explained.

You do not need to hand-write the config. `airlock mcp-config` prints the exact block for your
client, filled in for this machine — the interpreter that has Airlock installed, an absolute config
path, and the environment your config's `${VAR}` references need:

```bash
airlock mcp-config --client claude-code -c demo/airlock.yaml
```

Pass `--client cursor`, `--client claude-desktop`, `--client antigravity`, or `--client generic`.
`--json` prints only the block, for scripting. `--principal <name>` sets which agent identity the
stdio server acts as (default `growth-agent` in the demo).

## The two transports, and which to use

**stdio** — the client launches one gateway process per agent. The principal is fixed when the
process starts (`--principal`), because one process serves exactly one agent. This is the right
choice for a local IDE agent (Claude Code, Cursor, Claude Desktop): the client owns the process, so
the process boundary is the identity boundary. Everything below uses stdio.

**http** — one gateway serves many agents at once, and each request carries an `X-Airlock-Key`
header naming the agent. Use this when several agents share one long-running gateway. `airlock
mcp-config --transport http` prints the shape; run the server with `airlock serve --transport http
--port <port>`.

## Claude Code

```bash
airlock mcp-config --client claude-code -c demo/airlock.yaml
```

Either save the printed `mcpServers` block as `.mcp.json` in your project root (shared with your
team) or `~/.claude.json` (personal), or run the equivalent `claude mcp add …` one-liner it prints.
Then, in Claude Code:

```
> what tables can I query?        # the agent calls warehouse_list_tables
> top customers by lifetime value, with their emails
```

The second answer comes back with `email` masked and a verdict explaining why. Claude Code shows the
tool result; the enforcement already happened.

## Cursor

```bash
airlock mcp-config --client cursor -c demo/airlock.yaml
```

Save the block to `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for every project.
Cursor lists Airlock's three tools (`warehouse_run_query`, `warehouse_list_tables`,
`warehouse_describe_table`) once it reconnects.

## Claude Desktop

```bash
airlock mcp-config --client claude-desktop -c demo/airlock.yaml
```

Merge the block into `claude_desktop_config.json` (Settings → Developer → Edit Config) and restart
Claude Desktop. The block has no `cwd` — Claude Desktop does not support one — so Airlock uses the
absolute config path the command emits.

## Antigravity and other MCP clients

```bash
airlock mcp-config --client antigravity -c demo/airlock.yaml   # or --client generic
```

Every MCP client accepts the same `mcpServers` shape. Add the printed block through your client's
MCP-server settings. If the client resolves relative paths from a directory you don't control, the
absolute `--config` path in the block keeps it working.

## What the agent sees

Three read-only tools, each returning a typed envelope, not prose:

- **`warehouse_run_query`** — runs one governed `SELECT`. The response carries the rows plus a
  `verdicts` list: every mask, denial, substitution, and row cap, each with a stable reason code and
  a hint the agent can act on. A denied column comes back with *what to do instead*, so a capable
  agent reformulates on its next turn rather than looping.
- **`warehouse_list_tables`** — the tables this principal is scoped to, and nothing outside them.
- **`warehouse_describe_table`** — every column annotated with the policy that would fire on it
  (allow / mask / deny). The agent reads this first and selects only usable columns, avoiding a
  denial round-trip entirely.

Nothing about the client changes. Airlock exposes the tool surface an agent already expects from a
warehouse MCP server; it is a drop-in the way a reverse proxy is a drop-in for a human client.

## Troubleshooting

An MCP server that fails to start is usually one of three things, and `airlock mcp-config` is built
to prevent all three: the wrong interpreter (it emits the one Airlock is installed under), a
relative config path (it emits an absolute one), or an unset environment variable (it lists any that
are blank). If the server still will not start, run the same command by hand and read the error:

```bash
airlock serve -c demo/airlock.yaml --principal growth-agent
```

`airlock doctor -c demo/airlock.yaml` checks the whole environment — DataHub reachability, the
warehouse connection, a compilable snapshot — and names the fix for anything broken.
