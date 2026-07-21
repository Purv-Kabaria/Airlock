# Composing Airlock with DataHub's MCP Server

Airlock and [DataHub's MCP Server](https://docs.datahub.com/docs/features/feature-guides/mcp) are
two halves of a DataHub-native agent stack, and they do not overlap:

- **DataHub's MCP Server is for discovery.** `search`, `get_lineage`, `list_schema_fields`,
  `find_sql_context`, `get_dataset_queries` — the agent asks *what exists, what it means, what is
  connected to what, and what real queries look like*. All read-only metadata.
- **Airlock is for governed execution.** The agent sends the SQL it wants to run; Airlock enforces
  the policy compiled from that same catalog and returns rows plus a verdict envelope. It is the
  only component that touches warehouse data.

Point one agent at both and you get the full loop: it discovers a table through DataHub, reads its
lineage and example queries, then runs a governed query through Airlock — and every access is
written back into DataHub, where the discovery started.

```json
{
  "mcpServers": {
    "datahub": {
      "command": "uvx",
      "args": ["acryl-datahub-mcp", "--stdio"],
      "env": { "DATAHUB_GMS_URL": "http://localhost:8080", "DATAHUB_GMS_TOKEN": "..." }
    },
    "warehouse": {
      "command": "uvx",
      "args": ["airlock", "serve", "--config", "demo/airlock.yaml"]
    }
  }
}
```

## Why keep them separate

Discovery is open-world and safe to be broad: reading metadata leaks no rows. Execution is
closed-world and must fail closed. Collapsing them into one tool would force either an
over-permissioned discovery surface or an under-informed execution surface. Two servers keep each
one honest — DataHub answers *what could I ask*, Airlock decides *what you actually get*.

The division also matches where the two projects are authoritative. DataHub owns the metadata;
Airlock owns the enforcement decision and its audit trail. Neither reaches into the other's job.

## What the demo ships, and what it does not

The `python demo/up.py` stack runs the DataHub OSS quickstart, which does **not** bundle the MCP
Server — that ships separately (`acryl-datahub-mcp`, or the hosted endpoint on DataHub Cloud). The
demo therefore exercises Airlock against the DataHub **context graph** directly (the `acryl-datahub`
SDK, in `policy/compile.py`), which is the integration Airlock depends on and the one the judging
path verifies end to end.

This document is the reference topology for adding DataHub's MCP Server alongside Airlock once you
have one deployed. It is written to be honest about that boundary: the discovery half is a
configuration you add, not something the local demo fakes.

## Airlock's own agent surface

Even without DataHub's MCP Server, Airlock exposes a discovery surface an agent can plan against —
`warehouse_list_tables` (scope-filtered) and `warehouse_describe_table`, which annotates every
column with the policy that would fire on it (allow / mask / deny, with the strategy or reason).
That card is resolved through the same engine that enforces, so an agent can select only usable
columns before it ever sends a query. It is a narrower, enforcement-aware complement to DataHub's
broad catalog discovery — not a replacement for it.
