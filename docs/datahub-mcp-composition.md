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

## Why Airlock reads DataHub directly, not through the Agent Context Kit SDK

DataHub ships an [Agent Context Kit](https://docs.datahub.com/docs/dev-guides/agent-context/agent-context)
(`datahub-agent-context`) — an SDK and MCP server that expose `get_lineage`, `get_entities`,
`add_structured_properties`, and more as agent tools. The obvious question is why Airlock's
`policy/compile.py` and `audit/datahub_sink.py` talk to GMS directly instead of through the Kit.

We evaluated it against the exact stack judges run — the OSS quickstart (`v1.2.0`) — with
`datahub-agent-context` 1.6.0.x. The Kit is built for DataHub Cloud, and several of its tools do
not work against the open-source GMS:

- `add_structured_properties` fails with a 500 `SERVER_ERROR` — its property-validation query is
  cloud-shaped. Airlock's write-back loop is the core of its DataHub story; it cannot depend on a
  call that fails on the demo.
- `get_dataset_queries` errors on a cloud-only `getRelatedDocuments` field.
- `get_entities` returns schema tags but **omits `editableSchemaMetadata`** — the aspect a tag
  applied in the DataHub UI lands in. Airlock reads it explicitly so the live-retag moment (change
  a tag in the UI, watch enforcement change on the next refresh) works. Routing reads through the
  Kit would silently break that demo.

Only `get_lineage` works cleanly on OSS, and it duplicates a dozen lines Airlock already has.
Taking the Kit as a hard dependency would pull a compiled transitive (`google-re2`) and pin
`acryl-datahub` to one exact patch — a cross-platform and maintenance cost (see the universal-wheel
rule) — to call a single function. So Airlock integrates DataHub through the same GMS GraphQL and
MCP-emit APIs the Kit itself uses, reading five aspect types (schema, tags, glossary terms,
deprecation, domains, lineage — including `editableSchemaMetadata`) and writing structured
properties plus an institutional-memory ledger back. That path is the one the quickstart actually
supports, and it is more robust on OSS than the Kit's own tools.

## Airlock's own agent surface

Even without DataHub's MCP Server, Airlock exposes a discovery surface an agent can plan against —
`warehouse_list_tables` (scope-filtered) and `warehouse_describe_table`, which annotates every
column with the policy that would fire on it (allow / mask / deny, with the strategy or reason).
That card is resolved through the same engine that enforces, so an agent can select only usable
columns before it ever sends a query. It is a narrower, enforcement-aware complement to DataHub's
broad catalog discovery — not a replacement for it.
