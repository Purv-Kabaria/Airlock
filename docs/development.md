# Development guide

For contributors extending Airlock. Read [`README.md`](../README.md) first — it is the spec, and
this guide does not repeat it. Read [`CLAUDE.md`](../CLAUDE.md) before opening a PR: the anti-slop
rules and nomenclature there are review blockers, not suggestions.

## Architecture in code terms

Airlock is a policy decision point (PDP) wrapped in an enforcement point (PEP), split so the
decision is a pure function and everything impure lives at the edges.

| Role (XACML) | What it is here | Where |
|---|---|---|
| Policy information point | DataHub — tags, terms, lifecycle, lineage, schemas | read by `policy/compile.py` |
| Policy definition | Rules over classifications, in `airlock.yaml` | `policy/rules.py` |
| Decision point (PDP) | `decide(resolved, principal, graph) -> list[Verdict]` | `engine/decide.py` |
| Enforcement point (PEP) | AST rewrite + warehouse execution | `analyzer/rewrite.py`, `exec/` |

`engine/decide.py` is pure: no I/O, no clock, no globals. A decision is a total function of
`(ResolvedQuery, Principal, PolicyGraph)`, and the `PolicyGraph` is content-addressed
(`graph.content_hash`), so any historical decision replays bit-for-bit from `(sql, principal,
snapshot_hash)`. That purity is also what makes the decision cache in the gateway safe to key on the
hash — see `_hash_graph` in `policy/graph.py:292`, which must cover every field that changes a
decision (guarded by `tests/unit/test_snapshot_hash.py`).

Snapshot flow: `compile_snapshot` (`policy/compile.py:125`) reads DataHub over GraphQL and calls
`PolicyGraph.build`, combining catalog facts with rules/enforcement/principals from config into a
frozen `PolicyGraph`. `SnapshotStore.install` (`policy/store.py:49`) swaps it into an atomic
reference and persists the catalog facts to SQLite. Reads take `store.current` with a plain
attribute read — no lock, so concurrent decisions never contend. `refresh_loop` recompiles in the
background; a query never waits on DataHub.

## Request lifecycle

Trace one `warehouse_run_query` call through `gateway.py`:

| Step | Call | Note |
|---|---|---|
| Boot | `Gateway.build` → `bootstrap` (`:130`) | fail-fast if DataHub can't compile a snapshot, unless a persisted snapshot exists and stale-serving is on |
| Ingress | `run_query` (`:212`) | pins `_pinned_snapshot()`, resolves the `Principal`, raises `OverloadedError` (`AIRLOCK-440`) if `_inflight_count >= cap` |
| Staleness | `_staleness_note` (`:484`) | raises `AIRLOCK-410` past the budget under `fail_closed`; else attaches a warning verdict |
| Concurrency | `async with self._sem` | bounded by `max_concurrency`; extra requests queue up to `burst` |
| Plan | `_plan` (`:352`) | cache keyed `(sql, principal.name, graph.content_hash)`, LRU-evicted; miss calls `_build_plan` |
| Build | `_build_plan` (`:365`) | `resolve` → `decide` → (`rewrite` unless denied); returns a frozen `Plan` |
| Execute | `_materialize` → `_execute` (`:431`) | coalesces identical in-flight `(principal, executed_sql)` onto one warehouse call, then `_verify_masking` |
| Audit | `_audit` (`:521`) | local JSONL awaited on the path; remote sinks enqueued to a bounded drain worker |

The `Plan` (`gateway.py:43`) is the cached unit: verdicts, `executed_sql`, `masked_outputs` (for
post-flight verification), and `column_reads` (for usage write-back). A denied or errored plan
carries no `executed_sql`. `dry_run` (`:249`) runs the same plan path but stops before the
warehouse — that is `airlock check`.

Coalescing detail worth knowing before you touch `_execute`: the leader awaits the adapter directly
and hands its result (or exception) to followers through a shared future. A follower whose own
client dropped is distinguished from a leader failure by whether the shared future is still pending
(`:439`). `tests/unit/test_coalesce_cleanup.py` pins this.

## Module responsibilities

Layout is fixed by README §"Module layout". The invariants that matter:

| Module | Owns | Interface out |
|---|---|---|
| `policy/compile.py` | **the only** DataHub reader | `compile_snapshot(config) -> PolicyGraph` |
| `policy/graph.py` | the frozen snapshot + rule resolution | `governing_rule`, `dataset_by_name`, `certified_substitutes` |
| `policy/rules.py` | rule model + precedence matcher | `column_rule`, `winning_action`, `rule_applies` |
| `policy/store.py` | atomic swap + SQLite persistence | `current`, `install`, `persisted_catalog` |
| `analyzer/resolve.py` | parse, qualify, `*`-expand, bind columns→URNs, decide substitution | `resolve(...) -> ResolvedQuery` |
| `analyzer/rewrite.py` | apply verdicts to the AST, render dialect SQL | `rewrite(...) -> RewriteResult` |
| `engine/decide.py` | pure verdicts | `decide`, `column_outcome`, `outcome_for` |
| `engine/verdicts.py` | reason-code table, `Verdict`, `Envelope` | the wire shapes |
| `exec/` | one adapter per warehouse | `WarehouseAdapter` protocol |
| `masking/` | strategy registry | `resolve_strategy`, `mask_expression`, `verify_value` |
| `audit/datahub_sink.py` | **the only** DataHub writer | `Sink.write` |
| `mcp/server.py` | the three tools | FastMCP app |

The two hard invariants: `compile.py` is the only reader of DataHub, `audit/datahub_sink.py` is the
only writer. Everything else consumes the `PolicyGraph` type and never imports a DataHub client.
`decide.py` imports no I/O module; if you find yourself reaching for the clock or a network call
there, the logic belongs in the gateway.

`column_outcome` (`engine/decide.py:38`) is the single source of truth for what happens to a column.
It is shared by `decide`, `rewrite`, the `warehouse_describe_table` card, and `coverage` — so the
explanation an agent reads, the SQL that runs, and the posture report can never disagree.

## Adding a warehouse adapter

An adapter implements the `WarehouseAdapter` protocol (`exec/base.py:41`) — five methods:

```python
async def run(self, sql, *, timeout, row_limit) -> QueryResult
async def list_tables(self) -> list[str]
async def describe_table(self, name) -> list[tuple[str, str]]
async def healthcheck(self) -> None
async def close(self) -> None
```

Before writing one, check whether you need to. `kind: dbapi` already drives **any** PEP 249 driver
through `DbapiAdapter` (`exec/dbapi_adapter.py`) — name the module and the sqlglot dialect in config
and it connects; MySQL, Trino, ClickHouse, Redshift, ODBC all work without new code. Write a
dedicated adapter only for a driver that is not PEP 249 (BigQuery) or one whose pooling/cancellation
needs special handling.

Steps for a genuine new adapter:

1. Add `airlock/exec/<name>_adapter.py` with a class exposing `kind` and the five methods. Drive the
   sync driver off the event loop with `asyncio.to_thread` through a bounded pool, as `DbapiAdapter`
   does; carry a `timeout` on every await; discard a connection that was interrupted mid-statement.
2. Coerce every cell through `coerce_value` (`exec/base.py:26`) so dates and decimals serialize
   identically across warehouses.
3. Register it in `make_adapter` (`exec/base.py:55`) under its `kind`. Import the driver lazily
   *inside* the adapter so a DuckDB-only gateway never needs the cloud driver installed.
4. Add the `kind` to the `WarehouseConfig` literal and `demo/airlock.yaml` docs.

Do **not** write masking SQL in an adapter. All masking is one set of dialect-neutral templates
rendered per sqlglot dialect at rewrite time (see below); a per-warehouse mask is a review blocker.
Adding a warehouse is a connection, not a policy port.

## Adding a masking strategy

Strategies live in one registry, `_TEMPLATES` in `masking/strategies.py:35`. Each maps a name to a
SQL template with `{col}` and `{salt}` placeholders.

The rule that makes one template correct on every warehouse: **write the template once in the
canonical dialect (`_CANON = "duckdb"`), never the warehouse dialect.** `mask_expression`
(`:104`) parses it into a canonical AST; `analyzer/rewrite.py` renders the whole statement in the
target dialect, and sqlglot transpiles the *function semantics* — `MD5(...)` → `TO_HEX(MD5(...))` on
BigQuery, `||` → `CONCAT` on MySQL. Re-parsing a template directly in the target dialect skips that
transpilation and leaks bytes. Avoid any function sqlglot cannot transpile everywhere (`SPLIT_PART`
has no BigQuery form — `partial_email` uses `STRPOS` + `SUBSTRING` instead).

To add one:

1. Add the template to `_TEMPLATES` and a one-line hint to `_HINTS`.
2. If it should be auto-selected by column name/type, extend `resolve_strategy` (`:77`). An explicit
   strategy a column's type can't support must degrade to `hash` there, not emit SQL the warehouse
   rejects — and the name it returns is what the verdict reports, so a degrade stays visible.
3. Add a shape check to `verify_value` (`:128`) if the output has a cheap invariant; the gateway
   samples rows post-flight and withholds the response on a mismatch (`AIRLOCK-420`, README edge 17).
4. It is gated by `test_masking_is_dialect_portable` (`tests/unit/test_masking.py`), which renders
   the template across every supported dialect and fails if one doesn't transpile. A CASE length/`@`
   guard is load-bearing whenever a partial mask could reveal a short value whole — keep it.

## Adding a reason code

Reason codes are allocated in exactly one place: the `ReasonCode` enum in `engine/verdicts.py:18`.
Never write a bare `"AIRLOCK-NNN"` string anywhere else — reference `ReasonCode.<NAME>`.

1. Add the member with a one-line comment on what it means, in the right band: `1xx` mask/column,
   `2xx` substitution, `3xx` scope, `4xx` faults that cross the wire.
2. Add its short human phrase to `TITLES` (`:72`) — it leads the reason sentence.
3. If the reader could act on it (any deny/mask/scope/unknown case), add it to `_HINT_REQUIRED`
   (`:103`). A `Verdict` with a required code but no hint fails construction via the
   `_require_hint` model validator — every actionable verdict must carry a fix.

## Testing

| Suite | Command | Needs live stack |
|---|---|---|
| Unit | `make unit` (`uv run pytest tests/unit -q`) | no |
| Lint + types + edges | `make ci` | no |
| Property (rewriter) | part of unit; `tests/unit/test_analyzer_property.py` | no (embeds DuckDB) |
| Edge contract | `make edges` (`tools/check_edges.py`) | no |
| Bench (p95 < 10ms gate) | `make bench` | yes — `make up` first |
| Eval (10 questions) | `make eval` | yes |
| Judge (hostile gauntlet) | `make judge` | yes |
| Load (50 sustained, 200 burst) | `make load` | yes |

`make ci` is the fast lane CI runs on every commit across {ubuntu, macos, windows} × {3.11, 3.12};
`make integration` is the real-stack lane that boots DataHub + DuckDB via `python demo/up.py`.

Rules to keep:

- **No network in unit tests.** Fakes live only under `tests/unit/` behind the real protocols — see
  `conftest.py`, which builds a `PolicyGraph` directly (never compiled from DataHub) and seeds a
  local DuckDB file. The property test executes rewritten SQL on an embedded DuckDB, which is not
  network.
- **The edge table is the test plan.** Every row in the README edge-case table needs a
  `test_edge_NN_<slug>` test (mostly in `tests/unit/test_edges.py`); `tools/check_edges.py` parses
  the table and fails the build if a row loses its test.
- **The property test is the crown jewel** (`test_analyzer_property.py`): hypothesis generates
  queries over a known schema and asserts every sensitive column is masked or nulled in the output,
  non-sensitive columns are byte-identical, and the rewritten SQL still runs. Budget real time here
  when you touch `resolve` or `rewrite`.
- Verdict envelopes are golden-file diffed; regenerate deliberately, never hand-edit.

## Local setup

```bash
uv sync --extra dev        # or: make install
make ci                    # lint, mypy --strict, unit tests, edge coverage
```

`ruff` (lint + format) and `mypy --strict` are blocking in CI — run `make fmt` before committing.
Conventional commits (`feat:`/`fix:`/`test:`/`docs:`/`refactor:`), small PRs, one concern each.
Decisions that pin or reverse something in CLAUDE.md go in `docs/adr/NNN-title.md`.

Everything installs from prebuilt universal wheels on all target platforms — a dependency that
triggers a source build on any OS is not allowed (CLAUDE.md §11). Use `pathlib` for paths and pass
`encoding="utf-8"` on every `open()`; setup-path commands must be idempotent.
