# Changelog

All notable changes to Airlock. Format loosely follows [Keep a Changelog](https://keepachangelog.com).

## [0.1.0] — unreleased

First working build for the Build with DataHub hackathon.

### Enforcement
- Semantic SQL firewall over sqlglot: parse, qualify, star-expansion, and column-to-URN
  resolution through CTEs, subqueries, joins, aliases, `UNION`, and window functions.
- Column masking (`null`, `hash`, `partial_email`, `partial_phone`, `generalize_date`,
  `fixed_string`) as inlined SQL — zero warehouse footprint. Salted, equality-preserving `hash`.
- Column denial (nulled everywhere, including inside `CASE`/`COALESCE`/window derivations),
  certified-table substitution via lineage, membership-inference guards on masked predicates,
  scope confinement by domain, statement-class control, and row-limit injection.
- **Taint propagation:** a masked or denied column laundered through a CTE or subquery is still
  guarded when used in a predicate or aggregate — not just at its base reference.
- **Qualified-name resolution** (`table_matching: suffix`): resolve `catalog.schema.table` to a
  catalog dataset when unambiguous, for real warehouses whose ingestion omits qualifiers. Opt-in;
  the default stays fail-closed `exact`.

### Policy & catalog
- Policy compiled live from DataHub (tags, glossary terms, lifecycle, certification, domains,
  schemas, lineage) into a content-addressed, frozen `PolicyGraph`. Fail-fast startup without it.
- Content-addressed SQLite snapshot store with atomic pointer swap and offline bootstrap.

### MCP & runtime
- FastMCP server with three read-only tools returning typed verdict envelopes.
- Async request path with snapshot pinning, decision cache, in-flight coalescing (waiters survive
  a leader's cancellation), bounded-concurrency queue, and `/healthz` `/readyz`.

### Audit
- Append-only line-atomic JSONL, optional OpenTelemetry, and DataHub write-back (structured
  properties `airlock.lastAgentAccess` / `lastPolicySnapshot` / `deniedAttempts` + a per-dataset
  ledger).

### Security hardening
- Secret `masking.salt` (was derived from the public policy hash).
- Constant-time principal-key comparison.
- Fail closed on DuckDB `COLUMNS(...)` dynamic selectors (`AIRLOCK-407`): qualify never expands
  them, so their columns were never classified or masked - `SELECT COLUMNS('.*')` returned raw.
- Guard masked columns in the `QUALIFY` clause (`AIRLOCK-130`): it is a post-window filter and
  leaked row membership exactly like `WHERE`.
- Deny table-valued functions in `FROM` unconditionally (`AIRLOCK-408`) - `read_csv`, `read_text`,
  `glob`, `range` - even under `unknown_tables: allow`, closing an arbitrary file/URL read path.
- Include the verdict action in decision dedup so a denied column that is both projected and
  grouped is denied, not run against the raw column (was leaking distinct-value counts).
- Deny uncatalogued columns of known tables under the default `unknown_tables: deny`
  (`AIRLOCK-409`): a column the catalog schema does not list cannot be classified, so a warehouse
  whose schema drifted ahead of DataHub no longer leaks a new, untagged column raw.
- Bound the remote-audit backlog (`server.writeback_queue`, default 512): DataHub write-back is
  network-bound and serialized, so the old one-task-per-query hand-off could grow the pending set
  without limit under sustained load. A single drain worker now consumes a bounded queue; past the
  cap the remote copy is dropped with a counter while the local JSONL sink stays authoritative.
- Cap adapter results at `row_limit` as a fail-closed backstop, independent of the rewriter's
  injected `LIMIT`.

### CLI & DX
- `init`, `check` (`--json`, `--offline`), `serve`, `tail`, `explain`, `refresh`, `doctor`,
  `policy lint`/`diff`, `version`.

### Tooling
- `make ci` gate: ruff, `mypy --strict`, unit tests, edge-case coverage, decision benchmark
  (p95 < 10 ms), hostile-user gauntlet, and a 10-question MCP eval. Three-OS CI matrix that also
  boots the full demo stack.
