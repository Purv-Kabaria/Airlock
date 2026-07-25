# Reason codes

Every verdict Airlock produces and every fault it returns carries a stable `AIRLOCK-NNN`
reason code. The code is the machine-readable identity of a decision: it never changes meaning,
so an agent can branch on it and an operator can grep for it. Each code pairs with a human
`reason` sentence, and — for anything the reader might want to work around — an actionable `hint`.
Codes are allocated in one table in `airlock/engine/verdicts.py`; that file is the source of truth.

Numeric ranges (from the section comments in `verdicts.py`):

| Range | Meaning |
|---|---|
| `1xx` | Column-level masking and column handling |
| `2xx` | Certified-table substitution |
| `3xx` | Scope / domain denial |
| `4xx` | Faults — these cross the MCP wire; a traceback never does |

## The codes

`Name` is the `TITLES` phrase that leads the reason sentence. `Fires when` and `Action` paraphrase
the reason and hint text emitted at each `Verdict.make` call (`engine/decide.py`, `gateway.py`,
`mcp/server.py`) or built by a typed error's `to_verdict()` (`errors.py`).

| Code | Name | Fires when | Action for the agent / operator |
|---|---|---|---|
| `AIRLOCK-110` | column masked | A projected column carries a mask-classified tag or glossary term. | Column returns masked with the named strategy; read the strategy hint for what the masked value preserves. |
| `AIRLOCK-111` | ordering on a masked column is not meaningful | A masked column appears in `ORDER BY`. | Allowed but the ordering is not meaningful on masked values. Informational. |
| `AIRLOCK-113` | column masked by inherited classification | An untagged column derives, via column lineage, from a masked column. | Masked with the propagated strategy. Classify the column in DataHub to make this explicit, or query a column not derived from masked data. |
| `AIRLOCK-120` | column denied | A column is hard-denied for every principal (e.g. `PII.SSN`), whether projected, or used in a predicate/`ORDER BY`/`GROUP BY`. | Projected: the column is nulled. Used in a clause: the statement is denied. Remove it, or aggregate over a non-sensitive column for cardinality. |
| `AIRLOCK-121` | aggregate over a denied column | An aggregate (`COUNT(ssn)`, etc.) is taken over a denied column — including one laundered through a subquery. | Statement denied. Use `COUNT(*)` or aggregate over a non-sensitive key. |
| `AIRLOCK-122` | column denied by inherited classification | An untagged, projected column derives, via column lineage, from a denied column. | Column nulled for every principal. Classify it in DataHub, or query a column not derived from denied data. |
| `AIRLOCK-130` | masked column used in a predicate | A masked column is used in `WHERE` / `JOIN` / `HAVING` — directly or laundered through a subquery — the membership-inference guard. | Under `predicate_policy: deny` (default) the statement is denied; remove the predicate or set `predicate_policy: transform` to compare masked values. Under `transform` it is an informational note. |
| `AIRLOCK-150` | row limit applied | The query has no limit, or a limit above the effective cap. | A row limit was injected and truncation is declared in the envelope. Ask for a narrower query or an aggregate for the full population. |
| `AIRLOCK-160` | monitor mode: not enforced | The gateway runs in monitor mode. | The verdicts were observed but not applied to the query. Informational. |
| `AIRLOCK-201` | table substituted | A deprecated/uncertified table has a certified equivalent reachable via lineage with all referenced columns present. | The query was redirected to the certified table. Point future queries at it to avoid the redirect. |
| `AIRLOCK-202` | substitution downgraded to a warning | A deprecated table could not be substituted (e.g. the certified equivalent is missing referenced columns). | The original table was used. Ask data engineering for a certified replacement, or update the query. |
| `AIRLOCK-301` | table outside your scope | A referenced table's domain/platform lies outside the principal's permitted scope. | Statement denied. Request access from the owning team, or query a table within your domain. |
| `AIRLOCK-401` | query did not parse | The SQL did not parse in the target dialect. | Send a single, syntactically valid SQL statement for this dialect. |
| `AIRLOCK-402` | cannot expand * without a schema | `SELECT *` against a table whose schema is unknown to the catalog. | Name explicit columns, or register the table's schema in DataHub. |
| `AIRLOCK-403` | table not in the catalog | A referenced table is absent from the catalog (default `unknown_tables: deny`). | Call `warehouse_list_tables` for exact names, then retry. If it should exist, register it in DataHub. |
| `AIRLOCK-404` | statement type not permitted | The statement class (DDL/DML/multi-statement/`SET`/`SHOW`/`EXPLAIN`/…) is not in the principal's allowlist. | Send a read-only `SELECT`, or grant the class under `principals[].overrides.statement_classes`. |
| `AIRLOCK-405` | query too large or too deeply nested | The query exceeded a size or nesting-depth limit before analysis. | Reduce the query size or nesting depth and resend. |
| `AIRLOCK-406` | input is not SQL | The input looks like natural language, not SQL. | Send a SQL statement; the error lists the tables the principal can query. |
| `AIRLOCK-407` | dynamic column selection is not supported | A `COLUMNS(...)` dynamic selector (regex/lambda/star) cannot be resolved to concrete columns. | Fail closed. Name the explicit columns you need; Airlock masks or denies them per catalog policy. |
| `AIRLOCK-408` | table-valued functions are not permitted | A table-valued function (`read_csv`, `read_text`, `glob`, `range`, …) appears in `FROM`. | Denied unconditionally, even under `unknown_tables: allow`. Query a cataloged table by name. |
| `AIRLOCK-409` | column is not in the catalog schema | A column on a catalogued table is not listed in the catalog schema (default `unknown_tables: deny`). | Ingest the column into DataHub, or select only catalogued columns. Set `unknown_tables: allow` to pass it through. |
| `AIRLOCK-410` | policy snapshot is stale | The policy snapshot is older than the staleness budget. | Restore DataHub connectivity, or set `stale_policy: serve_stale_readonly`. |
| `AIRLOCK-420` | masking verification failed | Post-flight sampling showed a masked column leaked its shape. | The response was withheld and logged as an incident. Retry the query. |
| `AIRLOCK-430` | unknown principal | No valid principal key was presented; the anonymous policy denies all access. | Register the agent as a principal in `airlock.yaml` and send its key. |
| `AIRLOCK-440` | gateway at capacity | The concurrency cap was exceeded. | Retry after the milliseconds named in the hint. |
| `AIRLOCK-441` | warehouse unavailable | The warehouse was unreachable after one retry. | Verify the warehouse is up and the DSN is correct, then retry. |
| `AIRLOCK-450` | internal gateway error | The gateway itself faulted; not the caller's SQL. | Not a problem with your SQL. Retry; if it persists, the operator should check the logs for this `request_id`. The traceback stays in the log. |

### `AIRLOCK-112` — intentionally unallocated

`112` is deliberately never minted. A `UNION` masks each branch's columns by that branch's own
facts, and a column *derived* from a `UNION` takes the strictest branch via lineage (handled by
`113` / `122` / `130`). There is no separate "union column" verdict, so no code exists for one.
The gap is intentional, not a missing entry.

## What each code does to the query

The `action` field on each verdict says whether a code blocks the whole statement, modifies one
column, or is only informational. Derived from the `action` passed at each `Verdict.make` call.

| Effect | `action` values | Codes |
|---|---|---|
| Denies the whole statement | `deny_statement`, `scope_deny` | `AIRLOCK-121`, `AIRLOCK-130` (under `predicate_policy: deny`), `AIRLOCK-301`, and every `4xx` fault (`401`–`441`, `450`). `AIRLOCK-120` when the denied column is used in a predicate/`ORDER BY`/`GROUP BY`. |
| Modifies one column | `deny_column` (nulled), `mask` | `AIRLOCK-110`, `AIRLOCK-113` (mask); `AIRLOCK-120`, `AIRLOCK-122` (nulled projection). |
| Modifies the statement | `substitute`, `limit` | `AIRLOCK-201` (substitute), `AIRLOCK-150` (limit). |
| Informational note only | `note` | `AIRLOCK-111`, `AIRLOCK-160`, `AIRLOCK-202`, and `AIRLOCK-130` under `predicate_policy: transform`. |

`AIRLOCK-120` and `AIRLOCK-130` are context-dependent: the same code nulls a column when it is
projected but denies the statement when the column reaches a predicate or grouping/ordering clause.

## Cross-references

- Edge-case behavior for most codes is tabulated in README "Edge cases — and how Airlock handles them" (the edge `#` column maps codes to concrete inputs).
- The four-line reason/why/what-now/where-to-look shape every message follows is in README "Error message design".
- Codes for which a hint is mandatory are listed in `_HINT_REQUIRED` in `verdicts.py`; a verdict in that set without a hint fails validation.
