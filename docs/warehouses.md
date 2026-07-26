# Connecting a warehouse

Airlock enforces policy by rewriting SQL, so a warehouse is a connection, not a policy port. Adding
one never means re-authoring masks: the same rule renders in each warehouse's own dialect, verified
across nine of them. Four warehouses have a dedicated adapter; `kind: dbapi` handles the rest through
any [PEP 249](https://peps.python.org/pep-0249/) driver, which is nearly every Python database
library.

How far each one has actually been exercised, so you know what you are trusting:

| Warehouse | Status |
|---|---|
| DuckDB | The demo warehouse. Every demo, eval, and gauntlet run goes through it. |
| SQLite | Unit-tested live against the stdlib driver, including all five DB-API paramstyles. |
| Postgres | Verified end to end against a real server — see the conformance suite below. |
| Snowflake, BigQuery | Unit-tested (DSN parsing, request shaping) and audited call-by-call against the installed driver — every method, keyword, and parameter style the adapters use is checked to exist with the signature they assume. Never run against a real account, so expect to shake out a bug or two; please file what you find. |
| `dbapi` | The generic path SQLite is tested through. Any given driver is as good as its PEP 249 compliance. |

The `warehouse` block takes a `kind`, a `dsn`, and the row-limit and timeout defaults. Secrets stay
as `${ENV}` references, resolved at load — never written to the file. Confirm any connection with
`airlock doctor -c <config>` before serving; it names the fix for whatever is wrong.

## DuckDB

The demo warehouse. A file path or `:memory:`.

```yaml
warehouse:
  kind: duckdb
  dsn: ./data/warehouse.duckdb        # or duckdb:///abs/path, or :memory:
```

## SQLite

Standard library — no driver to install, ships on every platform including ARM. The zero-dependency
option for a laptop, a CI box, or a constrained device.

```yaml
warehouse:
  kind: sqlite
  dsn: ./data/warehouse.db            # or sqlite:///abs/path, or :memory:
```

## Postgres

Needs `pip install airlock-gateway[postgres]` (psycopg 3, native async).

```yaml
warehouse:
  kind: postgres
  dsn: ${WAREHOUSE_DSN}               # postgresql://user:pass@host:5432/dbname
```

psycopg runs on Airlock's own event loop, and it refuses the `ProactorEventLoop` that asyncio selects
by default on Windows. The CLI picks a compatible loop before it opens one, so `airlock serve`,
`check`, and `doctor` need nothing from you. If you embed the gateway in your own asyncio program on
Windows, set the policy yourself before the loop starts:

```python
import asyncio, sys
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
```

Skip it and the first query raises `AIRLOCK-441` naming this exact fix rather than a driver error.

To check the whole path against a real server — masking rendered in Postgres SQL, executed, and read
back — run the conformance suite against a throwaway container:

```bash
docker run -d --name airlock-pg -e POSTGRES_PASSWORD=airlock -e POSTGRES_USER=airlock \
    -e POSTGRES_DB=airlockdemo -p 55432:5432 postgres:16-alpine
AIRLOCK_TEST_POSTGRES_DSN=postgresql://airlock:airlock@localhost:55432/airlockdemo \
    uv run pytest tests/integration -q
```

## Snowflake

Needs `pip install airlock-gateway[snowflake]`. The DSN is a SQLAlchemy-style URL; anything after the
`?` is passed to the connector, so key-pair or SSO auth works by adding the connector's own arguments.

```yaml
warehouse:
  kind: snowflake
  dsn: ${WAREHOUSE_DSN}               # snowflake://user:pass@account/database/schema?warehouse=WH&role=READER
```

## BigQuery

Needs `pip install airlock-gateway[bigquery]`. Credentials come from `credentials_path` if given,
otherwise from Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS` or the ambient
service account). A dataset is required for table introspection.

```yaml
warehouse:
  kind: bigquery
  dsn: ${WAREHOUSE_DSN}               # bigquery://project-id/dataset?location=US&credentials_path=/keys/sa.json
```

## Anything else — `kind: dbapi`

Name the driver module and the sqlglot dialect. `connect_args` are passed straight to the driver's
`connect()`. Install the driver yourself; Airlock imports it lazily and, if it is missing, fails with
the install command rather than an opaque error at first query.

```yaml
# MySQL
warehouse:
  kind: dbapi
  driver: pymysql                     # pip install pymysql
  dialect: mysql
  dsn: ${WAREHOUSE_DSN}               # user:pass@host/db, in the form pymysql.connect() accepts
  connect_args: { charset: utf8mb4 }

# Trino
warehouse:
  kind: dbapi
  driver: trino.dbapi
  dialect: trino
  dsn: ""                            # empty when the connection is built entirely from connect_args
  connect_args: { host: trino.internal, port: 8080, user: airlock, catalog: hive, schema: default }
```

The `dsn` is the first positional argument to the driver's `connect()`; use `connect_args` for
keyword arguments, and an empty `dsn` when the driver takes only keywords. The sqlglot dialect is
what the analyzer parses and the rewriter renders in — get it right and masking is correct; get it
wrong and queries mis-parse. sqlglot's dialect names cover the common warehouses (`mysql`, `trino`,
`clickhouse`, `redshift`, `spark`, `oracle`, `tsql`, ...).

## What every adapter guarantees

- **A row cap and a statement timeout on every query**, from `warehouse.defaults` (or a per-principal
  override). The rewriter injects the `LIMIT`; the adapter enforces the timeout.
- **Client cancellation reaches the database** where the driver allows it — a dropped client or an
  elapsed timeout calls the connection's interrupt/cancel if it has one, and discards the connection
  otherwise, so a statement never keeps running on a connection handed to someone else.
- **A bounded connection pool**, so a burst cannot open unbounded connections.
- **Values arrive JSON-safe** — a date, a decimal, or bytes are coerced the same way whatever
  warehouse produced them, so the response envelope is identical across backends.

## Introspection and `warehouse_list_tables` / `warehouse_describe_table`

The catalog tools read the warehouse's own `information_schema` (or, for SQLite, `sqlite_master` and
`PRAGMA table_info`). A warehouse without `information_schema` will answer queries but return nothing
for these two tools; the enforcement path does not depend on them.
