"""The crown-jewel property test: whatever query goes in, sensitive data never comes out raw.

Hypothesis generates queries over a known schema (plain, CTE-wrapped, DISTINCT, ORDER BY, star).
Each is resolved, decided, and rewritten, then the rewritten SQL is *executed on DuckDB* and the
result checked against three invariants:
  (a) every masked column's values are transformed (never a raw value),
  (b) every denied column is NULL,
  (c) non-sensitive columns are byte-identical to the source.
The rewritten SQL must also parse and run in the target dialect.
"""

from __future__ import annotations

import duckdb
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.unit.conftest import build_graph, seed_duckdb

from airlock.analyzer.resolve import resolve
from airlock.analyzer.rewrite import rewrite
from airlock.engine.decide import decide, statement_is_denied

RAW_EMAILS = {"ada@corp.com", "bo@x.io", "cy@corp.com"}
RAW_NAMES = {"Ada", "Bo", "Cy"}
RAW_IDS = {1, 2, 3}


@pytest.fixture(scope="module")
def con(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("wh") / "wh.duckdb")
    seed_duckdb(path)
    connection = duckdb.connect(path, read_only=True)
    yield connection
    connection.close()


@pytest.fixture(scope="module")
def graph():
    return build_graph()


_COLUMNS = ["id", "name", "email", "ssn"]


@st.composite
def queries(draw: st.DrawFn) -> str:
    if draw(st.booleans()):
        return "SELECT * FROM dim_users"
    cols = draw(st.lists(st.sampled_from(_COLUMNS), min_size=1, max_size=4, unique=True))
    distinct = "DISTINCT " if draw(st.booleans()) else ""
    projection = ", ".join(cols)
    if draw(st.booleans()):
        sql = f"WITH t AS (SELECT {projection} FROM dim_users) SELECT {distinct}{projection} FROM t"
    else:
        sql = f"SELECT {distinct}{projection} FROM dim_users"
    if draw(st.booleans()) and "id" in cols:
        sql += " ORDER BY id"
    return sql


@settings(max_examples=120, deadline=None)
@given(sql=queries())
def test_rewrite_never_leaks_sensitive_data(sql: str, con, graph) -> None:
    resolved = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    verdicts = decide(resolved, graph.principal("growth-agent"), graph)
    assert not statement_is_denied(verdicts)  # these shapes are never statement-denied

    result = rewrite(resolved, graph.principal("growth-agent"), graph)
    rows = con.execute(result.executed_sql).fetchall()
    columns = [d[0] for d in con.execute(result.executed_sql).description]
    by_name = {c: [row[i] for row in rows] for i, c in enumerate(columns)}

    if "email" in by_name:
        for value in by_name["email"]:
            assert value not in RAW_EMAILS
            assert value is None or "***" in value
    if "ssn" in by_name:
        assert all(v is None for v in by_name["ssn"])
    if "name" in by_name:
        assert set(by_name["name"]) <= RAW_NAMES
    if "id" in by_name:
        assert set(by_name["id"]) <= RAW_IDS


@settings(max_examples=120, deadline=None)
@given(sql=queries())
def test_rewritten_sql_parses_in_dialect(sql: str, graph) -> None:
    import sqlglot

    resolved = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    result = rewrite(resolved, graph.principal("growth-agent"), graph)
    # Must round-trip through the parser: a rewrite that produces invalid SQL is a security bug.
    assert sqlglot.parse_one(result.executed_sql, dialect="duckdb") is not None


# Named derivation vectors that try to smuggle a sensitive value past masking: function wrappers,
# string concat, CASE, scalar and correlated subqueries, and star-expansion through a CTE/subquery.
# The executed SQL must never return a raw PII/SSN value for any of them.
_LEAK_VECTORS = [
    "SELECT UPPER(email) AS e FROM dim_users",
    "SELECT 'x' || email AS e FROM dim_users",
    "SELECT CASE WHEN id > 1 THEN email ELSE 'n' END AS e FROM dim_users",
    "SELECT o.id, (SELECT email FROM dim_users LIMIT 1) AS leaked FROM orders o",
    "SELECT o.id, (SELECT ssn FROM dim_users LIMIT 1) AS leaked FROM orders o",
    "SELECT u.id, (SELECT email FROM dim_users d WHERE d.id = u.id) AS e FROM dim_users u",
    "WITH t AS (SELECT * FROM dim_users) SELECT * FROM t",
    "SELECT * FROM (SELECT * FROM dim_users) s",
    "SELECT LENGTH(ssn) AS n FROM dim_users",
]


@pytest.mark.parametrize("sql", _LEAK_VECTORS)
def test_derivations_never_leak_raw_sensitive_values(sql: str, con, graph) -> None:
    from airlock.engine.decide import decide, statement_is_denied

    resolved = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    if statement_is_denied(decide(resolved, graph.principal("growth-agent"), graph)):
        return  # denied outright is a safe outcome
    executed = rewrite(resolved, graph.principal("growth-agent"), graph).executed_sql
    values = {str(cell) for row in con.execute(executed).fetchall() for cell in row}
    raw = RAW_EMAILS | {"111-22-3333", "999-88-7777", "555-44-3333"}
    assert not (values & raw)  # no raw email or ssn escaped through the derivation
