"""Real-codebase robustness: exotic SQL never crashes, and qualified names resolve on request.

The contract for anything Airlock cannot fully analyze is *fail closed* — a typed AirlockError,
never an uncaught exception and never a silent pass-through. This battery mirrors constructs that
appear in real analytics SQL (windows, CTEs, set ops, subqueries, lateral, values, ...).
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from airlock.analyzer.resolve import resolve
from airlock.analyzer.rewrite import rewrite
from airlock.engine.decide import decide, statement_is_denied
from airlock.errors import AirlockError, UnknownTableError, WarehouseUnavailableError
from airlock.exec.duckdb_adapter import DuckdbAdapter

COMPLEX_SQL = [
    "SELECT name, ROW_NUMBER() OVER (PARTITION BY email ORDER BY id) AS rn FROM dim_users",
    "SELECT name, email FROM dim_users QUALIFY ROW_NUMBER() OVER (ORDER BY id) = 1",
    "SELECT a.name, b.name FROM dim_users a JOIN dim_users b ON a.id = b.id",
    "SELECT s.e FROM (SELECT email AS e FROM dim_users) s",
    "SELECT name, (SELECT MAX(total) FROM orders) AS m FROM dim_users",
    "SELECT name FROM dim_users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)",
    "SELECT email FROM dim_users UNION ALL SELECT email FROM users_raw",
    "SELECT id FROM dim_users EXCEPT SELECT user_id FROM orders",
    "SELECT id FROM dim_users INTERSECT SELECT user_id FROM orders",
    "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 5) SELECT n FROM t",
    "WITH dim_users AS (SELECT 1 AS x) SELECT x FROM dim_users",
    "SELECT CASE WHEN id > 1 THEN email ELSE name END AS c FROM dim_users",
    "SELECT DISTINCT ON (id) id, email FROM dim_users",
    "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS t(x, y)",
    "SELECT * FROM dim_users u JOIN orders o ON o.user_id = u.id",
    "SELECT COUNT(*) FROM (SELECT email, COUNT(*) FROM dim_users GROUP BY email) s",
    "SELECT email, COUNT(*) c FROM dim_users GROUP BY email HAVING COUNT(*) > 0",
    "SELECT CAST(id AS VARCHAR) || email FROM dim_users",
    "SELECT name FROM dim_users WHERE id IN (SELECT user_id FROM orders)",
    "SELECT COALESCE(email, 'none') AS e FROM dim_users",
]


@pytest.mark.parametrize("sql", COMPLEX_SQL)
def test_complex_sql_never_crashes(sql: str, graph) -> None:
    principal = graph.principal("growth-agent")
    try:
        resolved = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    except AirlockError:
        return  # failing closed is an acceptable outcome
    verdicts = decide(resolved, principal, graph)
    if not statement_is_denied(verdicts):
        rewrite(resolved, principal, graph)  # rewrite must not crash either


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT CASE WHEN ssn IS NULL THEN 0 ELSE 1 END FROM dim_users",
        "SELECT COALESCE(ssn, 'x') FROM dim_users",
        "SELECT id, ROW_NUMBER() OVER (PARTITION BY ssn) AS rn FROM dim_users",
    ],
)
def test_denied_column_is_nulled_in_every_derivation(sql: str, graph) -> None:
    # A denied column must never reach output, even inside CASE/COALESCE/window — NULL propagates.
    resolved = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    result = rewrite(resolved, graph.principal("growth-agent"), graph)
    assert "ssn" not in result.executed_sql.lower().replace('"ssn"', "")  # no bare ssn reference


def test_qualified_name_denied_in_exact_mode(graph) -> None:
    with pytest.raises(UnknownTableError):
        resolve(
            "SELECT email FROM warehouse.main.dim_users",
            dialect="duckdb",
            graph=graph,
            enforcement=graph.enforcement,
        )


def test_qualified_name_resolves_in_suffix_mode(graph) -> None:
    g = replace(graph, enforcement=replace(graph.enforcement, table_matching="suffix"))
    resolved = resolve(
        "SELECT email FROM warehouse.main.dim_users",
        dialect="duckdb",
        graph=g,
        enforcement=g.enforcement,
    )
    verdicts = decide(resolved, g.principal("growth-agent"), g)
    assert any(v.code == "AIRLOCK-110" for v in verdicts)  # policy applied to the resolved table


def test_ambiguous_suffix_fails_closed(graph) -> None:
    # dim_users and payroll both have an `ssn` column but different names; a bare leaf that maps to
    # two datasets must not resolve even in suffix mode. Here we force ambiguity via a shared leaf.
    from datetime import UTC, datetime

    from airlock.policy.graph import ColumnFact, DatasetFacts, EnforcementSettings, PolicyGraph
    from airlock.urns import dataset_urn, field_urn

    def ds(schema: str) -> DatasetFacts:
        urn = dataset_urn("duckdb", f"{schema}.events")
        return DatasetFacts(
            urn=urn,
            platform="duckdb",
            name=f"{schema}.events",
            env="PROD",
            columns=(ColumnFact("id", field_urn(urn, "id"), "BIGINT"),),
            domain="Marketing",
        )

    a, b = ds("sales"), ds("hr")
    g = PolicyGraph.build(
        datasets={a.urn: a, b.urn: b},
        lineage={},
        rules=(),
        enforcement=EnforcementSettings(table_matching="suffix"),
        principals=dict(graph.principals),
        compiled_at=datetime.now(UTC),
        source_url="http://x",
    )
    assert g.dataset_by_name("events") is None  # ambiguous leaf: must not resolve
    assert g.dataset_by_name("sales.events") is a  # qualified: resolves


async def test_duckdb_timeout_drains_and_pool_stays_usable(warehouse) -> None:
    # A query that exceeds its timeout is interrupted and returns a typed error; the interrupted
    # worker thread is drained so the connection is safe to reuse for the next query.
    adapter = DuckdbAdapter(warehouse, pool_size=2)
    slow = "SELECT COUNT(*) FROM range(100000000) a, range(100) b"
    with pytest.raises(WarehouseUnavailableError):
        await adapter.run(slow, timeout=0.3, row_limit=10)
    result = await adapter.run("SELECT name FROM dim_users LIMIT 2", timeout=10, row_limit=10)
    assert len(result.rows) == 2  # pool reusable after the interrupt
    await adapter.close()


async def test_duckdb_caps_rows_even_without_a_sql_limit(warehouse) -> None:
    # Defense in depth: the adapter must never hand back more than row_limit rows even if the SQL it
    # is given carries no LIMIT (the rewriter normally injects one; this is the backstop).
    adapter = DuckdbAdapter(warehouse, pool_size=1)
    result = await adapter.run("SELECT n FROM range(20) t(n)", timeout=10, row_limit=4)
    await adapter.close()
    assert len(result.rows) == 4
    assert result.truncated


async def test_duckdb_concurrent_queries_are_consistent(warehouse) -> None:
    adapter = DuckdbAdapter(warehouse, pool_size=4)
    results = await asyncio.gather(
        *[
            adapter.run("SELECT COUNT(*) c FROM dim_users", timeout=10, row_limit=10)
            for _ in range(12)
        ]
    )
    counts = {r.rows[0]["c"] for r in results}
    await adapter.close()
    assert counts == {3}  # every concurrent query saw the same, correct count


def test_substitution_clears_stale_schema_prefix() -> None:
    # Substituting a schema-qualified deprecated table with a bare certified one must not leave the
    # old schema prefix behind (would point at the wrong table).
    from datetime import UTC, datetime

    from airlock.policy.graph import (
        ColumnFact,
        DatasetFacts,
        EnforcementSettings,
        PolicyGraph,
        Principal,
        Scope,
    )
    from airlock.policy.rules import ActionKind, ActionSpec, Match, Rule
    from airlock.urns import dataset_urn, field_urn

    def _ds(name: str, urn: str, **kw) -> DatasetFacts:
        return DatasetFacts(
            urn=urn,
            platform="duckdb",
            name=name,
            env="PROD",
            columns=(ColumnFact("name", field_urn(urn, "name"), "VARCHAR"),),
            domain="M",
            **kw,
        )

    src, dst = dataset_urn("duckdb", "retail.users_raw"), dataset_urn("duckdb", "dim_users")
    g = PolicyGraph.build(
        datasets={
            src: _ds("retail.users_raw", src, lifecycle="DEPRECATED"),
            dst: _ds("dim_users", dst, certification="CERTIFIED"),
        },
        lineage={src: (dst,)},
        rules=(
            Rule.make(
                "d", Match(lifecycle="DEPRECATED"), ActionSpec(ActionKind.SUBSTITUTE_CERTIFIED)
            ),
        ),
        enforcement=EnforcementSettings(table_matching="suffix"),
        principals={"a": Principal("a", Scope(domains=frozenset({"M"})))},
        compiled_at=datetime.now(UTC),
        source_url="http://x",
    )
    resolved = resolve(
        "SELECT name FROM retail.users_raw", dialect="duckdb", graph=g, enforcement=g.enforcement
    )
    out = rewrite(resolved, g.principal("a"), g).executed_sql
    assert "retail" not in out.lower() and "dim_users" in out
