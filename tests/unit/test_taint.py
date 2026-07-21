"""Taint propagation: sensitive columns laundered through CTEs/subqueries are still guarded.

Output masking happens at the base column (covered by the property test). These cover the other
half: a predicate on, or an aggregate over, a masked/denied column stays blocked even when the
column is aliased away behind one or more scopes (README edge 4, 6, 7).
"""

from __future__ import annotations

from airlock.analyzer.resolve import resolve
from airlock.engine.decide import decide, statement_is_denied


def _decide(graph, sql, principal="growth-agent"):
    r = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    return decide(r, graph.principal(principal), graph)


def test_masked_predicate_through_subquery_is_denied(graph) -> None:
    v = _decide(
        graph, "SELECT x FROM (SELECT email AS x FROM dim_users) s WHERE x = 'ada@corp.com'"
    )
    assert statement_is_denied(v)
    assert any(c.code == "AIRLOCK-130" for c in v)


def test_denied_aggregate_through_subquery_is_denied(graph) -> None:
    v = _decide(graph, "SELECT COUNT(x) FROM (SELECT ssn AS x FROM dim_users) s")
    assert statement_is_denied(v)
    assert any(c.code == "AIRLOCK-121" for c in v)


def test_masked_predicate_through_nested_ctes_is_denied(graph) -> None:
    sql = (
        "WITH a AS (SELECT email AS e FROM dim_users), b AS (SELECT e AS f FROM a) "
        "SELECT d.name FROM dim_users d JOIN b ON b.f = d.name WHERE b.f = 'x'"
    )
    v = _decide(graph, sql)
    assert statement_is_denied(v)
    assert any(c.code == "AIRLOCK-130" for c in v)


def test_non_sensitive_laundering_is_allowed(graph) -> None:
    v = _decide(graph, "SELECT n FROM (SELECT name AS n FROM dim_users) s WHERE n = 'Ada'")
    assert not statement_is_denied(v)


def test_masked_group_by_through_subquery_is_allowed(graph) -> None:
    # Grouping on a laundered *masked* value operates on masked data (hash preserves equality),
    # so it is allowed, not denied.
    v = _decide(graph, "SELECT x, COUNT(*) FROM (SELECT email AS x FROM dim_users) s GROUP BY x")
    assert not statement_is_denied(v)
