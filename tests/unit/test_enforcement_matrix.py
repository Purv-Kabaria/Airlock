"""Every config line that relaxes enforcement, and what it actually changes.

These settings are the ones an operator reaches for under pressure, usually to unblock something.
Each is documented in the README's configuration reference as a deliberate, bounded relaxation, so
each needs a test that says exactly what it gives up. Verified by hand against the live stack first;
pinned here so the behaviour cannot drift without a failure.
"""

from __future__ import annotations

import dataclasses

import pytest
from tests.unit.conftest import build_graph

from airlock.analyzer.resolve import resolve
from airlock.engine.decide import decide


def _codes(graph, sql: str, principal: str = "growth-agent") -> set[str]:
    resolved = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    return {str(v.code) for v in decide(resolved, graph.principal(principal), graph)}


def _with(**enforcement):
    """A graph rebuilt with different enforcement.

    Goes through PolicyGraph.build rather than dataclasses.replace: replace would swap the field
    while leaving content_hash as it was, which would make the hash test below pass for the wrong
    reason. The hash is computed by build, so only build produces a coherent graph.
    """
    from airlock.policy.graph import PolicyGraph

    graph = build_graph()
    return PolicyGraph.build(
        datasets=dict(graph.datasets),
        lineage={u: graph.lineage.downstream_of(u) for u in graph.datasets},
        rules=graph.rules,
        enforcement=dataclasses.replace(graph.enforcement, **enforcement),
        principals=dict(graph.principals),
        compiled_at=graph.compiled_at,
        source_url=graph.source_url,
    )


DEPRECATED = "SELECT name FROM users_raw"


def test_substitution_rewrite_redirects_a_deprecated_table() -> None:
    assert "AIRLOCK-201" in _codes(build_graph(), DEPRECATED)


def test_substitution_warn_reports_but_does_not_redirect() -> None:
    codes = _codes(_with(substitution="warn"), DEPRECATED)
    assert "AIRLOCK-202" in codes  # the downgrade note
    assert "AIRLOCK-201" not in codes  # nothing was actually redirected


def test_substitution_off_is_silent() -> None:
    codes = _codes(_with(substitution="off"), DEPRECATED)
    assert "AIRLOCK-201" not in codes and "AIRLOCK-202" not in codes


def test_predicate_policy_deny_blocks_a_filter_on_a_masked_column() -> None:
    codes = _codes(build_graph(), "SELECT name FROM dim_users WHERE email = 'x'")
    assert "AIRLOCK-130" in codes


def test_predicate_policy_transform_allows_it_against_masked_values() -> None:
    # Still reported, but as a note rather than a refusal: the comparison runs against the masked
    # form, so a raw literal matches nothing instead of proving a row exists.
    graph = _with(predicate_policy="transform")
    resolved = resolve(
        "SELECT name FROM dim_users WHERE email = 'x'",
        dialect="duckdb",
        graph=graph,
        enforcement=graph.enforcement,
    )
    verdicts = decide(resolved, graph.principal("growth-agent"), graph)
    guard = [v for v in verdicts if str(v.code) == "AIRLOCK-130"]
    assert guard and guard[0].action == "note"


def test_unknown_tables_deny_refuses_a_table_the_catalog_does_not_list() -> None:
    from airlock.errors import UnknownTableError

    graph = build_graph()
    with pytest.raises(UnknownTableError):
        resolve("SELECT x FROM ghost", dialect="duckdb", graph=graph, enforcement=graph.enforcement)


def test_unknown_tables_allow_lets_it_through_policy() -> None:
    # The relaxation is that policy stops objecting - the warehouse still decides whether the table
    # exists. Nothing about the catalog is invented to fill the gap.
    graph = _with(unknown_tables="allow")
    resolved = resolve(
        "SELECT x FROM ghost", dialect="duckdb", graph=graph, enforcement=graph.enforcement
    )
    assert not any(
        str(v.code) == "AIRLOCK-403"
        for v in decide(resolved, graph.principal("growth-agent"), graph)
    )


def test_each_relaxation_changes_the_snapshot_hash() -> None:
    # If a relaxation did not move the hash, the decision cache could serve plans built under the
    # stricter setting (or the looser one) after a config change. Guarded here as behaviour, not
    # just as a field list.
    base = build_graph().content_hash
    for setting in (
        {"substitution": "off"},
        {"predicate_policy": "transform"},
        {"unknown_tables": "allow"},
        {"lineage_propagation": "off"},  # covered behaviourally in test_lineage_propagation.py
        {"mode": "monitor"},
    ):
        assert _with(**setting).content_hash != base, f"{setting} did not move the hash"
