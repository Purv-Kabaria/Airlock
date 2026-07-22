"""Classification propagation along DataHub column-level lineage.

A column the catalog never tagged inherits masking/denial from the columns it derives from, so
sensitive data that flows into a derived table is protected without waiting for someone to re-tag
it. This is the behavior DataHub Cloud offers as a term-propagation automation; Airlock does it
deterministically at enforcement time, on open-source DataHub.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from airlock.analyzer.resolve import resolve
from airlock.engine.decide import Outcome, column_outcome, decide
from airlock.policy.graph import (
    ColumnFact,
    DatasetFacts,
    EnforcementSettings,
    PolicyGraph,
    Principal,
)
from airlock.policy.rules import ActionKind, ActionSpec, Match, Rule
from airlock.urns import dataset_urn, field_urn

RAW = dataset_urn("duckdb", "raw_events")
SUMMARY = dataset_urn("duckdb", "summary")


def _col(ds: str, name: str, *, tags: Sequence[str] = (), terms: Sequence[str] = ()) -> ColumnFact:
    return ColumnFact(
        name, field_urn(ds, name), "VARCHAR", tags=frozenset(tags), glossary_terms=frozenset(terms)
    )


def _graph(*, propagation: str = "on") -> PolicyGraph:
    raw = DatasetFacts(
        urn=RAW,
        platform="duckdb",
        name="raw_events",
        env="PROD",
        columns=(
            _col(RAW, "email", tags=["PII"]),
            _col(RAW, "ssn", terms=["Classification.SSN"]),
        ),
        domain="Marketing",
    )
    # summary.contact <- raw.email (PII), summary.national_id <- raw.ssn (denied), summary.note <- nothing
    summary = DatasetFacts(
        urn=SUMMARY,
        platform="duckdb",
        name="summary",
        env="PROD",
        columns=(_col(SUMMARY, "contact"), _col(SUMMARY, "national_id"), _col(SUMMARY, "note")),
        domain="Marketing",
    )
    rules = (
        Rule.make("pii", Match(tag="PII"), ActionSpec(ActionKind.MASK, "auto")),
        Rule.make("ssn", Match(glossary_term="Classification.SSN"), ActionSpec(ActionKind.DENY)),
    )
    return PolicyGraph.build(
        datasets={RAW: raw, SUMMARY: summary},
        lineage={},
        column_lineage={
            field_urn(SUMMARY, "contact"): (field_urn(RAW, "email"),),
            field_urn(SUMMARY, "national_id"): (field_urn(RAW, "ssn"),),
        },
        rules=rules,
        enforcement=EnforcementSettings(lineage_propagation=propagation),
        principals={"a": Principal("a")},
        compiled_at=datetime.now(UTC),
        source_url="http://x",
    )


def _outcome(graph: PolicyGraph, dataset_urn_: str, column: str) -> Outcome:
    ds = graph.dataset(dataset_urn_)
    assert ds is not None
    fact = ds.column(column)
    assert fact is not None
    return column_outcome(ds, fact, graph)


def test_untagged_column_inherits_masking_from_the_column_it_derives_from() -> None:
    out = _outcome(_graph(), SUMMARY, "contact")
    assert out.kind == "mask"
    assert out.propagated_from == "raw_events.email"


def test_untagged_column_inherits_denial_from_the_column_it_derives_from() -> None:
    out = _outcome(_graph(), SUMMARY, "national_id")
    assert out.kind == "deny"
    assert out.propagated_from == "raw_events.ssn"


def test_a_column_with_no_sensitive_upstream_is_left_alone() -> None:
    assert _outcome(_graph(), SUMMARY, "note").kind == "allow"


def test_directly_classified_column_keeps_its_own_classification_not_an_inherited_one() -> None:
    out = _outcome(_graph(), RAW, "email")
    assert out.kind == "mask"
    assert out.propagated_from is None  # direct, not inherited


def test_propagation_can_be_turned_off() -> None:
    assert _outcome(_graph(propagation="off"), SUMMARY, "contact").kind == "allow"


def test_transitive_propagation_follows_multiple_hops() -> None:
    """contact <- mid <- raw.email, where mid is itself untagged. The classification still lands."""
    g = _graph()
    mid = field_urn(SUMMARY, "note")  # reuse note as an intermediate, untagged, derived from email
    graph = PolicyGraph.build(
        datasets=dict(g.datasets),
        lineage={},
        column_lineage={
            field_urn(SUMMARY, "contact"): (mid,),
            mid: (field_urn(RAW, "email"),),
        },
        rules=g.rules,
        enforcement=g.enforcement,
        principals=dict(g.principals),
        compiled_at=datetime.now(UTC),
        source_url="http://x",
    )
    out = _outcome(graph, SUMMARY, "contact")
    assert out.kind == "mask"
    assert out.propagated_from == "raw_events.email"


def test_decide_emits_the_lineage_reason_code() -> None:
    graph = _graph()
    resolved = resolve(
        "SELECT contact FROM summary", dialect="duckdb", graph=graph, enforcement=graph.enforcement
    )
    verdicts = decide(resolved, graph.principal("a") or Principal.anonymous(), graph)
    assert any(v.code == "AIRLOCK-113" for v in verdicts)  # MASK_LINEAGE


def test_a_lineage_governed_column_is_not_a_coverage_gap() -> None:
    from airlock.policy.coverage import measure_coverage

    report = measure_coverage(_graph())
    # raw.email + raw.ssn (direct) and summary.contact + summary.national_id (propagated) = 4.
    assert report.governed_columns == 4
    assert all("contact" not in g.column for g in report.suspected_gaps)


def test_column_lineage_survives_the_snapshot_round_trip(tmp_path) -> None:
    """A restored snapshot must decide exactly as strictly as the one it was saved from.

    Only `lineage.downstream` used to be persisted, so a graph rebuilt from disk had no column-level
    edges. Classification propagation then stopped firing and a derived PII column came back in the
    clear -- on the stale-serving path, which is precisely when nobody is watching.
    """
    from airlock.policy.store import SnapshotStore

    graph = _graph()
    store = SnapshotStore(str(tmp_path / "snap.sqlite"))
    store.install(graph)

    persisted = store.persisted_catalog()
    assert persisted is not None
    assert dict(persisted.column_lineage) == dict(graph.lineage.column_upstreams)
    assert persisted.column_lineage, "fixture must carry column lineage for this to prove anything"


def test_a_snapshot_written_before_column_lineage_still_loads(tmp_path) -> None:
    # Forward compatibility: an older payload has no such key and must not fail the whole catalog.
    import json
    import sqlite3

    from airlock.policy.store import SnapshotStore

    path = tmp_path / "old.sqlite"
    store = SnapshotStore(str(path))
    store.install(_graph())
    with sqlite3.connect(path) as conn:
        (payload,) = conn.execute("SELECT payload FROM snapshots").fetchone()
        data = json.loads(payload)
        del data["column_lineage"]
        conn.execute("UPDATE snapshots SET payload = ?", (json.dumps(data),))
        conn.commit()

    restored = SnapshotStore(str(path)).persisted_catalog()
    assert restored is not None
    assert restored.column_lineage == {}
    assert restored.datasets  # the rest of the catalog is intact
