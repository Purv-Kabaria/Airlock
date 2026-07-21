"""Coverage reporting: rule-aware posture, blind spots, and the advisory name heuristic.

The load-bearing property is that `measure_coverage` never influences enforcement - it reads a
snapshot and returns a report. These tests pin the counting rules and, most importantly, that a
classified column is never reported as a gap (a false positive there would send someone tagging
columns that are already governed).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.unit.conftest import build_graph

from airlock.policy.coverage import measure_coverage
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

PLAIN = dataset_urn("duckdb", "plain")


def _col(name: str, dtype: str = "VARCHAR", tags=(), terms=()) -> ColumnFact:
    return ColumnFact(
        name=name,
        urn=field_urn(PLAIN, name),
        data_type=dtype,
        tags=frozenset(tags),
        glossary_terms=frozenset(terms),
    )


def _graph(
    columns: tuple[ColumnFact, ...],
    *,
    rules: tuple[Rule, ...] = (),
    owners: tuple[str, ...] = ("data-eng",),
    domain: str | None = "Marketing",
    principals: dict[str, Principal] | None = None,
    lifecycle: str | None = None,
) -> PolicyGraph:
    ds = DatasetFacts(
        urn=PLAIN,
        platform="duckdb",
        name="plain",
        env="PROD",
        columns=columns,
        domain=domain,
        owners=owners,
        lifecycle=lifecycle,
    )
    return PolicyGraph.build(
        datasets={PLAIN: ds},
        lineage={},
        rules=rules,
        enforcement=EnforcementSettings(),
        principals=principals
        if principals is not None
        else {"a": Principal("a", Scope(domains=frozenset({"Marketing"})))},
        compiled_at=datetime.now(UTC),
        source_url="http://localhost:9002",
    )


MASK_PII = Rule.make("pii", Match(tag="PII"), ActionSpec(ActionKind.MASK, "auto"))
DENY_SSN = Rule.make("ssn", Match(glossary_term="Classification.SSN"), ActionSpec(ActionKind.DENY))


def test_counts_governed_masked_and_denied_separately() -> None:
    report = measure_coverage(build_graph())

    # email is tagged PII (mask) on both users_raw and dim_users; salary on payroll is the third.
    assert report.masked_columns == 3
    assert report.denied_columns == 2  # ssn on users_raw and dim_users
    assert report.governed_columns == 5
    assert report.total_datasets == 4


def test_classified_but_ungoverned_column_is_not_counted_as_governed() -> None:
    """A tag no rule mentions is catalog metadata, not enforcement. This distinction is the
    reason coverage is rule-aware rather than a tag census."""
    report = measure_coverage(_graph((_col("region", tags=["Geo"]),), rules=(MASK_PII,)))

    assert report.classified_columns == 1
    assert report.governed_columns == 0
    assert report.classified_pct == 100.0
    assert report.governed_pct == 0.0


def test_unclassified_sensitive_name_is_flagged_at_risk() -> None:
    report = measure_coverage(_graph((_col("id", "BIGINT"), _col("email")), rules=(MASK_PII,)))

    assert report.grade == "at-risk"
    assert [g.column for g in report.suspected_gaps] == ["email"]
    gap = report.suspected_gaps[0]
    assert gap.subject == "column:plain.email"
    assert gap.reason == "email address"
    assert gap.dataset_urn == PLAIN


def test_governed_column_is_never_reported_as_a_gap() -> None:
    """False positives here would send someone to tag a column Airlock already masks."""
    report = measure_coverage(_graph((_col("email", tags=["PII"]),), rules=(MASK_PII,)))

    assert report.suspected_gaps == ()
    assert report.masked_columns == 1


def test_denied_column_is_never_reported_as_a_gap() -> None:
    report = measure_coverage(
        _graph((_col("ssn", terms=["Classification.SSN"]),), rules=(DENY_SSN,))
    )

    assert report.suspected_gaps == ()
    assert report.denied_columns == 1


def test_classification_without_a_matching_rule_still_flags_the_gap() -> None:
    """Tagging a column does not protect it if no rule acts on that tag - the most dangerous
    false sense of security this report exists to surface."""
    report = measure_coverage(_graph((_col("email", tags=["Reviewed"]),), rules=(MASK_PII,)))

    assert report.grade == "at-risk"
    assert [g.column for g in report.suspected_gaps] == ["email"]
    assert report.classified_columns == 1


@pytest.mark.parametrize(
    ("column", "expected"),
    [
        ("user_email", "email address"),
        ("emailer_config", None),  # token split prevents the substring false positive
        ("SSN", "national identifier"),
        ("date_of_birth", "date of birth"),
        ("credit_card_number", "payment instrument"),
        ("home_address", "postal address"),
        ("addressee", None),
        ("id", None),
        ("total", None),
        ("name", None),  # too ambiguous to flag: table_name, first_name, brand_name
    ],
)
def test_name_heuristic_boundaries(column: str, expected: str | None) -> None:
    report = measure_coverage(_graph((_col(column),)))
    found = report.suspected_gaps[0].reason if report.suspected_gaps else None
    assert found == expected


def test_dead_rule_is_reported() -> None:
    unused = Rule.make("gdpr", Match(tag="GDPR"), ActionSpec(ActionKind.MASK, "auto"))
    report = measure_coverage(_graph((_col("email", tags=["PII"]),), rules=(MASK_PII, unused)))

    assert report.dead_rules == ("gdpr",)
    assert report.grade == "gaps"


def test_substitution_rule_counts_as_fired_on_dataset_facts() -> None:
    """Table-level rules never match a column, so they must be credited at dataset level or they
    would be reported dead on a catalog where they work."""
    sub = Rule.make(
        "dep", Match(lifecycle="DEPRECATED"), ActionSpec(ActionKind.SUBSTITUTE_CERTIFIED)
    )
    report = measure_coverage(_graph((_col("id", "BIGINT"),), rules=(sub,), lifecycle="DEPRECATED"))

    assert report.dead_rules == ()


def test_orphan_deprecated_dataset_is_reported() -> None:
    report = measure_coverage(_graph((_col("id", "BIGINT"),), lifecycle="DEPRECATED"))

    assert [g.name for g in report.orphan_deprecated] == ["plain"]


def test_deprecated_with_certified_substitute_is_not_orphan() -> None:
    report = measure_coverage(build_graph())

    assert report.orphan_deprecated == ()  # users_raw redirects to certified dim_users


def test_unowned_and_unreachable_datasets_are_reported() -> None:
    report = measure_coverage(
        _graph(
            (_col("id", "BIGINT"),),
            owners=(),
            domain="Payroll",
            principals={"a": Principal("a", Scope(domains=frozenset({"Marketing"})))},
        )
    )

    assert [g.name for g in report.unowned_datasets] == ["plain"]
    assert [g.name for g in report.unreachable_datasets] == ["plain"]
    assert "Payroll" in report.unreachable_datasets[0].detail


def test_anonymous_principal_does_not_make_everything_unreachable() -> None:
    report = measure_coverage(
        _graph((_col("id", "BIGINT"),), principals={"anonymous": Principal.anonymous()})
    )

    assert report.unreachable_datasets == ()


def test_clear_posture_when_nothing_is_blind() -> None:
    report = measure_coverage(
        _graph((_col("email", tags=["PII"]), _col("id", "BIGINT")), rules=(MASK_PII,))
    )

    assert report.grade == "clear"
    assert report.is_clear


def test_report_is_deterministic_for_a_snapshot() -> None:
    graph = build_graph()

    assert measure_coverage(graph) == measure_coverage(graph)


def test_empty_catalog_does_not_divide_by_zero() -> None:
    report = measure_coverage(_graph(()))

    assert report.governed_pct == 0.0
    assert report.classified_pct == 0.0
