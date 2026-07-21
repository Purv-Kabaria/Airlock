"""Agent read activity written back as DataHub dataset usage statistics.

Airlock is the only door agents have to the warehouse, so it is the only place that can tell the
catalog which datasets and columns AI agents actually read. The tally is cumulative per UTC day and
re-emitted whole, because DataHub replaces a timeseries document keyed by (urn, aspect, bucket) -
these tests pin that contract, the restart reseed, and the rule that denied queries are not usage.
No network: the DataHub client is faked behind the two methods the sink calls.
"""

from __future__ import annotations

import time
from typing import Any

from datahub.metadata.schema_classes import (
    CalendarIntervalClass,
    DatasetFieldUsageCountsClass,
    DatasetUsageStatisticsClass,
    DatasetUserUsageCountsClass,
    TimeWindowSizeClass,
)

from airlock.audit.datahub_sink import _DAY_MS, DatahubLedgerSink, _usage_aspect
from airlock.audit.record import AuditRecord
from airlock.config import AirlockConfig

ORDERS = "urn:li:dataset:(urn:li:dataPlatform:duckdb,orders,PROD)"


def _config(*, usage: bool = True) -> AirlockConfig:
    return AirlockConfig.model_validate(
        {
            "datahub": {"url": "http://datahub.invalid"},
            "warehouse": {"kind": "duckdb", "dsn": "./x.duckdb"},
            "rules": [],
            "audit": {"datahub_usage": usage},
        }
    )


class FakeGraph:
    """Records every emitted usage aspect and serves a preset timeseries value back."""

    def __init__(self, existing: DatasetUsageStatisticsClass | None = None) -> None:
        self.existing = existing
        self.usage: list[DatasetUsageStatisticsClass] = []

    def get_latest_timeseries_value(
        self, *, entity_urn: str, aspect_type: type, filter_criteria_map: dict[str, str]
    ) -> DatasetUsageStatisticsClass | None:
        return self.existing

    def get_aspect(self, *, entity_urn: str, aspect_type: type) -> object | None:
        return None

    def emit_mcp(self, mcp: Any) -> None:
        if isinstance(mcp.aspect, DatasetUsageStatisticsClass):
            self.usage.append(mcp.aspect)


def _record(principal: str, sql: str, columns: dict[str, list[str]]) -> AuditRecord:
    return AuditRecord(
        request_id="req_1",
        ts="2026-07-21T00:00:00+00:00",
        principal=principal,
        status="executed",
        original_sql=sql,
        executed_sql=sql,
        snapshot_hash="sha256:x",
        verdicts=[],
        subjects=[],
        row_count=1,
        truncated=False,
        latency_ms=1.0,
        coalesced=False,
        warehouse="duckdb",
        dataset_urns=list(columns),
        column_reads=columns,
    )


def _sink(graph: FakeGraph, *, usage: bool = True) -> DatahubLedgerSink:
    sink = DatahubLedgerSink(_config(usage=usage))
    sink._client = graph
    sink._defined = True
    return sink


def test_repeated_queries_accumulate_into_one_daily_bucket() -> None:
    graph = FakeGraph()
    sink = _sink(graph)
    for _ in range(3):
        sink._write_usage(graph, _record("growth-agent", "SELECT id FROM orders", {ORDERS: ["id"]}))

    assert len(graph.usage) == 3  # one emit per query, each replacing the bucket
    last = graph.usage[-1]
    assert last.totalSqlQueries == 3
    assert [(f.fieldPath, f.count) for f in last.fieldCounts or []] == [("id", 3)]
    assert len({u.timestampMillis for u in graph.usage}) == 1  # all three hit the same bucket


def test_columns_and_principals_are_counted_separately() -> None:
    graph = FakeGraph()
    sink = _sink(graph)
    sink._write_usage(
        graph, _record("growth-agent", "SELECT id, total FROM orders", {ORDERS: ["id", "total"]})
    )
    sink._write_usage(graph, _record("finance-agent", "SELECT id FROM orders", {ORDERS: ["id"]}))

    last = graph.usage[-1]
    assert last.totalSqlQueries == 2
    assert last.uniqueUserCount == 2
    assert {f.fieldPath: f.count for f in last.fieldCounts or []} == {"id": 2, "total": 1}
    assert {u.user: u.count for u in last.userCounts or []} == {
        "urn:li:corpuser:growth-agent": 1,
        "urn:li:corpuser:finance-agent": 1,
    }


def test_a_denied_query_is_not_counted_as_usage() -> None:
    graph = FakeGraph()
    sink = _sink(graph)
    # The gateway leaves column_reads empty on a denied plan: nothing was read.
    sink._write_usage(graph, _record("growth-agent", "SELECT ssn FROM orders", {}))
    assert graph.usage == []


def test_a_restart_resumes_the_day_from_what_datahub_already_has() -> None:
    bucket = (int(time.time() * 1000) // _DAY_MS) * _DAY_MS
    existing = DatasetUsageStatisticsClass(
        timestampMillis=bucket,
        eventGranularity=TimeWindowSizeClass(unit=CalendarIntervalClass.DAY, multiple=1),
        uniqueUserCount=1,
        totalSqlQueries=40,
        userCounts=[DatasetUserUsageCountsClass(user="urn:li:corpuser:growth-agent", count=40)],
        fieldCounts=[DatasetFieldUsageCountsClass(fieldPath="id", count=40)],
    )
    graph = FakeGraph(existing)
    sink = _sink(graph)
    sink._write_usage(graph, _record("growth-agent", "SELECT id FROM orders", {ORDERS: ["id"]}))

    last = graph.usage[-1]
    assert last.totalSqlQueries == 41  # continues the day, does not reset to 1
    assert {f.fieldPath: f.count for f in last.fieldCounts or []} == {"id": 41}


def test_a_stale_bucket_from_a_previous_day_does_not_seed_today() -> None:
    bucket = (int(time.time() * 1000) // _DAY_MS) * _DAY_MS
    yesterday = DatasetUsageStatisticsClass(
        timestampMillis=bucket - _DAY_MS,
        eventGranularity=TimeWindowSizeClass(unit=CalendarIntervalClass.DAY, multiple=1),
        uniqueUserCount=1,
        totalSqlQueries=900,
    )
    graph = FakeGraph(yesterday)
    sink = _sink(graph)
    sink._write_usage(graph, _record("growth-agent", "SELECT id FROM orders", {ORDERS: ["id"]}))

    assert graph.usage[-1].totalSqlQueries == 1


def test_usage_writeback_can_be_turned_off() -> None:
    graph = FakeGraph()
    sink = _sink(graph, usage=False)
    sink._write_sync(_record("growth-agent", "SELECT id FROM orders", {ORDERS: ["id"]}))
    assert graph.usage == []


def test_top_sql_is_bounded_and_ordered_by_frequency() -> None:
    graph = FakeGraph()
    sink = _sink(graph)
    for i in range(8):
        for _ in range(8 - i):  # query 0 runs 8 times, query 7 once
            sink._write_usage(
                graph, _record("growth-agent", f"SELECT c{i} FROM orders", {ORDERS: [f"c{i}"]})
            )

    top = graph.usage[-1].topSqlQueries or []
    assert len(top) == 5
    assert top[0] == "SELECT c0 FROM orders"


def test_the_emitted_aspect_uses_a_daily_window() -> None:
    from airlock.audit.datahub_sink import _DayUsage

    tally = _DayUsage()
    tally.record("growth-agent", ["id"], "SELECT id FROM orders")
    aspect = _usage_aspect(tally, 0)
    assert aspect.eventGranularity.unit == CalendarIntervalClass.DAY
    assert aspect.eventGranularity.multiple == 1
