"""DataHub write-back: the loop-closing sink. The only module that writes to DataHub.

Every decision updates the datasets it touched with structured properties the governance team can
see and query in DataHub itself:
  * airlock.lastAgentAccess   - "<iso-ts> by <principal>"
  * airlock.lastPolicySnapshot - the snapshot hash that made the decision
  * airlock.deniedAttempts    - a cumulative count, incremented on every denial
and appends a one-line institutional-memory ledger element.

It also writes agent read activity back as `datasetUsageStatistics`, DataHub's native usage aspect,
which renders in the stock Stats tab: queries per dataset, reads per column, and a per-principal
breakdown. Airlock is the only door agents have to the warehouse, so it is the only place that
knows this - a warehouse query log attributes every agent to one service account, if it can see
them at all.

Write-back is off the request path and best-effort: any failure is logged and never fails a query
(README §12). Property definitions are created idempotently on first use so the properties render
on the dataset page.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from airlock.audit.record import AuditRecord
from airlock.config import AirlockConfig
from airlock.logging import get_logger

log = get_logger("airlock.audit.datahub")

_ACTOR = "urn:li:corpuser:airlock"
_ENTITY_TYPES = ["urn:li:entityType:datahub.dataset"]
_PROP_LAST_ACCESS = "airlock.lastAgentAccess"
_PROP_SNAPSHOT = "airlock.lastPolicySnapshot"
_PROP_DENIED = "airlock.deniedAttempts"
_PROP_SUSPECTED = "airlock.suspectedSensitive"

_DAY_MS = 86_400_000  # DataHub usage buckets are daily
_TOP_SQL = 5  # how many distinct queries to surface per dataset per day
_SQL_CHARS = 2000  # cap query text so one pathological query cannot bloat the aspect


@dataclass
class _DayUsage:
    """Running tally for one dataset on one UTC day.

    Re-emitted in full on every update rather than as a delta: DataHub keys a timeseries document by
    (urn, aspect, bucket), so writing the same bucket again replaces it. That makes the write
    idempotent and self-healing - a dropped write-back is corrected by the next query, and a
    restart reseeds from whatever DataHub already has for the day.
    """

    queries: int = 0
    by_principal: Counter[str] = field(default_factory=Counter)
    by_column: Counter[str] = field(default_factory=Counter)
    by_sql: Counter[str] = field(default_factory=Counter)

    def record(self, principal: str, columns: list[str], sql: str) -> None:
        self.queries += 1
        self.by_principal[principal] += 1
        self.by_column.update(columns)
        self.by_sql[sql[:_SQL_CHARS]] += 1


class DatahubLedgerSink:
    background = True  # runs off the request path; see Gateway._audit

    def __init__(self, config: AirlockConfig) -> None:
        self._config = config
        self._client: Any | None = None
        self._defined = False
        # Serialize write-backs: each one is a read-modify-write on per-dataset structured
        # properties (the denied-attempts counter), so concurrent writes would race and lose
        # increments. This is off the request path, so serializing costs nothing that matters.
        self._lock = asyncio.Lock()
        self._usage: dict[tuple[str, int], _DayUsage] = {}

    async def write(self, record: AuditRecord) -> None:
        try:
            async with self._lock:
                await asyncio.to_thread(self._write_sync, record)
        except Exception as exc:
            log.warning("writeback.failed", request_id=record.request_id, detail=str(exc))

    def _write_sync(self, record: AuditRecord) -> None:
        client = self._ensure_client()
        self._ensure_definitions(client)
        for urn in record.dataset_urns:
            self._write_dataset(client, urn, record)
        if self._config.audit.datahub_usage:
            self._write_usage(client, record)

    def _write_usage(self, client: Any, record: AuditRecord) -> None:
        """Fold this query into the day's tally for each dataset it read, and re-emit the bucket."""
        from datahub.emitter.mcp import MetadataChangeProposalWrapper

        bucket = (int(time.time() * 1000) // _DAY_MS) * _DAY_MS
        self._usage = {k: v for k, v in self._usage.items() if k[1] == bucket}
        for urn, columns in record.column_reads.items():
            tally = self._usage.get((urn, bucket))
            if tally is None:
                tally = self._seed_usage(client, urn, bucket)
                self._usage[(urn, bucket)] = tally
            tally.record(record.principal, columns, record.executed_sql or record.original_sql)
            client.emit_mcp(
                MetadataChangeProposalWrapper(entityUrn=urn, aspect=_usage_aspect(tally, bucket))
            )

    def _seed_usage(self, client: Any, urn: str, bucket: int) -> _DayUsage:
        """Start the day's tally from whatever DataHub already holds for this bucket, so a gateway
        restart mid-day continues the count instead of resetting it to one."""
        from datahub.metadata.schema_classes import DatasetUsageStatisticsClass

        tally = _DayUsage()
        existing = client.get_latest_timeseries_value(
            entity_urn=urn, aspect_type=DatasetUsageStatisticsClass, filter_criteria_map={}
        )
        if existing is None or existing.timestampMillis != bucket:
            return tally
        tally.queries = existing.totalSqlQueries or 0
        for user in existing.userCounts or []:
            tally.by_principal[user.user.split(":")[-1]] = user.count
        for fc in existing.fieldCounts or []:
            tally.by_column[fc.fieldPath] = fc.count
        for sql in existing.topSqlQueries or []:
            tally.by_sql[sql] += 1
        return tally

    def _write_dataset(self, client: Any, urn: str, record: AuditRecord) -> None:
        from datahub.emitter.mcp import MetadataChangeProposalWrapper
        from datahub.metadata.schema_classes import (
            AuditStampClass,
            InstitutionalMemoryClass,
            InstitutionalMemoryMetadataClass,
            StructuredPropertyValueAssignmentClass,
        )

        stamp = AuditStampClass(time=int(time.time() * 1000), actor=_ACTOR)
        denied_count = self._next_denied_count(client, urn, record.denied)
        assignments = [
            StructuredPropertyValueAssignmentClass(
                propertyUrn=_prop_urn(_PROP_LAST_ACCESS),
                values=[f"{record.ts} by {record.principal}"],
            ),
            StructuredPropertyValueAssignmentClass(
                propertyUrn=_prop_urn(_PROP_SNAPSHOT), values=[record.snapshot_hash or "unknown"]
            ),
            StructuredPropertyValueAssignmentClass(
                propertyUrn=_prop_urn(_PROP_DENIED), values=[float(denied_count)]
            ),
        ]
        # Merge, don't overwrite: a StructuredProperties aspect is the full set, so emitting only the
        # audit assignments would wipe a suspected-sensitive proposal (`airlock propose`) on the same
        # dataset. Keep every foreign assignment; replace only our three.
        _merge_and_emit(client, urn, assignments)

        summary = (
            f"{record.principal} ran {record.request_id} ({record.status}); "
            f"verdicts: {', '.join(v.code for v in record.verdicts) or 'none'}"
        )
        elements = self._existing_memory(client, urn)
        elements.append(
            InstitutionalMemoryMetadataClass(
                url=f"{self._config.datahub.url.rstrip('/')}/airlock/{record.request_id}",
                description=f"airlock: {summary}",
                createStamp=stamp,
            )
        )
        client.emit_mcp(
            MetadataChangeProposalWrapper(
                entityUrn=urn, aspect=InstitutionalMemoryClass(elements=elements[-50:])
            )
        )

    def _next_denied_count(self, client: Any, urn: str, denied: bool) -> int:
        if not denied:
            return self._current_denied(client, urn)
        return self._current_denied(client, urn) + 1

    def _current_denied(self, client: Any, urn: str) -> int:
        from datahub.metadata.schema_classes import StructuredPropertiesClass

        current = client.get_aspect(entity_urn=urn, aspect_type=StructuredPropertiesClass)
        if current is None:
            return 0
        for prop in current.properties:
            if prop.propertyUrn == _prop_urn(_PROP_DENIED) and prop.values:
                try:
                    return int(float(prop.values[0]))
                except (TypeError, ValueError):
                    return 0
        return 0

    def _existing_memory(self, client: Any, urn: str) -> list[Any]:
        from datahub.metadata.schema_classes import InstitutionalMemoryClass

        current = client.get_aspect(entity_urn=urn, aspect_type=InstitutionalMemoryClass)
        return list(current.elements) if current is not None else []

    def _ensure_definitions(self, client: Any) -> None:
        if self._defined:
            return
        from datahub.emitter.mcp import MetadataChangeProposalWrapper
        from datahub.metadata.schema_classes import StructuredPropertyDefinitionClass

        defs = [
            (_PROP_LAST_ACCESS, "urn:li:dataType:datahub.string", "Airlock last agent access"),
            (_PROP_SNAPSHOT, "urn:li:dataType:datahub.string", "Airlock policy snapshot"),
            (_PROP_DENIED, "urn:li:dataType:datahub.number", "Airlock denied attempts"),
        ]
        for qualified, value_type, display in defs:
            client.emit_mcp(
                MetadataChangeProposalWrapper(
                    entityUrn=_prop_urn(qualified),
                    aspect=StructuredPropertyDefinitionClass(
                        qualifiedName=qualified,
                        valueType=value_type,
                        entityTypes=_ENTITY_TYPES,
                        displayName=display,
                    ),
                )
            )
        self._defined = True

    def _ensure_client(self) -> Any:
        if self._client is None:
            from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph

            self._client = DataHubGraph(
                DatahubClientConfig(
                    server=self._config.datahub.url, token=self._config.datahub.token
                )
            )
        return self._client

    async def close(self) -> None:
        return None


def _prop_urn(qualified: str) -> str:
    return f"urn:li:structuredProperty:{qualified}"


def _usage_aspect(tally: _DayUsage, bucket: int) -> Any:
    from datahub.metadata.schema_classes import (
        CalendarIntervalClass,
        DatasetFieldUsageCountsClass,
        DatasetUsageStatisticsClass,
        DatasetUserUsageCountsClass,
        TimeWindowSizeClass,
    )

    return DatasetUsageStatisticsClass(
        timestampMillis=bucket,
        eventGranularity=TimeWindowSizeClass(unit=CalendarIntervalClass.DAY, multiple=1),
        uniqueUserCount=len(tally.by_principal),
        totalSqlQueries=tally.queries,
        topSqlQueries=[sql for sql, _ in tally.by_sql.most_common(_TOP_SQL)],
        userCounts=[
            DatasetUserUsageCountsClass(user=f"urn:li:corpuser:{name}", count=count)
            for name, count in sorted(tally.by_principal.items())
        ],
        fieldCounts=[
            DatasetFieldUsageCountsClass(fieldPath=column, count=count)
            for column, count in sorted(tally.by_column.items())
        ],
    )


def _merge_and_emit(client: Any, urn: str, new_assignments: list[Any]) -> None:
    """Set `new_assignments` on a dataset's structured-properties aspect while preserving every
    other assignment already there. The aspect is the full set, so a naive emit would drop foreign
    properties; read-modify-write keeps the audit sink and `airlock propose` from clobbering each
    other on a shared dataset."""
    from datahub.emitter.mcp import MetadataChangeProposalWrapper
    from datahub.metadata.schema_classes import StructuredPropertiesClass

    replaced = {a.propertyUrn for a in new_assignments}
    current = client.get_aspect(entity_urn=urn, aspect_type=StructuredPropertiesClass)
    kept = [a for a in (current.properties if current else []) if a.propertyUrn not in replaced]
    client.emit_mcp(
        MetadataChangeProposalWrapper(
            entityUrn=urn, aspect=StructuredPropertiesClass(properties=kept + new_assignments)
        )
    )


def write_classification_proposals(
    config: AirlockConfig, proposals: Mapping[str, tuple[str, ...]]
) -> int:
    """Write Airlock's suspected-sensitive findings back to DataHub as a structured property on each
    dataset, so a steward sees the gateway's suggestion in the catalog and can act on it. Overwrites
    the property (idempotent) and preserves any other Airlock properties already on the dataset.
    Returns the number of datasets written. Raises on connection failure - the caller reports it."""
    if not proposals:
        return 0
    from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph
    from datahub.metadata.schema_classes import StructuredPropertyValueAssignmentClass

    client = DataHubGraph(
        DatahubClientConfig(server=config.datahub.url, token=config.datahub.token)
    )
    _ensure_suspected_definition(client)
    for urn, columns in proposals.items():
        assignment = StructuredPropertyValueAssignmentClass(
            propertyUrn=_prop_urn(_PROP_SUSPECTED), values=list(columns)
        )
        _merge_and_emit(client, urn, [assignment])
    log.info("proposals.written", datasets=len(proposals))
    return len(proposals)


@dataclass(frozen=True, slots=True)
class DatasetUsage:
    """One dataset's agent read activity, as DataHub currently holds it."""

    name: str
    queries: int
    principals: tuple[tuple[str, int], ...]
    columns: tuple[tuple[str, int], ...]


def read_usage(config: AirlockConfig, datasets: Mapping[str, str]) -> list[DatasetUsage]:
    """Read the usage statistics Airlock wrote back, from DataHub, for `datasets` (urn -> name).

    Reads the timeseries aspect directly rather than the GraphQL usage aggregation: GMS caches that
    aggregation for minutes, so a fresh write is invisible there long after it has landed. Datasets
    with no recorded activity are omitted. Raises on connection failure - the caller reports it.
    """
    from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph
    from datahub.metadata.schema_classes import DatasetUsageStatisticsClass

    client = DataHubGraph(
        DatahubClientConfig(server=config.datahub.url, token=config.datahub.token)
    )
    out: list[DatasetUsage] = []
    for urn, name in datasets.items():
        stats = client.get_latest_timeseries_value(
            entity_urn=urn, aspect_type=DatasetUsageStatisticsClass, filter_criteria_map={}
        )
        if stats is None or not stats.totalSqlQueries:
            continue
        out.append(
            DatasetUsage(
                name=name,
                queries=stats.totalSqlQueries,
                principals=tuple((u.user.split(":")[-1], u.count) for u in stats.userCounts or []),
                columns=tuple((f.fieldPath, f.count) for f in stats.fieldCounts or []),
            )
        )
    return sorted(out, key=lambda u: u.queries, reverse=True)


def _ensure_suspected_definition(client: Any) -> None:
    from datahub.emitter.mcp import MetadataChangeProposalWrapper
    from datahub.metadata.schema_classes import StructuredPropertyDefinitionClass

    client.emit_mcp(
        MetadataChangeProposalWrapper(
            entityUrn=_prop_urn(_PROP_SUSPECTED),
            aspect=StructuredPropertyDefinitionClass(
                qualifiedName=_PROP_SUSPECTED,
                valueType="urn:li:dataType:datahub.string",
                entityTypes=_ENTITY_TYPES,
                displayName="Airlock suspected-sensitive columns",
                cardinality="MULTIPLE",
            ),
        )
    )
