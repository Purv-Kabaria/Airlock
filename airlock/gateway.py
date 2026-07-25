"""The runtime that turns a query into an envelope: pin snapshot, decide, execute, audit.

`engine.decide` is the pure core; this is the impure shell around it — the piece that touches the
warehouse, the clock, the caches, and the audit sinks. Each request pins the current snapshot at
ingress (lock-free), plans the decision (cached on `(sql, principal, snapshot_hash)`), coalesces
identical in-flight executions, and enforces a bounded concurrency queue. Nothing on the read path
waits on DataHub.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime

from airlock.analyzer.resolve import ResolvedQuery, resolve
from airlock.analyzer.rewrite import rewrite
from airlock.audit.jsonl import JsonlSink
from airlock.audit.record import AuditRecord, Sink
from airlock.config import AirlockConfig
from airlock.engine.decide import decide, effective_row_limit, statement_is_denied
from airlock.engine.verdicts import Envelope, ReasonCode, Subject, Verdict
from airlock.errors import (
    AirlockError,
    OverloadedError,
    SnapshotUnavailableError,
    StaleSnapshotError,
)
from airlock.exec.base import QueryResult, WarehouseAdapter, make_adapter
from airlock.logging import get_logger
from airlock.policy.graph import PolicyGraph, Principal
from airlock.policy.store import SnapshotStore

log = get_logger("airlock.gateway")

_STRUCTURAL_DENY = frozenset({ReasonCode.STATEMENT_CLASS, ReasonCode.UNKNOWN_PRINCIPAL})


@dataclass(frozen=True, slots=True)
class Plan:
    verdicts: tuple[Verdict, ...]
    dataset_urns: tuple[str, ...]
    row_limit: int
    timeout: float
    error: Verdict | None = None
    denied: bool = False
    executed_sql: str | None = None  # real SQL for the warehouse; carries the masking salt
    display_sql: str | None = None  # salt-redacted; what the envelope, audit, and write-back use
    modified: bool = False
    masked_outputs: tuple[tuple[str, str], ...] = ()
    # (dataset_urn, column) actually read, for the DataHub usage write-back. Empty on denied plans:
    # a blocked query read nothing, and counting it as usage would misreport the catalog.
    column_reads: tuple[tuple[str, str], ...] = ()


@dataclass
class _Inflight:
    future: asyncio.Future[QueryResult]
    waiters: int = 1


class Gateway:
    def __init__(
        self,
        config: AirlockConfig,
        store: SnapshotStore,
        adapter: WarehouseAdapter,
        sinks: list[Sink],
        *,
        max_concurrency: int = 64,
        burst: int = 200,
        cache_size: int = 2048,
        writeback_queue: int = 512,
    ) -> None:
        self._config = config
        self._store = store
        self._adapter = adapter
        self._sinks = sinks
        self._dialect = config.warehouse.dialect or config.warehouse.kind
        self._sem = asyncio.Semaphore(max_concurrency)
        self._cap = max_concurrency + burst
        self._inflight_count = 0
        self._coalesce: dict[tuple[str, str], _Inflight] = {}
        self._cache: OrderedDict[tuple[str, str, str], Plan] = OrderedDict()
        self._cache_size = cache_size
        self._mask_salt = config.masking.salt
        # Remote audit sinks (DataHub write-back, OTel) run off the request path so a query never
        # waits on the catalog or the ledger (README "Off-path everything"). Records are handed to a
        # single drain worker through a bounded queue: DataHub write-back is network-bound and
        # serialized, so an unbounded hand-off would let the backlog grow without limit under
        # sustained load. When the queue is full we drop the *remote* copy with a loud counter — the
        # local JSONL sink is awaited on the request path and remains the durable source of truth.
        self._remote_sinks = [s for s in sinks if getattr(s, "background", False)]
        self._local_sinks = [s for s in sinks if not getattr(s, "background", False)]
        self._writeback_cap = writeback_queue
        self._writeback_queue: asyncio.Queue[AuditRecord] | None = None
        self._writeback_worker: asyncio.Task[None] | None = None
        self._writeback_dropped = 0

    @classmethod
    def build(
        cls, config: AirlockConfig, *, snapshot_db: str = ".airlock/snapshots.sqlite"
    ) -> Gateway:
        """Construct the full runtime (store, adapter, sinks) from config."""
        store = SnapshotStore(snapshot_db)
        adapter = make_adapter(config.warehouse, pool_size=config.server.connection_pool)
        sinks: list[Sink] = [JsonlSink(config.audit.jsonl)]
        if config.audit.datahub_writeback:
            from airlock.audit.datahub_sink import DatahubLedgerSink

            sinks.append(DatahubLedgerSink(config))
        if config.audit.otel.enabled:
            from airlock.audit.otel import OtelSink

            sinks.append(OtelSink(config.audit.otel.endpoint))
        return cls(
            config,
            store,
            adapter,
            sinks,
            max_concurrency=config.server.max_concurrency,
            burst=config.server.burst,
            cache_size=config.server.decision_cache,
            writeback_queue=config.server.writeback_queue,
        )

    async def bootstrap(self) -> None:
        """Load the first snapshot. Fail fast if DataHub is unreachable (README §10), unless
        a persisted snapshot exists and stale-serving is enabled."""
        try:
            await self.refresh()
            return
        except SnapshotUnavailableError:
            persisted = self._store.persisted_catalog()
            allow_stale = self._config.datahub.snapshot.stale_policy == "serve_stale_readonly"
            if persisted is None or not allow_stale:
                raise
            self._store.install(self._graph_from_persisted())
            log.warning("snapshot.stale_bootstrap", compiled_at=persisted.compiled_at.isoformat())

    def bootstrap_offline(self) -> None:
        """Build a snapshot from the last cached catalog + current config, without touching DataHub.

        Lets you iterate on *rules* (which live in airlock.yaml, not DataHub) with fast feedback.
        Facts are whatever the last live refresh cached; run a live refresh to pick up catalog edits.
        """
        self._store.install(self._graph_from_persisted())

    def _graph_from_persisted(self) -> PolicyGraph:
        persisted = self._store.persisted_catalog()
        if persisted is None:
            raise SnapshotUnavailableError(
                "No cached snapshot is available. Run `airlock refresh` once against DataHub first."
            )
        return PolicyGraph.build(
            datasets=dict(persisted.datasets),
            lineage=dict(persisted.lineage),
            rules=self._config.compiled_rules(),
            enforcement=self._config.enforcement_settings(),
            principals=self._config.compiled_principals(),
            compiled_at=persisted.compiled_at,
            source_url=persisted.source_url,
            # Without this the restored graph carries no column-level edges, so classification
            # propagation stops firing and the stale path serves a derived PII column in the clear.
            column_lineage=dict(persisted.column_lineage),
        )

    async def refresh_loop(self) -> None:
        """Background snapshot refresh. Failures are logged and retried on the next tick."""
        interval = self._config.datahub.snapshot.refresh_interval
        while True:
            await asyncio.sleep(interval)
            try:
                await self.refresh()
            except Exception as exc:
                log.warning("snapshot.refresh_failed", detail=str(exc))

    def snapshot(self) -> PolicyGraph | None:
        return self._store.current

    def snapshot_hash(self) -> str | None:
        graph = self._store.current
        return graph.content_hash if graph is not None else None

    def visible_tables(self, principal_name: str) -> list[str]:
        """Catalog tables the principal is scoped to see (README edge 14)."""
        graph = self._store.current
        if graph is None:
            return []
        principal = graph.principal(principal_name) or Principal.anonymous()
        return sorted(
            ds.name
            for ds in graph.datasets.values()
            if principal.scope.permits(domain=ds.domain, platform=ds.platform)
        )

    def table_in_scope(self, principal_name: str, name: str) -> bool:
        graph = self._store.current
        if graph is None:
            return False
        principal = graph.principal(principal_name) or Principal.anonymous()
        ds = graph.dataset_by_name(name)
        if ds is None:
            return False
        return principal.scope.permits(domain=ds.domain, platform=ds.platform)

    # -- public API ------------------------------------------------------------------

    async def run_query(self, sql: str, principal_name: str) -> Envelope:
        request_id = new_request_id()
        start = time.perf_counter()
        graph = self._pinned_snapshot()
        stale_note = self._staleness_note(graph)  # raises 410 if fail_closed past budget
        principal = graph.principal(principal_name) or Principal.anonymous()

        if self._inflight_count >= self._cap:
            raise OverloadedError(retry_after_ms=100)
        self._inflight_count += 1
        try:
            async with self._sem:
                plan = self._plan(sql, principal, graph)
                envelope, coalesced = await self._materialize(
                    request_id, sql, principal, graph, plan, stale_note
                )
        finally:
            self._inflight_count -= 1

        latency_ms = (time.perf_counter() - start) * 1000
        await self._audit(
            envelope,
            latency_ms=latency_ms,
            coalesced=coalesced,
            dataset_urns=list(plan.dataset_urns),
            column_reads=plan.column_reads,
        )
        log.info(
            "decision.made",
            request_id=request_id,
            principal=principal.name,
            status=str(envelope.status),
            verdicts=len(envelope.verdicts),
            latency_ms=round(latency_ms, 2),
        )
        return envelope

    def dry_run(self, sql: str, principal_name: str) -> Envelope:
        """Decide without executing (CLI `check`). Pure with respect to the warehouse."""
        request_id = new_request_id()
        graph = self._pinned_snapshot()
        principal = graph.principal(principal_name) or Principal.anonymous()
        plan = self._plan(sql, principal, graph)
        verdicts = list(plan.verdicts)
        if plan.error is not None:
            return Envelope.error(
                request_id=request_id,
                principal=principal.name,
                original_sql=sql,
                verdict=plan.error,
                snapshot=graph.content_hash,
            )
        if plan.denied:
            return Envelope.denied(
                request_id=request_id,
                principal=principal.name,
                original_sql=sql,
                verdicts=verdicts,
                snapshot=graph.content_hash,
            )
        return Envelope.executed(
            request_id=request_id,
            principal=principal.name,
            original_sql=sql,
            executed_sql=plan.display_sql or sql,  # salt-redacted; `check` output is screenshotted
            columns=None,
            rows=None,
            verdicts=verdicts,
            snapshot=graph.content_hash,
            truncated=False,
            modified=plan.modified,
        )

    # -- request lifecycle -----------------------------------------------------------

    async def _materialize(
        self,
        request_id: str,
        sql: str,
        principal: Principal,
        graph: PolicyGraph,
        plan: Plan,
        stale_note: Verdict | None,
    ) -> tuple[Envelope, bool]:
        verdicts = list(plan.verdicts)
        if stale_note is not None:
            verdicts.append(stale_note)

        if plan.error is not None:
            return (
                Envelope.error(
                    request_id=request_id,
                    principal=principal.name,
                    original_sql=sql,
                    verdict=plan.error,
                    snapshot=graph.content_hash,
                ),
                False,
            )
        if plan.denied:
            return (
                Envelope.denied(
                    request_id=request_id,
                    principal=principal.name,
                    original_sql=sql,
                    verdicts=verdicts,
                    snapshot=graph.content_hash,
                ),
                False,
            )

        assert plan.executed_sql is not None
        assert plan.display_sql is not None  # set together in _build_plan; both present on an exec plan
        try:
            result, coalesced = await self._execute(principal.name, plan)
            _verify_masking(plan, result)
        except AirlockError as exc:
            return (
                Envelope.error(
                    request_id=request_id,
                    principal=principal.name,
                    original_sql=sql,
                    verdict=exc.to_verdict(),
                    snapshot=graph.content_hash,
                ),
                False,
            )
        envelope = Envelope.executed(
            request_id=request_id,
            principal=principal.name,
            original_sql=sql,
            # display_sql, never executed_sql: the salt ran on the warehouse but must not ride back
            # out in the envelope, the audit record, or the DataHub write-back this envelope feeds.
            executed_sql=plan.display_sql,
            columns=result.columns,
            rows=result.rows,
            verdicts=verdicts,
            snapshot=graph.content_hash,
            truncated=result.truncated,
            modified=plan.modified,
        )
        return envelope, coalesced

    def _plan(self, sql: str, principal: Principal, graph: PolicyGraph) -> Plan:
        key = (sql, principal.name, graph.content_hash)
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached
        plan = self._build_plan(sql, principal, graph)
        self._cache[key] = plan
        self._cache.move_to_end(key)
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return plan

    def _build_plan(self, sql: str, principal: Principal, graph: PolicyGraph) -> Plan:
        enforcement = graph.enforcement
        row_limit = effective_row_limit(principal, enforcement)
        timeout = principal.statement_timeout or enforcement.default_statement_timeout
        try:
            resolved = resolve(sql, dialect=self._dialect, graph=graph, enforcement=enforcement)
        except AirlockError as exc:
            return Plan(
                verdicts=(exc.to_verdict(),),
                dataset_urns=(),
                row_limit=row_limit,
                timeout=timeout,
                error=exc.to_verdict(),
                denied=True,
            )

        verdicts = decide(resolved, principal, graph)
        dataset_urns = tuple({t.effective.urn for t in resolved.tables if t.effective is not None})
        structural = any(v.code in _STRUCTURAL_DENY for v in verdicts)

        if structural:
            return Plan(
                verdicts=tuple(verdicts),
                dataset_urns=dataset_urns,
                row_limit=row_limit,
                timeout=timeout,
                denied=True,
            )
        if enforcement.is_monitor:
            rr = rewrite(resolved, principal, graph, enforce=False, salt=self._mask_salt)
            note = Verdict.make(
                ReasonCode.MONITOR,
                "note",
                Subject.statement(),
                "Monitor mode: the verdicts below were observed but not applied to the query.",
            )
            return Plan(
                verdicts=(*verdicts, note),
                dataset_urns=dataset_urns,
                row_limit=row_limit,
                timeout=timeout,
                executed_sql=rr.executed_sql,
                display_sql=rr.display_sql,
                modified=False,
                column_reads=_column_reads(resolved),
            )

        if statement_is_denied(verdicts):
            return Plan(
                verdicts=tuple(_without_limit(verdicts)),
                dataset_urns=dataset_urns,
                row_limit=row_limit,
                timeout=timeout,
                denied=True,
            )
        rr = rewrite(resolved, principal, graph, enforce=True, salt=self._mask_salt)
        return Plan(
            verdicts=tuple(verdicts),
            dataset_urns=dataset_urns,
            row_limit=row_limit,
            timeout=timeout,
            executed_sql=rr.executed_sql,
            display_sql=rr.display_sql,
            modified=rr.modified,
            masked_outputs=rr.masked_outputs,
            column_reads=_column_reads(resolved),
        )

    async def _execute(self, principal_name: str, plan: Plan) -> tuple[QueryResult, bool]:
        assert plan.executed_sql is not None
        key = (principal_name, plan.executed_sql)
        existing = self._coalesce.get(key)
        if existing is not None:
            existing.waiters += 1
            try:
                return await asyncio.shield(existing.future), True
            except asyncio.CancelledError:
                # If the shared future is still pending, *we* were cancelled (our client dropped) —
                # propagate. If it is done, the leader was cancelled/failed; fall through and run
                # ourselves so one client's disconnect never fails another's query.
                if not existing.future.done():
                    raise
            except Exception as exc:
                # The leader's execution failed for any reason; fall through and run our own so this
                # waiter gets its own result or error rather than inheriting the leader's.
                log.debug("coalesce.leader_failed", detail=str(exc))

        loop = asyncio.get_running_loop()
        inflight = _Inflight(future=loop.create_future())
        self._coalesce[key] = inflight
        try:
            result = await self._adapter.run(
                plan.executed_sql, timeout=plan.timeout, row_limit=plan.row_limit
            )
            if not inflight.future.done():
                inflight.future.set_result(result)
            return result, False
        except BaseException as exc:  # hand the outcome to any coalesced waiters, then re-raise
            if not inflight.future.done():
                inflight.future.set_exception(exc)
            raise
        finally:
            if self._coalesce.get(key) is inflight:
                self._coalesce.pop(key, None)
            # The leader awaits the adapter directly, never its own future - only coalesced followers
            # await it. With no follower, a failure would leave the exception unretrieved and asyncio
            # would log it at GC. Retrieve it here; followers still receive it when they await.
            if inflight.future.done() and not inflight.future.cancelled():
                inflight.future.exception()

    # -- snapshot / refresh ----------------------------------------------------------

    def _pinned_snapshot(self) -> PolicyGraph:
        graph = self._store.current
        if graph is None:
            raise StaleSnapshotError(
                "No policy snapshot is loaded.",
                hint="Wait for the first snapshot to compile, or run `airlock doctor`.",
            )
        return graph

    def _staleness_note(self, graph: PolicyGraph) -> Verdict | None:
        max_staleness = self._config.datahub.snapshot.max_staleness
        age = (datetime.now(UTC) - graph.compiled_at).total_seconds()
        if age <= max_staleness:
            return None
        if self._config.datahub.snapshot.stale_policy == "fail_closed":
            raise StaleSnapshotError(
                f"Policy snapshot is {int(age)}s old, past the {int(max_staleness)}s budget."
            )
        return Verdict.make(
            ReasonCode.STALE_SNAPSHOT,
            "note",
            Subject.statement(),
            f"Serving a stale policy snapshot ({int(age)}s old); DataHub is unreachable.",
            hint="Decisions use the last-known catalog until DataHub recovers.",
        )

    def ready(self) -> bool:
        graph = self._store.current
        if graph is None:
            return False
        if self._config.datahub.snapshot.stale_policy != "fail_closed":
            return True
        age = (datetime.now(UTC) - graph.compiled_at).total_seconds()
        return age <= self._config.datahub.snapshot.max_staleness

    async def healthcheck(self) -> None:
        await self._adapter.healthcheck()

    async def refresh(self) -> PolicyGraph:
        """Recompile the snapshot from DataHub off the event loop and install it atomically."""
        from airlock.policy.compile import compile_snapshot

        graph = await asyncio.to_thread(compile_snapshot, self._config)
        self._store.install(graph)
        return graph

    async def _audit(
        self,
        envelope: Envelope,
        *,
        latency_ms: float,
        coalesced: bool,
        dataset_urns: list[str],
        column_reads: tuple[tuple[str, str], ...],
    ) -> None:
        record = AuditRecord.from_envelope(
            envelope,
            latency_ms=latency_ms,
            warehouse=self._dialect,
            coalesced=coalesced,
            dataset_urns=dataset_urns,
            column_reads=column_reads,
        )
        # Local, fast sinks (the append-only JSONL log) are awaited so no query is answered without
        # a durable audit record. Remote sinks are handed to the bounded drain worker.
        for sink in self._local_sinks:
            await self._write_sink(sink, record)
        if self._remote_sinks:
            self._enqueue_remote(record)

    def _enqueue_remote(self, record: AuditRecord) -> None:
        if self._writeback_queue is None:
            self._writeback_queue = asyncio.Queue(maxsize=self._writeback_cap)
            self._writeback_worker = asyncio.ensure_future(self._drain_writeback())
        try:
            self._writeback_queue.put_nowait(record)
        except asyncio.QueueFull:
            self._writeback_dropped += 1
            log.warning(
                "audit.writeback_dropped",
                request_id=record.request_id,
                total_dropped=self._writeback_dropped,
            )

    async def _drain_writeback(self) -> None:
        """Serially apply queued records to every remote sink. One worker; the DataHub sink already
        serializes its own writes, so extra concurrency here would only race the denied-attempt
        counter."""
        assert self._writeback_queue is not None
        while True:
            record = await self._writeback_queue.get()
            try:
                for sink in self._remote_sinks:
                    await self._write_sink(sink, record)
            finally:
                self._writeback_queue.task_done()

    @staticmethod
    async def _write_sink(sink: Sink, record: AuditRecord) -> None:
        try:
            await sink.write(record)
        except Exception as exc:  # a sink must never fail (or slow) a query
            log.warning("audit.sink_failed", sink=type(sink).__name__, detail=str(exc))

    async def aclose(self, *, drain_deadline: float = 5.0) -> None:
        """Drain the queued remote audit writes (bounded), then close the adapter and sinks."""
        if self._writeback_worker is not None and self._writeback_queue is not None:
            try:
                await asyncio.wait_for(self._writeback_queue.join(), timeout=drain_deadline)
            except TimeoutError:
                log.warning("audit.drain_timeout", pending=self._writeback_queue.qsize())
            self._writeback_worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._writeback_worker
        await self._adapter.close()
        for sink in self._sinks:
            await sink.close()


def _without_limit(verdicts: list[Verdict]) -> list[Verdict]:
    """Drop the row-limit note from a denied plan.

    The limit verdict describes something the rewriter is about to do. On a denied statement the
    rewriter never runs, so "a row limit of 10000 was applied" is describing an event that did not
    happen - noise the agent has to reason past on the one response where it can least afford to.
    """
    return [v for v in verdicts if v.action != "limit"]


def _column_reads(resolved: ResolvedQuery) -> tuple[tuple[str, str], ...]:
    """Distinct (dataset_urn, column) pairs the query touches, counted once per query however many
    times the column appears. Uses the effective dataset, so a substituted read is attributed to the
    certified table the agent actually got, not the deprecated one it asked for."""
    return tuple(sorted({(c.dataset_urn, c.fact.name) for c in resolved.columns}))


def _verify_masking(plan: Plan, result: QueryResult, *, sample: int = 50) -> None:
    """Post-flight check that masked output columns match their strategy shape (README edge 17)."""
    from airlock.errors import MaskVerifyError
    from airlock.masking import verify_value

    if not plan.masked_outputs:
        return
    columns = set(result.columns)
    for alias, strategy in plan.masked_outputs:
        if alias not in columns:
            continue
        for row in result.rows[:sample]:
            if not verify_value(strategy, row.get(alias)):
                raise MaskVerifyError(
                    f"Masked column {alias!r} returned a value not matching strategy {strategy!r}."
                )


def new_request_id() -> str:
    return "req_" + secrets.token_hex(6)
