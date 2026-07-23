"""DuckDB adapter: the primary demo warehouse.

DuckDB's Python driver is synchronous, so every statement runs on a worker thread via
`asyncio.to_thread`; the event loop never blocks. A bounded pool caps concurrent connections.
Timeouts and client cancellation both reach the warehouse through `connection.interrupt()`, so a
dropped client or a slow query never orphans work in the database.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

import duckdb

from airlock.errors import WarehouseUnavailableError
from airlock.exec.base import QueryResult, coerce_value
from airlock.logging import get_logger

log = get_logger("airlock.exec.duckdb")


class DuckdbAdapter:
    kind = "duckdb"

    def __init__(self, dsn: str, *, pool_size: int = 8) -> None:
        self._path = _normalize_dsn(dsn)
        self._memory = self._path == ":memory:"
        self._pool_size = 1 if self._memory else max(1, pool_size)
        self._sem = asyncio.Semaphore(self._pool_size)
        self._lock = asyncio.Lock()
        self._free: list[duckdb.DuckDBPyConnection] = []
        self._all: list[duckdb.DuckDBPyConnection] = []

    async def run(self, sql: str, *, timeout: float, row_limit: int) -> QueryResult:
        conn = await self._acquire()
        try:
            return await self._run_on(conn, sql, timeout=timeout, row_limit=row_limit)
        except duckdb.IOException as exc:
            log.warning("warehouse.retry", kind=self.kind, detail=str(exc))
            await asyncio.sleep(0.2)
            return await self._run_on(conn, sql, timeout=timeout, row_limit=row_limit)
        finally:
            await self._release(conn)

    async def _run_on(
        self, conn: duckdb.DuckDBPyConnection, sql: str, *, timeout: float, row_limit: int
    ) -> QueryResult:
        # The query runs on a worker thread. On timeout or client cancellation we interrupt it, then
        # DRAIN the thread before returning so the connection is never handed to another caller while
        # a thread is still using it (DuckDB connections are not safe for concurrent use).
        task = asyncio.ensure_future(asyncio.to_thread(_execute, conn, sql))
        try:
            done, _pending = await asyncio.wait({task}, timeout=timeout)
        except asyncio.CancelledError:
            conn.interrupt()
            await _drain(task)
            raise
        if task not in done:
            conn.interrupt()
            await _drain(task)
            raise WarehouseUnavailableError(self.kind, f"statement timed out after {timeout:g}s")
        try:
            columns, rows = task.result()
        except duckdb.Error as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc
        # The rewriter always injects a LIMIT, so rows is already bounded; slicing is a fail-closed
        # backstop that keeps the envelope within row_limit even if a query shape ever slips a LIMIT.
        truncated = len(rows) >= row_limit
        shaped = [
            {c: coerce_value(v) for c, v in zip(columns, row, strict=False)}
            for row in rows[:row_limit]
        ]
        return QueryResult(columns=columns, rows=shaped, truncated=truncated)

    async def list_tables(self) -> list[str]:
        conn = await self._acquire()
        try:
            _, rows = await asyncio.to_thread(
                _execute,
                conn,
                "SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('information_schema','pg_catalog') ORDER BY 1, 2",
            )
            return [
                f"{schema}.{name}" if schema not in ("main", "") else name for schema, name in rows
            ]
        finally:
            await self._release(conn)

    async def describe_table(self, name: str) -> list[tuple[str, str]]:
        conn = await self._acquire()
        try:
            schema, _, table = name.rpartition(".")
            where = "table_name = ?" + (" AND table_schema = ?" if schema else "")
            params = [table] + ([schema] if schema else [])
            _, rows = await asyncio.to_thread(
                _execute,
                conn,
                "SELECT column_name, data_type FROM information_schema.columns "
                f"WHERE {where} ORDER BY ordinal_position",
                params,
            )
            return [(c, t) for c, t in rows]
        finally:
            await self._release(conn)

    async def healthcheck(self) -> None:
        conn = await self._acquire()
        try:
            await asyncio.to_thread(_execute, conn, "SELECT 1")
        except duckdb.Error as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc
        finally:
            await self._release(conn)

    async def close(self) -> None:
        async with self._lock:
            for conn in self._all:
                conn.close()
            self._all.clear()
            self._free.clear()

    async def _acquire(self) -> duckdb.DuckDBPyConnection:
        await self._sem.acquire()
        try:
            async with self._lock:
                if self._free:
                    return self._free.pop()
            conn = await asyncio.to_thread(self._connect)
        except BaseException:
            # A failed connect must not leak the permit, or repeated failures during a warehouse
            # outage exhaust the pool and every later acquire blocks forever - a deadlock that
            # survives the outage. Release before propagating so the pool self-heals on recovery.
            self._sem.release()
            raise
        async with self._lock:
            self._all.append(conn)
        return conn

    async def _release(self, conn: duckdb.DuckDBPyConnection) -> None:
        async with self._lock:
            self._free.append(conn)
        self._sem.release()

    def _connect(self) -> duckdb.DuckDBPyConnection:
        if not self._memory:
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        return duckdb.connect(self._path)


async def _drain(task: asyncio.Task[Any]) -> None:
    """Wait for an interrupted worker thread to finish (bounded), swallowing its outcome. The
    connection is only reused after this, so it is never touched by two threads at once."""
    with contextlib.suppress(Exception):
        await asyncio.wait({task}, timeout=10.0)
    if task.done() and not task.cancelled():
        task.exception()  # mark retrieved so asyncio does not log "exception never retrieved"


def _execute(
    conn: duckdb.DuckDBPyConnection, sql: str, params: list[Any] | None = None
) -> tuple[list[str], list[tuple[Any, ...]]]:
    cur = conn.execute(sql, params) if params else conn.execute(sql)
    description = cur.description or []
    columns = [d[0] for d in description]
    rows = cur.fetchall()
    return columns, rows


def _normalize_dsn(dsn: str) -> str:
    raw = dsn.strip()
    for prefix in ("duckdb:///", "duckdb://", "duckdb:"):
        if raw.startswith(prefix):
            raw = raw[len(prefix) :]
            break
    if raw in ("", ":memory:"):
        return ":memory:"
    return str(Path(raw))
