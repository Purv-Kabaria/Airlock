"""Postgres adapter (psycopg 3, native async).

The second warehouse. Unlike DuckDB it needs no worker thread - psycopg speaks asyncio directly.
A bounded pool of async connections caps concurrency; per-statement `statement_timeout` is set on
the server and client cancellation calls `connection.cancel()` so a dropped client stops the query
in Postgres, not just in Airlock.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from airlock.errors import WarehouseUnavailableError
from airlock.exec.base import QueryResult, coerce_value
from airlock.logging import get_logger

log = get_logger("airlock.exec.postgres")


class PostgresAdapter:
    kind = "postgres"

    def __init__(self, dsn: str, *, pool_size: int = 8) -> None:
        self._dsn = dsn
        self._pool_size = max(1, pool_size)
        self._sem = asyncio.Semaphore(self._pool_size)
        self._lock = asyncio.Lock()
        self._free: list[Any] = []
        self._all: list[Any] = []

    async def run(self, sql: str, *, timeout: float, row_limit: int) -> QueryResult:
        conn = await self._acquire()
        healthy = True
        try:
            return await self._run_on(conn, sql, timeout=timeout, row_limit=row_limit)
        except BaseException:
            healthy = False  # a cancelled or errored connection may be tainted; discard it
            raise
        finally:
            await self._release(conn, healthy=healthy)

    async def _run_on(self, conn: Any, sql: str, *, timeout: float, row_limit: int) -> QueryResult:
        import psycopg

        try:
            async with conn.cursor() as cur:
                await cur.execute(f"SET statement_timeout = {int(timeout * 1000)}")
                await cur.execute(sql)
                rows = await cur.fetchall()
                columns = [d.name for d in cur.description]
        except asyncio.CancelledError:
            conn.cancel()
            raise
        except psycopg.Error as exc:
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
        _, rows = await self._query(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_schema NOT IN ('information_schema','pg_catalog') ORDER BY 1, 2"
        )
        return [f"{schema}.{name}" if schema != "public" else name for schema, name in rows]

    async def describe_table(self, name: str) -> list[tuple[str, str]]:
        schema, _, table = name.rpartition(".")
        where = "table_name = %s" + (" AND table_schema = %s" if schema else "")
        params = [table] + ([schema] if schema else [])
        _, rows = await self._query(
            "SELECT column_name, data_type FROM information_schema.columns "
            f"WHERE {where} ORDER BY ordinal_position",
            params,
        )
        return [(c, t) for c, t in rows]

    async def healthcheck(self) -> None:
        import psycopg

        try:
            await self._query("SELECT 1")
        except psycopg.Error as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc

    async def _query(
        self, sql: str, params: list[Any] | None = None
    ) -> tuple[list[str], list[Any]]:
        conn = await self._acquire()
        healthy = True
        try:
            async with conn.cursor() as cur:
                await cur.execute(sql, params)
                rows = await cur.fetchall()
                columns = [d.name for d in cur.description]
            return columns, rows
        except BaseException:
            healthy = False
            raise
        finally:
            await self._release(conn, healthy=healthy)

    async def close(self) -> None:
        async with self._lock:
            for conn in self._all:
                await conn.close()
            self._all.clear()
            self._free.clear()

    async def _acquire(self) -> Any:
        await self._sem.acquire()
        try:
            async with self._lock:
                if self._free:
                    return self._free.pop()
            conn = await self._connect()
        except BaseException:
            # A failed connect must not leak the permit, or repeated failures during a Postgres
            # outage exhaust the pool and every later acquire blocks forever - a deadlock that
            # survives the outage. Release before propagating so the pool self-heals on recovery.
            self._sem.release()
            raise
        async with self._lock:
            self._all.append(conn)
        return conn

    async def _release(self, conn: Any, *, healthy: bool = True) -> None:
        if not healthy:
            # Discard a tainted connection instead of pooling it; a fresh one is made on next acquire.
            async with self._lock:
                if conn in self._all:
                    self._all.remove(conn)
            with contextlib.suppress(Exception):
                await conn.close()
            self._sem.release()
            return
        async with self._lock:
            self._free.append(conn)
        self._sem.release()

    async def _connect(self) -> Any:
        import psycopg

        return await psycopg.AsyncConnection.connect(self._dsn, autocommit=True)
