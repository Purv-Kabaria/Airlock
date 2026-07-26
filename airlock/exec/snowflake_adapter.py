"""Snowflake adapter.

snowflake-connector-python is synchronous, so every statement runs on a worker thread via
`asyncio.to_thread` and the event loop never blocks - the same shape as the DuckDB adapter. The
connector cancels a query server-side when `cursor.execute(..., timeout=N)` elapses; a client
disconnect additionally issues `SYSTEM$CANCEL_QUERY` on the query id so a dropped client stops the
warehouse work too, not just the wait for it.

The driver is an optional dependency (`pip install airlock-gateway[snowflake]`) and is imported
lazily inside `_connect`, so a gateway that never uses Snowflake need not have it installed - and
this module's DSN parsing is testable without it.

Config: `warehouse.dsn` is a SQLAlchemy-style Snowflake URL,

    snowflake://<user>:<password>@<account>/<database>/<schema>?warehouse=<wh>&role=<role>

Extra connect args go in the query string (e.g. `authenticator=externalbrowser`,
`private_key_file=/path/key.p8`); every query parameter is passed through to `connect()`.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from airlock.errors import ConfigError, WarehouseUnavailableError
from airlock.exec.base import QueryResult, coerce_value
from airlock.logging import get_logger

log = get_logger("airlock.exec.snowflake")


def parse_snowflake_dsn(dsn: str) -> dict[str, Any]:
    """Turn a Snowflake URL into `snowflake.connector.connect` kwargs.

    Kept pure and driver-free so it is unit-testable without the connector installed.
    """
    parsed = urlparse(dsn)
    if parsed.scheme != "snowflake":
        raise ConfigError(
            f"snowflake dsn must start with 'snowflake://', got {parsed.scheme or '(none)'}://"
        )
    if not parsed.hostname:
        raise ConfigError(
            "snowflake dsn is missing the account (the host part): "
            "snowflake://user:password@<account>/database/schema?warehouse=..&role=.."
        )
    # Path is /database/schema; either may be absent.
    parts = [p for p in parsed.path.split("/") if p]
    args: dict[str, Any] = {"account": parsed.hostname}
    if parsed.username:
        args["user"] = unquote(parsed.username)
    if parsed.password:
        args["password"] = unquote(parsed.password)
    if len(parts) >= 1:
        args["database"] = parts[0]
    if len(parts) >= 2:
        args["schema"] = parts[1]
    # Every query-string key is a connect() kwarg (warehouse, role, authenticator, ...). Last wins.
    for key, values in parse_qs(parsed.query).items():
        args[key] = values[-1]
    # Tag the session so Airlock's traffic is identifiable in Snowflake's QUERY_HISTORY, which is
    # what lets an auditor reconcile the gateway's own ledger against the warehouse's view of it.
    # A DSN-supplied value wins; a non-dict one (someone wrote ?session_parameters=x) is replaced
    # rather than crashed on.
    session = args.get("session_parameters")
    args["session_parameters"] = session = session if isinstance(session, dict) else {}
    session.setdefault("QUERY_TAG", "airlock")
    return args


class SnowflakeAdapter:
    kind = "snowflake"

    def __init__(self, dsn: str, *, pool_size: int = 8) -> None:
        self._connect_args = parse_snowflake_dsn(dsn)  # fail fast on a bad DSN at construction
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
            healthy = False  # a cancelled/errored connection may be mid-statement; do not pool it
            raise
        finally:
            await self._release(conn, healthy=healthy)

    async def _run_on(self, conn: Any, sql: str, *, timeout: float, row_limit: int) -> QueryResult:
        import snowflake.connector

        # The cancel path needs the cursor's query id while execute() is still blocking a worker
        # thread, so the cursor is published here rather than only returned at the end.
        inflight: dict[str, Any] = {}

        def _work() -> tuple[list[str], list[tuple[Any, ...]], str | None]:
            cur = conn.cursor()
            inflight["cursor"] = cur
            try:
                cur.execute(sql, timeout=int(timeout))
                columns = [d.name for d in cur.description or []]
                rows = cur.fetchall()
                return columns, rows, getattr(cur, "sfqid", None)
            finally:
                cur.close()

        task = asyncio.ensure_future(asyncio.to_thread(_work))
        try:
            columns, rows, _ = await task
        except asyncio.CancelledError:
            # The client dropped. Cancel the query server-side so it stops burning credits, then let
            # the drain finish before the connection is discarded.
            await self._cancel_inflight(inflight.get("cursor"))
            await _drain(task)
            raise
        except snowflake.connector.errors.Error as exc:
            message = str(exc).splitlines()[0]
            if "timeout" in message.lower() or "cancel" in message.lower():
                raise WarehouseUnavailableError(
                    self.kind, f"statement timed out after {timeout:g}s"
                ) from exc
            raise WarehouseUnavailableError(self.kind, message) from exc
        truncated = len(rows) >= row_limit
        shaped = [
            {c: coerce_value(v) for c, v in zip(columns, row, strict=False)}
            for row in rows[:row_limit]
        ]
        return QueryResult(columns=columns, rows=shaped, truncated=truncated)

    async def _cancel_inflight(self, cursor: Any) -> None:
        """Stop a still-running query after its client went away.

        Neither the connection nor the cursor exposes a public `cancel()` - the connector keeps
        cancellation private (`SnowflakeConnection._cancel_query`), and calling a private method
        would break on a driver upgrade. So this uses the documented SQL entry point,
        `SYSTEM$CANCEL_QUERY`, against the query id the cursor publishes as `sfqid`.

        It runs on a connection of its own because the query's connection is still blocked inside
        execute() on a worker thread. Failure is logged, never raised: this runs while a
        CancelledError is already propagating, and masking that would lose the real outcome.
        """
        from snowflake.connector import errors as sf_errors

        query_id = getattr(cursor, "sfqid", None)
        if not query_id:
            return  # execute() had not reached the server yet; nothing is running to cancel

        def _cancel() -> None:
            conn = self._connect()
            try:
                cur = conn.cursor()
                try:
                    cur.execute("SELECT SYSTEM$CANCEL_QUERY(%s)", (query_id,))
                finally:
                    cur.close()
            finally:
                conn.close()

        try:
            await asyncio.to_thread(_cancel)
        except (sf_errors.Error, OSError) as exc:
            log.warning("snowflake.cancel_failed", query_id=query_id, detail=str(exc))

    async def list_tables(self) -> list[str]:
        _, rows = await self._query(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_schema NOT IN ('INFORMATION_SCHEMA') ORDER BY 1, 2"
        )
        return [f"{schema}.{name}" for schema, name in rows]

    async def describe_table(self, name: str) -> list[tuple[str, str]]:
        schema, _, table = name.rpartition(".")
        where = "table_name = %s" + (" AND table_schema = %s" if schema else "")
        params: list[Any] = [table.upper()] + ([schema.upper()] if schema else [])
        _, rows = await self._query(
            "SELECT column_name, data_type FROM information_schema.columns "
            f"WHERE {where} ORDER BY ordinal_position",
            params,
        )
        return [(c, t) for c, t in rows]

    async def healthcheck(self) -> None:
        import snowflake.connector

        try:
            await self._query("SELECT 1")
        except snowflake.connector.errors.Error as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc

    async def _query(
        self, sql: str, params: list[Any] | None = None
    ) -> tuple[list[str], list[Any]]:
        conn = await self._acquire()
        healthy = True

        def _work() -> tuple[list[str], list[Any]]:
            cur = conn.cursor()
            try:
                cur.execute(sql, params) if params else cur.execute(sql)
                columns = [d.name for d in cur.description or []]
                return columns, cur.fetchall()
            finally:
                cur.close()

        try:
            return await asyncio.to_thread(_work)
        except BaseException:
            healthy = False
            raise
        finally:
            await self._release(conn, healthy=healthy)

    async def close(self) -> None:
        async with self._lock:
            conns = list(self._all)
            self._all.clear()
            self._free.clear()
        for conn in conns:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(conn.close)

    async def _acquire(self) -> Any:
        await self._sem.acquire()
        try:
            async with self._lock:
                if self._free:
                    return self._free.pop()
            conn = await asyncio.to_thread(self._connect)
        except BaseException:
            # A failed connect must not leak the permit, or repeated failures during an outage
            # exhaust the pool and every later acquire blocks forever. Release before propagating.
            self._sem.release()
            raise
        async with self._lock:
            self._all.append(conn)
        return conn

    async def _release(self, conn: Any, *, healthy: bool = True) -> None:
        if not healthy:
            async with self._lock:
                if conn in self._all:
                    self._all.remove(conn)
            with contextlib.suppress(Exception):
                await asyncio.to_thread(conn.close)
            self._sem.release()
            return
        async with self._lock:
            self._free.append(conn)
        self._sem.release()

    def _connect(self) -> Any:
        import snowflake.connector

        return snowflake.connector.connect(**self._connect_args)


async def _drain(task: asyncio.Task[Any]) -> None:
    """Wait for an interrupted worker thread to finish (bounded), swallowing its outcome, so the
    connection is never discarded while a thread is still using it."""
    with contextlib.suppress(Exception):
        await asyncio.wait({task}, timeout=10.0)
    if task.done() and not task.cancelled():
        task.exception()  # mark retrieved so asyncio does not log "exception never retrieved"
