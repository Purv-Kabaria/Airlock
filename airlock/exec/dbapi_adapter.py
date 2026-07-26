"""A generic adapter for any PEP 249 (DB-API 2.0) driver.

Nearly every Python database library - sqlite3, pymysql, pyodbc, cx_Oracle, trino, clickhouse-driver,
redshift-connector - implements DB-API 2.0. This adapter drives any of them, so Airlock is not
locked to a fixed list of warehouses: name the driver module and the sqlglot dialect in config and
it connects. The two named-kind niceties do not carry over automatically, so they are configured
explicitly: the dialect (a driver and its dialect rarely share a name) and how to introspect tables.

DB-API drivers are synchronous, so every statement runs on a worker thread through a bounded
connection pool, exactly as the DuckDB and Snowflake adapters do - the event loop never blocks.
Timeout and client cancellation call `connection.interrupt()` when the driver offers it (sqlite3
does); drivers without it can only be abandoned, so the connection is discarded rather than reused
while a statement may still be running on it.

This module is also the SQLite adapter: `make_adapter` builds it with Python's stdlib `sqlite3` and
SQLite-shaped introspection. SQLite adds no dependency and ships on every platform, which makes it
the zero-install warehouse for constrained devices and the concrete case these adapters are tested
against - the generic path's query, coercion, and pool logic is the same code, exercised live.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from typing import Any, Literal

from airlock.errors import ConfigError, WarehouseUnavailableError
from airlock.exec.base import QueryResult, coerce_value
from airlock.logging import get_logger

log = get_logger("airlock.exec.dbapi")

Introspection = Literal["information_schema", "sqlite"]

_SYSTEM_SCHEMAS = ("information_schema", "pg_catalog", "sys")


def _bind(paramstyle: str, values: list[Any]) -> tuple[list[str], Any]:
    """Placeholders and a params container for a positional bind, in the driver's paramstyle.

    DB-API leaves the placeholder spelling to the driver (`?`, `%s`, `:1`, ...), advertised on
    `module.paramstyle`. Rendering it wrong turns every introspection query into a syntax error, so
    the one place Airlock binds a value against an arbitrary driver honours all five styles.
    """
    n = len(values)
    if paramstyle == "qmark":
        return ["?"] * n, tuple(values)
    if paramstyle == "format":
        return ["%s"] * n, tuple(values)
    if paramstyle == "numeric":
        return [f":{i + 1}" for i in range(n)], tuple(values)
    if paramstyle == "named":
        return [f":p{i}" for i in range(n)], {f"p{i}": v for i, v in enumerate(values)}
    if paramstyle == "pyformat":
        return [f"%(p{i})s" for i in range(n)], {f"p{i}": v for i, v in enumerate(values)}
    raise ConfigError(f"unsupported DB-API paramstyle {paramstyle!r}")


class DbapiAdapter:
    def __init__(
        self,
        *,
        kind: str,
        dialect: str,
        connect: Callable[[], Any],
        paramstyle: str,
        introspection: Introspection,
        pool_size: int = 8,
        single_connection: bool = False,
    ) -> None:
        self.kind = kind
        self._dialect = dialect
        self._connect_fn = connect
        self._paramstyle = paramstyle
        self._introspection = introspection
        # A file-backed SQLite database is one writer; more than one connection to a :memory: db
        # sees a different, empty database. Either way, cap the pool at one.
        self._pool_size = 1 if single_connection else max(1, pool_size)
        self._sem = asyncio.Semaphore(self._pool_size)
        self._lock = asyncio.Lock()
        self._free: list[Any] = []
        self._all: list[Any] = []

    async def run(self, sql: str, *, timeout: float, row_limit: int) -> QueryResult:
        conn = await self._acquire()
        healthy = True
        try:
            columns, rows = await self._execute(conn, sql, timeout=timeout)
        except BaseException:
            healthy = False  # a cancelled/interrupted connection may be mid-statement; discard it
            raise
        finally:
            await self._release(conn, healthy=healthy)
        truncated = len(rows) >= row_limit
        shaped = [
            {c: coerce_value(v) for c, v in zip(columns, row, strict=False)}
            for row in rows[:row_limit]
        ]
        return QueryResult(columns=columns, rows=shaped, truncated=truncated)

    async def _execute(
        self, conn: Any, sql: str, *, timeout: float, params: Any = None
    ) -> tuple[list[str], list[tuple[Any, ...]]]:
        task = asyncio.ensure_future(asyncio.to_thread(_run_statement, conn, sql, params))
        try:
            done, _pending = await asyncio.wait({task}, timeout=timeout)
        except asyncio.CancelledError:
            self._interrupt(conn)
            await _drain(task)
            raise
        if task not in done:
            self._interrupt(conn)
            await _drain(task)
            raise WarehouseUnavailableError(self.kind, f"statement timed out after {timeout:g}s")
        try:
            return task.result()
        except Exception as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc

    def _interrupt(self, conn: Any) -> None:
        # Not in DB-API; sqlite3 and a few others expose it. Best effort - the connection is
        # discarded afterward regardless, so a driver without interrupt is still safe.
        interrupt = getattr(conn, "interrupt", None)
        if callable(interrupt):
            with contextlib.suppress(Exception):
                interrupt()

    async def list_tables(self) -> list[str]:
        if self._introspection == "sqlite":
            _, rows = await self._query(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            return [name for (name,) in rows]
        placeholders, params = _bind(self._paramstyle, list(_SYSTEM_SCHEMAS))
        _, rows = await self._query(
            "SELECT table_schema, table_name FROM information_schema.tables "
            f"WHERE LOWER(table_schema) NOT IN ({', '.join(placeholders)}) ORDER BY 1, 2",
            params,
        )
        return [
            f"{schema}.{name}" if schema not in ("public", "main", "") else name
            for schema, name in rows
        ]

    async def describe_table(self, name: str) -> list[tuple[str, str]]:
        if self._introspection == "sqlite":
            # PRAGMA takes an identifier, not a bound value; quote it so a name with a quote cannot
            # break out. Returns rows of (cid, name, type, notnull, dflt_value, pk).
            _, rows = await self._query(
                f'PRAGMA table_info("{name.replace(chr(34), chr(34) * 2)}")'
            )
            return [(row[1], row[2] or "") for row in rows]
        schema, _, table = name.rpartition(".")
        values: list[Any] = [table] + ([schema] if schema else [])
        placeholders, params = _bind(self._paramstyle, values)
        where = f"table_name = {placeholders[0]}" + (
            f" AND table_schema = {placeholders[1]}" if schema else ""
        )
        _, rows = await self._query(
            "SELECT column_name, data_type FROM information_schema.columns "
            f"WHERE {where} ORDER BY ordinal_position",
            params,
        )
        return [(c, t) for c, t in rows]

    async def healthcheck(self) -> None:
        try:
            await self._query("SELECT 1")
        except WarehouseUnavailableError:
            raise
        except Exception as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc

    async def _query(self, sql: str, params: Any = None) -> tuple[list[str], list[tuple[Any, ...]]]:
        conn = await self._acquire()
        healthy = True
        try:
            return await self._execute(conn, sql, timeout=30.0, params=params)
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
            conn = await asyncio.to_thread(self._connect_fn)
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


def _run_statement(conn: Any, sql: str, params: Any) -> tuple[list[str], list[tuple[Any, ...]]]:
    cur = conn.cursor()
    try:
        cur.execute(sql, params) if params is not None else cur.execute(sql)
        columns = [d[0] for d in cur.description or []]
        return columns, cur.fetchall()
    finally:
        cur.close()


async def _drain(task: asyncio.Task[Any]) -> None:
    """Wait for an interrupted worker thread to finish (bounded), swallowing its outcome, so the
    connection is never touched by two threads at once before it is discarded."""
    with contextlib.suppress(Exception):
        await asyncio.wait({task}, timeout=10.0)
    if task.done() and not task.cancelled():
        task.exception()  # mark retrieved so asyncio does not log "exception never retrieved"


def _register_masking_functions(conn: Any) -> None:
    """Teach SQLite the scalar functions the mask templates expect.

    Alone among the supported warehouses, SQLite ships almost no string or hash builtins: there is no
    MD5 and no RIGHT. The masks every other engine binds natively therefore had nothing to resolve,
    and a `hash`-masked column - the default for any PII that is not an email, phone, or date - failed
    at query time with "no such function: MD5". That made SQLite unusable for the case it is
    recommended for, and it was invisible because the adapter's tests cover connections and row
    shaping, not the SQL masking emits.

    Registering them uses sqlite3's own documented extension point and keeps the masking layer
    dialect-neutral: the template is untouched, the engine simply gains the function it lacked.
    Declared deterministic because both are pure - SQLite may then use them in indexed expressions.
    """
    import hashlib

    def md5(value: object) -> str | None:
        # Pseudonymisation, not authentication: this must match what every other warehouse's MD5
        # returns, so the same value hashes identically wherever the query runs.
        if value is None:
            return None
        return hashlib.md5(str(value).encode("utf-8")).hexdigest()

    def right(value: object, count: object) -> str | None:
        if value is None:
            return None
        chars = int(count) if isinstance(count, (int, float, str)) else 0
        return str(value)[-chars:] if chars > 0 else ""

    conn.create_function("MD5", 1, md5, deterministic=True)
    conn.create_function("RIGHT", 2, right, deterministic=True)


def make_sqlite_adapter(dsn: str, *, pool_size: int = 8) -> DbapiAdapter:
    """SQLite over the stdlib `sqlite3` driver. No dependency, every platform."""
    import sqlite3

    path = _sqlite_path(dsn)
    memory = path == ":memory:"

    def connect() -> Any:
        # check_same_thread=False: connections are pooled and dispatched to worker threads, but the
        # pool never hands one connection to two threads at once (the semaphore + free-list ensure
        # that), so cross-thread use is serialized and safe.
        conn = sqlite3.connect(path, check_same_thread=False)
        _register_masking_functions(conn)
        return conn

    return DbapiAdapter(
        kind="sqlite",
        dialect="sqlite",
        connect=connect,
        paramstyle=sqlite3.paramstyle,
        introspection="sqlite",
        pool_size=pool_size,
        single_connection=memory,
    )


def make_dbapi_adapter(
    *, driver: str, dialect: str, dsn: str, connect_args: dict[str, Any], pool_size: int = 8
) -> DbapiAdapter:
    """Any PEP 249 driver named by module path. The driver is imported lazily, so it need not be
    installed unless this warehouse is actually used."""
    import importlib

    try:
        module = importlib.import_module(driver)
    except ImportError as exc:
        raise ConfigError(
            f"warehouse.driver {driver!r} is not importable: {exc}. "
            f"Install it (e.g. `pip install {driver.split('.')[0]}`)."
        ) from exc
    paramstyle = getattr(module, "paramstyle", "qmark")

    def connect() -> Any:
        return module.connect(dsn, **connect_args) if dsn else module.connect(**connect_args)

    return DbapiAdapter(
        kind="dbapi",
        dialect=dialect,
        connect=connect,
        paramstyle=paramstyle,
        introspection="information_schema",
        pool_size=pool_size,
    )


def _sqlite_path(dsn: str) -> str:
    raw = dsn.strip()
    for prefix in ("sqlite:///", "sqlite://", "sqlite:"):
        if raw.startswith(prefix):
            raw = raw[len(prefix) :]
            break
    return raw or ":memory:"
