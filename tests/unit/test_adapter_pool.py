"""The connection pool must not leak a semaphore permit when a connect fails.

Without the guard, each failed connect during a warehouse outage permanently consumes a pool permit;
after `pool_size` failures every acquire blocks forever - a deadlock that outlives the outage. Each
test fails a connect once, then asserts the next acquire still completes (a leak would hang it).
"""

from __future__ import annotations

import asyncio

import duckdb
import pytest

from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.exec.postgres_adapter import PostgresAdapter


async def test_duckdb_acquire_does_not_leak_a_permit_on_connect_failure(tmp_path) -> None:
    adapter = DuckdbAdapter(str(tmp_path / "w.duckdb"), pool_size=1)
    real = adapter._connect
    calls = {"n": 0}

    def flaky() -> duckdb.DuckDBPyConnection:
        calls["n"] += 1
        if calls["n"] == 1:
            raise duckdb.IOException("transient lock")
        return real()

    adapter._connect = flaky  # type: ignore[method-assign]

    with pytest.raises(duckdb.IOException):
        await adapter._acquire()
    # A leaked permit would make this block; the timeout turns a regression into a failure, not a hang.
    conn = await asyncio.wait_for(adapter._acquire(), timeout=2.0)
    assert conn is not None
    await adapter.close()


async def test_postgres_acquire_does_not_leak_a_permit_on_connect_failure() -> None:
    adapter = PostgresAdapter("postgresql://unused", pool_size=1)
    sentinel = object()
    calls = {"n": 0}

    async def flaky() -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("server starting up")
        return sentinel

    adapter._connect = flaky  # type: ignore[method-assign]

    with pytest.raises(ConnectionError):
        await adapter._acquire()
    conn = await asyncio.wait_for(adapter._acquire(), timeout=2.0)
    assert conn is sentinel
