"""A failed warehouse execution must not leave an unretrieved exception on the singleflight future.

The leader awaits the adapter directly, not its own future - only coalesced followers await that. A
failure with no follower would otherwise leave the exception unretrieved, and asyncio logs it at GC
(a stray traceback under the judge's warehouse-drop gauntlet, README zero-traceback rule).
"""

from __future__ import annotations

import gc
import logging

from tests.unit.conftest import RecordingSink, build_graph, make_config

from airlock.engine.verdicts import EnvelopeStatus
from airlock.errors import WarehouseUnavailableError
from airlock.exec.base import QueryResult
from airlock.gateway import Gateway
from airlock.policy.store import SnapshotStore


class _FailingAdapter:
    kind = "duckdb"

    async def run(self, sql: str, *, timeout: float, row_limit: int) -> QueryResult:
        raise WarehouseUnavailableError("duckdb", "connection dropped mid-query")

    async def list_tables(self) -> list[str]:
        return []

    async def describe_table(self, name: str) -> list[tuple[str, str]]:
        return []

    async def healthcheck(self) -> None:
        return None

    async def close(self) -> None:
        return None


async def test_leader_failure_without_followers_is_clean(tmp_path, caplog) -> None:
    cfg = make_config(str(tmp_path / "wh.duckdb"), str(tmp_path / "audit.jsonl"))
    store = SnapshotStore(str(tmp_path / "snap.sqlite"))
    store.install(build_graph())
    gateway = Gateway(cfg, store, _FailingAdapter(), [RecordingSink()])

    with caplog.at_level(logging.ERROR, logger="asyncio"):
        env = await gateway.run_query("SELECT name FROM dim_users", "growth-agent")
        gc.collect()  # trigger Future.__del__ for any unretrieved-exception future

    await gateway.aclose()
    assert env.status is EnvelopeStatus.ERROR  # the failure became a clean envelope, not a raise
    assert gateway._coalesce == {}  # the singleflight entry was removed
    assert not any("never retrieved" in r.message for r in caplog.records)
