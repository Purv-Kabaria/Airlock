"""End-to-end gateway tests against a real DuckDB file (no DataHub; the graph is built directly).

Exercises the full async path: pin snapshot, decide, rewrite, execute, verify masking, audit.
"""

from __future__ import annotations

import asyncio

import pytest
from tests.unit.conftest import RecordingSink, build_graph, make_config

from airlock.engine.verdicts import EnvelopeStatus
from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.policy.store import SnapshotStore


def _gateway(tmp_path, warehouse: str, *, mode: str = "enforce") -> tuple[Gateway, RecordingSink]:
    cfg = make_config(warehouse, str(tmp_path / "audit.jsonl"), mode=mode)
    store = SnapshotStore(str(tmp_path / "snap.sqlite"))
    store.install(build_graph(mode=mode))
    sink = RecordingSink()
    gateway = Gateway(cfg, store, DuckdbAdapter(warehouse), [sink])
    return gateway, sink


async def test_masks_and_denies_end_to_end(tmp_path, warehouse) -> None:
    gateway, sink = _gateway(tmp_path, warehouse)
    env = await gateway.run_query("SELECT name, email, ssn FROM dim_users", "growth-agent")
    await gateway.aclose()

    assert env.status is EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS
    assert env.rows is not None and len(env.rows) == 3
    for row in env.rows:
        assert row["ssn"] is None
        assert "***" in row["email"]
        assert row["name"] in {"Ada", "Bo", "Cy"}
    assert len(sink.records) == 1
    assert sink.records[0].snapshot_hash == env.policy_snapshot


async def test_substitution_redirects_to_certified(tmp_path, warehouse) -> None:
    gateway, _ = _gateway(tmp_path, warehouse)
    env = await gateway.run_query("SELECT name FROM users_raw", "growth-agent")
    await gateway.aclose()
    assert "dim_users" in (env.executed_sql or "")
    assert any(v.code == "AIRLOCK-201" for v in env.verdicts)


async def test_masked_predicate_is_denied(tmp_path, warehouse) -> None:
    gateway, _ = _gateway(tmp_path, warehouse)
    env = await gateway.run_query(
        "SELECT name FROM dim_users WHERE email = 'ada@corp.com'", "growth-agent"
    )
    await gateway.aclose()
    assert env.status is EnvelopeStatus.DENIED
    assert env.rows is None
    assert any(v.code == "AIRLOCK-130" for v in env.verdicts)


async def test_out_of_scope_is_denied(tmp_path, warehouse) -> None:
    gateway, _ = _gateway(tmp_path, warehouse)
    env = await gateway.run_query("SELECT emp_id FROM payroll", "growth-agent")
    await gateway.aclose()
    assert env.status is EnvelopeStatus.DENIED
    assert any(v.code == "AIRLOCK-301" for v in env.verdicts)


async def test_identical_concurrent_sends_are_coalesced(tmp_path, warehouse) -> None:
    gateway, sink = _gateway(tmp_path, warehouse)
    sql = "SELECT name, email FROM dim_users"
    a, b = await asyncio.gather(
        gateway.run_query(sql, "growth-agent"), gateway.run_query(sql, "growth-agent")
    )
    await gateway.aclose()
    assert a.rows == b.rows  # both callers get the same result
    assert len(sink.records) == 2


async def test_plan_is_cached(tmp_path, warehouse) -> None:
    gateway, _ = _gateway(tmp_path, warehouse)
    graph = gateway.snapshot()
    p1 = gateway._plan("SELECT name FROM dim_users", graph.principal("growth-agent"), graph)
    p2 = gateway._plan("SELECT name FROM dim_users", graph.principal("growth-agent"), graph)
    await gateway.aclose()
    assert p1 is p2  # second call is a cache hit


async def test_remote_sink_is_off_the_request_path(tmp_path, warehouse) -> None:
    # A slow remote sink (like DataHub write-back) must not delay the query response. It runs as a
    # background task and is drained on shutdown.
    started = asyncio.Event()
    released = asyncio.Event()

    class SlowRemoteSink:
        background = True

        def __init__(self) -> None:
            self.written = 0

        async def write(self, record) -> None:
            started.set()
            await released.wait()
            self.written += 1

        async def close(self) -> None:
            return None

    cfg = make_config(warehouse, str(tmp_path / "a.jsonl"))
    store = SnapshotStore(str(tmp_path / "s.sqlite"))
    store.install(build_graph())
    remote = SlowRemoteSink()
    gateway = Gateway(cfg, store, DuckdbAdapter(warehouse), [remote])

    env = await gateway.run_query("SELECT name FROM dim_users", "growth-agent")
    assert env.is_ok()  # returned without waiting on the remote sink
    await asyncio.sleep(0)  # let the background task get scheduled
    assert started.is_set() and remote.written == 0  # sink is running but has not completed
    released.set()
    await gateway.aclose()  # drains the background write
    assert remote.written == 1


async def test_writeback_backlog_is_bounded_and_drops_loudly(tmp_path, warehouse) -> None:
    # A remote sink slower than the query rate must not grow an unbounded backlog. Above the queue
    # cap the remote copy is dropped (counted), while the local JSONL sink still records every query.
    release = asyncio.Event()

    class StalledRemoteSink:
        background = True

        def __init__(self) -> None:
            self.written = 0

        async def write(self, record) -> None:
            await release.wait()
            self.written += 1

        async def close(self) -> None:
            return None

    cfg = make_config(warehouse, str(tmp_path / "a.jsonl"))
    store = SnapshotStore(str(tmp_path / "s.sqlite"))
    store.install(build_graph())
    local = RecordingSink()
    remote = StalledRemoteSink()
    gateway = Gateway(cfg, store, DuckdbAdapter(warehouse), [local, remote], writeback_queue=1)

    for _ in range(5):
        env = await gateway.run_query("SELECT name FROM dim_users", "growth-agent")
        assert env.is_ok()  # never blocked by the stalled remote sink

    assert len(local.records) == 5  # local audit is complete regardless of remote backpressure
    assert gateway._writeback_dropped >= 1  # backlog past the cap was shed, not queued unboundedly
    release.set()
    await gateway.aclose()


async def test_coalesced_waiter_survives_leader_cancel(tmp_path, warehouse) -> None:
    # A leader whose client disconnects must not fail a waiter coalescing on the same query.
    from airlock.exec.base import QueryResult

    class GatedAdapter:
        kind = "duckdb"

        def __init__(self) -> None:
            self.calls = 0
            self.block = asyncio.Event()

        async def run(self, sql, *, timeout, row_limit):
            self.calls += 1
            if self.calls == 1:
                await self.block.wait()  # leader hangs until its client drops
            return QueryResult(columns=["one"], rows=[{"one": 1}], truncated=False)

        async def list_tables(self):
            return []

        async def describe_table(self, name):
            return []

        async def healthcheck(self):
            return None

        async def close(self):
            return None

    cfg = make_config(warehouse, str(tmp_path / "a.jsonl"))
    store = SnapshotStore(str(tmp_path / "s.sqlite"))
    store.install(build_graph())
    adapter = GatedAdapter()
    gateway = Gateway(cfg, store, adapter, [])

    sql = "SELECT name FROM dim_users LIMIT 1"
    leader = asyncio.ensure_future(gateway.run_query(sql, "growth-agent"))
    await asyncio.sleep(0.05)  # let the leader register the in-flight execution
    waiter = asyncio.ensure_future(gateway.run_query(sql, "growth-agent"))
    await asyncio.sleep(0.05)  # let the waiter coalesce onto the leader
    leader.cancel()  # the leader's client disconnects
    adapter.block.set()  # allow a fresh execution to complete

    with pytest.raises(asyncio.CancelledError):
        await leader
    env = await waiter  # the waiter must still succeed on its own
    await gateway.aclose()
    assert env.status is EnvelopeStatus.EXECUTED


async def test_offline_bootstrap_uses_cached_snapshot(tmp_path, warehouse) -> None:
    cfg = make_config(warehouse, str(tmp_path / "a.jsonl"))
    db = str(tmp_path / "s.sqlite")
    SnapshotStore(db).install(build_graph())  # persist a snapshot, then start fresh
    gateway = Gateway.build(cfg, snapshot_db=db)
    gateway.bootstrap_offline()  # no DataHub call
    env = gateway.dry_run("SELECT email FROM dim_users", "growth-agent")
    await gateway.aclose()
    assert any(v.code == "AIRLOCK-110" for v in env.verdicts)


async def test_denied_envelope_does_not_claim_a_row_limit_was_applied(tmp_path, warehouse) -> None:
    # The limit verdict describes what the rewriter is about to do. A denied statement never
    # reaches the rewriter, so reporting it would describe an event that did not happen - on the
    # one response the agent most needs to read cleanly.
    gateway, _ = _gateway(tmp_path, warehouse)
    env = await gateway.run_query(
        "SELECT name FROM dim_users WHERE ssn = '111-22-3333'", "growth-agent"
    )
    await gateway.aclose()
    assert env.status is EnvelopeStatus.DENIED
    assert [v.action for v in env.verdicts] == ["deny_statement"]


async def test_executed_envelope_still_reports_the_row_limit(tmp_path, warehouse) -> None:
    gateway, _ = _gateway(tmp_path, warehouse)
    env = await gateway.run_query("SELECT name FROM dim_users", "growth-agent")
    await gateway.aclose()
    assert any(v.action == "limit" for v in env.verdicts)
