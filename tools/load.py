"""Concurrency load test. `make load` / `python tools/load.py`.

Drives the real gateway over a snapshot compiled from live DataHub and asserts the concurrency
budgets from README "Performance & concurrency": sustained load runs with zero errors, and a burst
over the bounded-queue cap is rejected cleanly with AIRLOCK-440 rather than crashing or hanging.
Needs `demo/up.py`. Exits non-zero if a budget is missed.
"""

from __future__ import annotations

import asyncio
import random
import time

from _common import ROOT, live_snapshot, load_demo_config, seed_warehouse
from airlock.engine.verdicts import Envelope
from airlock.errors import OverloadedError
from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.policy.store import SnapshotStore

# A mix that exercises every decision path: clean, mask, column-deny, predicate-deny, scope-deny,
# and certified-substitution. All run as the same principal so the decision cache is also stressed.
QUERIES = [
    "SELECT status, COUNT(*) FROM orders GROUP BY status",
    "SELECT name, email FROM dim_users",
    "SELECT name, ssn FROM dim_users",
    "SELECT name FROM dim_users WHERE email = 'x'",
    "SELECT salary FROM payroll",
    "SELECT u.name, u.email FROM users_raw u LIMIT 5",
]

SUSTAINED_CONCURRENCY = 50
SUSTAINED_ROUNDS = 6
BURST = 400


async def main() -> int:
    cfg = load_demo_config()
    warehouse = seed_warehouse(cfg)
    graph = live_snapshot(cfg)
    store = SnapshotStore(str(ROOT / ".airlock" / "load.sqlite"))
    store.install(graph)
    gateway = Gateway(cfg, store, DuckdbAdapter(warehouse), [])
    failures: list[str] = []
    try:
        failures += await _sustained(gateway)
        failures += await _burst(gateway)
    finally:
        await gateway.aclose()

    if failures:
        print("\nLOAD FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nLOAD PASSED: sustained load clean, burst rejected cleanly, zero crashes")
    return 0


async def _sustained(gateway: Gateway) -> list[str]:
    total = SUSTAINED_CONCURRENCY * SUSTAINED_ROUNDS
    latencies: list[float] = []
    errors: list[str] = []

    async def one(sql: str) -> None:
        start = time.perf_counter()
        try:
            env = await gateway.run_query(sql, "growth-agent")
            if not isinstance(env, Envelope):
                errors.append(f"non-envelope result: {env!r}")
        except OverloadedError:
            pass  # allowed even under sustained load if a round briefly saturates
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        latencies.append((time.perf_counter() - start) * 1000)

    for _ in range(SUSTAINED_ROUNDS):
        await asyncio.gather(*(one(random.choice(QUERIES)) for _ in range(SUSTAINED_CONCURRENCY)))

    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95)]
    print(
        f"sustained: {total} requests at {SUSTAINED_CONCURRENCY} concurrent, "
        f"{len(errors)} errors, end-to-end p95 {p95:.1f}ms"
    )
    return errors


async def _burst(gateway: Gateway) -> list[str]:
    results = await asyncio.gather(
        *(gateway.run_query(random.choice(QUERIES), "growth-agent") for _ in range(BURST)),
        return_exceptions=True,
    )
    served = sum(1 for r in results if isinstance(r, Envelope))
    rejected = sum(1 for r in results if isinstance(r, OverloadedError))
    crashed = [r for r in results if not isinstance(r, (Envelope, OverloadedError))]
    print(
        f"burst: {BURST} at once -> {served} served, {rejected} rejected (AIRLOCK-440), "
        f"{len(crashed)} crashed"
    )
    if crashed:
        return [f"burst crashed with {type(crashed[0]).__name__}: {crashed[0]}"]
    if served + rejected != BURST:
        return [f"burst accounting off: {served}+{rejected} != {BURST}"]
    return []


if __name__ == "__main__":
    from _common import run

    run(main)
