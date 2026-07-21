"""MCP eval against the live demo stack. `make eval` / `python tools/eval.py`.

A mix of clean, maskable, deniable, and substitutable queries with verified expected outcomes, run
through the real gateway over a snapshot compiled from live DataHub. Doubles as the demo rehearsal:
if this is green, the scripted prompts behave. Exits non-zero on any mismatch. Needs `demo/up.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

from _common import ROOT, live_snapshot, load_demo_config, seed_warehouse
from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.policy.store import SnapshotStore


@dataclass(frozen=True)
class Case:
    principal: str
    sql: str
    expect_status: str
    expect_codes: tuple[str, ...] = ()


CASES = [
    Case("growth-agent", "SELECT status, COUNT(*) FROM orders GROUP BY status", "executed"),
    Case(
        "growth-agent",
        "SELECT name, email FROM dim_users",
        "executed_with_modifications",
        ("AIRLOCK-110",),
    ),
    Case(
        "growth-agent",
        "SELECT phone FROM dim_users",
        "executed_with_modifications",
        ("AIRLOCK-110",),
    ),
    Case(
        "growth-agent",
        "SELECT name, ssn FROM dim_users",
        "executed_with_modifications",
        ("AIRLOCK-120",),
    ),
    Case(
        "growth-agent",
        "SELECT name FROM users_raw",
        "executed_with_modifications",
        ("AIRLOCK-201",),
    ),
    Case("growth-agent", "SELECT COUNT(ssn) FROM dim_users", "denied", ("AIRLOCK-121",)),
    Case(
        "growth-agent",
        "SELECT name FROM dim_users WHERE email = 'ada@corp.com'",
        "denied",
        ("AIRLOCK-130",),
    ),
    Case("growth-agent", "SELECT salary FROM payroll", "denied", ("AIRLOCK-301",)),
    Case(
        "finance-agent",
        "SELECT emp_id, salary FROM payroll",
        "executed_with_modifications",
        ("AIRLOCK-110",),
    ),
    Case("growth-agent", "show me the biggest spenders", "error", ("AIRLOCK-406",)),
    # user_report.contact is untagged; the mask comes from DataHub's column-level lineage back to
    # dim_users.email. If this case regresses, propagation stopped reading the graph.
    Case(
        "growth-agent",
        "SELECT user_id, contact FROM user_report",
        "executed_with_modifications",
        ("AIRLOCK-113",),
    ),
]


async def main() -> int:
    cfg = load_demo_config()
    warehouse = seed_warehouse(cfg)
    graph = live_snapshot(cfg)  # real snapshot from live DataHub
    failures: list[str] = []
    store = SnapshotStore(str(ROOT / ".airlock" / "eval.sqlite"))
    store.install(graph)
    gateway = Gateway(cfg, store, DuckdbAdapter(warehouse), [])
    try:
        for i, case in enumerate(CASES, 1):
            env = await gateway.run_query(case.sql, case.principal)
            codes = {v.code for v in env.verdicts}
            ok = str(env.status) == case.expect_status and all(
                c in codes for c in case.expect_codes
            )
            mark = "ok " if ok else "FAIL"
            print(f"  [{mark}] {i:2} {case.principal:<13} {env.status!s:<28} {case.sql[:48]}")
            if not ok:
                failures.append(
                    f"case {i}: expected {case.expect_status}/{case.expect_codes}, got {env.status}/{sorted(codes)}"
                )
    finally:
        await gateway.aclose()

    if failures:
        print("\nEVAL FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print(f"\nEVAL PASSED: {len(CASES)}/{len(CASES)}")
    return 0


if __name__ == "__main__":
    from _common import run

    run(main)
