"""The deny-then-reformulate loop that is Airlock's reason to speak to an agent instead of a human.

A blocked human retries the same query in frustration; a blocked agent that is told, in structured
form, why it was blocked and what to do instead can fix its next call. These tests pin that: each
case sends a query Airlock refuses, asserts the refusal carries an actionable hint (never a dead
end), then sends the reformulation a reader of that hint would write and asserts it goes through.
Same real gateway path as production - parse, decide, rewrite, execute - over a fake graph and a
real DuckDB, no network. The README claims this loop is tested; this is where.
"""

from __future__ import annotations

from tests.unit.conftest import RecordingSink, build_graph, make_config

from airlock.engine.verdicts import EnvelopeStatus
from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.policy.store import SnapshotStore

_BLOCKED = {EnvelopeStatus.DENIED, EnvelopeStatus.ERROR}
_OK = {EnvelopeStatus.EXECUTED, EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS}


def _gateway(tmp_path, warehouse: str) -> Gateway:
    cfg = make_config(warehouse, str(tmp_path / "audit.jsonl"))
    store = SnapshotStore(str(tmp_path / "snap.sqlite"))
    store.install(build_graph())
    return Gateway(cfg, store, DuckdbAdapter(warehouse), [RecordingSink()])


def _assert_actionable(env, code: str) -> None:
    """The refusal must name `code` and every verdict that blocks must carry a hint - the signal the
    agent steers on. A deny without a hint is the dead end this project exists to remove."""
    assert env.status in _BLOCKED, f"expected a refusal, got {env.status}"
    codes = {v.code for v in env.verdicts}
    assert code in codes, f"expected {code}, got {sorted(codes)}"
    hinted = [v for v in env.verdicts if v.code == code]
    assert hinted and all(v.hint for v in hinted), f"{code} carried no actionable hint"


async def test_aggregate_over_denied_column_recovers_via_count_star(tmp_path, warehouse) -> None:
    gateway = _gateway(tmp_path, warehouse)
    blocked = await gateway.run_query("SELECT COUNT(ssn) FROM dim_users", "growth-agent")
    _assert_actionable(blocked, "AIRLOCK-121")  # hint points at COUNT(*) / a non-sensitive key

    fixed = await gateway.run_query("SELECT COUNT(*) FROM dim_users", "growth-agent")
    await gateway.aclose()
    assert fixed.status in _OK
    assert fixed.rows is not None and list(fixed.rows[0].values()) == [3]  # all three rows counted


async def test_masked_predicate_recovers_by_selecting_the_masked_column(
    tmp_path, warehouse
) -> None:
    gateway = _gateway(tmp_path, warehouse)
    # Filtering on a masked column would leak membership (WHERE email='x' proves the row exists).
    blocked = await gateway.run_query(
        "SELECT name FROM dim_users WHERE email = 'ada@corp.com'", "growth-agent"
    )
    _assert_actionable(blocked, "AIRLOCK-130")

    # The sanctioned move: read the masked column instead of filtering on its cleartext.
    fixed = await gateway.run_query("SELECT name, email FROM dim_users", "growth-agent")
    await gateway.aclose()
    assert fixed.status is EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS
    assert fixed.rows is not None and len(fixed.rows) == 3
    assert all("***" in row["email"] for row in fixed.rows)


async def test_natural_language_recovers_in_one_turn(tmp_path, warehouse) -> None:
    gateway = _gateway(tmp_path, warehouse)
    blocked = await gateway.run_query("show me the biggest spenders", "growth-agent")
    _assert_actionable(blocked, "AIRLOCK-406")  # hint says: this tool takes SQL; list tables first

    fixed = await gateway.run_query(
        "SELECT user_id, SUM(total) AS spend FROM orders GROUP BY user_id ORDER BY spend DESC",
        "growth-agent",
    )
    await gateway.aclose()
    assert fixed.status in _OK
    assert fixed.rows is not None and len(fixed.rows) > 0
