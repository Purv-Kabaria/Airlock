"""The three MCP tools: typed envelopes, scope filtering, and no leaked exceptions."""

from __future__ import annotations

from tests.unit.conftest import build_graph, make_config, seed_duckdb

from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.mcp.server import build_mcp
from airlock.policy.store import SnapshotStore


def _build(tmp_path):
    wh = str(tmp_path / "w.duckdb")
    seed_duckdb(wh)
    cfg = make_config(wh, str(tmp_path / "a.jsonl"))
    store = SnapshotStore(str(tmp_path / "s.sqlite"))
    store.install(build_graph())
    gateway = Gateway(cfg, store, DuckdbAdapter(wh), [])
    return gateway, build_mcp(gateway, "growth-agent")


async def _content(result) -> dict:
    return result[1] if isinstance(result, tuple) else result.structuredContent


async def test_list_tables_is_scope_filtered(tmp_path) -> None:
    gateway, mcp = _build(tmp_path)
    content = await _content(await mcp.call_tool("warehouse_list_tables", {}))
    await gateway.aclose()
    assert "payroll" not in content["tables"]  # Finance domain hidden from growth-agent
    assert "dim_users" in content["tables"]


async def test_describe_reports_per_column_policy(tmp_path) -> None:
    gateway, mcp = _build(tmp_path)
    content = await _content(await mcp.call_tool("warehouse_describe_table", {"name": "dim_users"}))
    await gateway.aclose()
    assert content["in_scope"] is True
    policy = {c["name"]: c["policy"] for c in content["columns"]}
    # The card must match what a query actually triggers: email masked, ssn denied, name allowed.
    assert policy["email"] == "mask"
    assert policy["ssn"] == "deny"
    assert policy["name"] == "allow"
    email = next(c for c in content["columns"] if c["name"] == "email")
    assert email["note"] and "mask" in email["note"]
    assert content["note"] and "masked" in content["note"]


async def test_describe_card_matches_enforcement(tmp_path) -> None:
    """The plan the agent reads must equal what running the query would do - same engine, so a
    column the card calls mask/deny is one the gateway actually masks or denies."""
    gateway, mcp = _build(tmp_path)
    card = await _content(await mcp.call_tool("warehouse_describe_table", {"name": "dim_users"}))
    env = await gateway.run_query("SELECT name, email, ssn FROM dim_users", "growth-agent")
    await gateway.aclose()
    row = env.rows[0]
    policy = {c["name"]: c["policy"] for c in card["columns"]}
    assert policy["ssn"] == "deny" and row["ssn"] is None
    assert policy["email"] == "mask" and row["email"] != "ada@corp.com"
    assert policy["name"] == "allow" and row["name"] == "Ada"


async def test_describe_out_of_scope_and_unknown_are_indistinguishable(tmp_path) -> None:
    # Enumeration protection: an out-of-scope table and a nonexistent one return the same shape,
    # so an agent cannot map what exists beyond its scope.
    gateway, mcp = _build(tmp_path)
    out = await _content(await mcp.call_tool("warehouse_describe_table", {"name": "payroll"}))
    ghost = await _content(await mcp.call_tool("warehouse_describe_table", {"name": "nope"}))
    await gateway.aclose()
    assert out["in_scope"] is False and out["columns"] == []
    assert ghost["in_scope"] is False and ghost["columns"] == []
    assert out["note"] == ghost["note"]


async def test_run_query_masks_through_the_tool(tmp_path) -> None:
    gateway, mcp = _build(tmp_path)
    content = await _content(
        await mcp.call_tool("warehouse_run_query", {"sql": "SELECT email FROM dim_users"})
    )
    await gateway.aclose()
    assert content["status"] == "executed_with_modifications"
    assert all("***" in row["email"] for row in content["rows"])
