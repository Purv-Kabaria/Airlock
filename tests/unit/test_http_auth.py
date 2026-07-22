"""Per-request principal resolution for HTTP transport.

Over stdio the client launches the process, so one process serves one agent and the startup
principal is the identity. Over HTTP one process serves many clients concurrently, so identity has
to come from the request - otherwise every agent that connects inherits whichever principal the
operator named at startup, which is precisely the over-permissioned credential Airlock exists to
remove.
"""

from __future__ import annotations

import pytest
from tests.unit.conftest import build_graph, make_config, seed_duckdb

from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.mcp.auth import ANONYMOUS, PRINCIPAL_HEADER, principal_from_headers
from airlock.mcp.server import build_mcp
from airlock.policy.store import SnapshotStore


@pytest.fixture
def cfg(tmp_path):
    return make_config(str(tmp_path / "w.duckdb"), str(tmp_path / "a.jsonl"))


def test_valid_key_resolves_to_its_principal(cfg) -> None:
    # make_config registers growth-agent with key "g" and finance-agent with key "f".
    assert principal_from_headers(cfg, {PRINCIPAL_HEADER: "g"}) == "growth-agent"
    assert principal_from_headers(cfg, {PRINCIPAL_HEADER: "f"}) == "finance-agent"


@pytest.mark.parametrize("headers", [{}, {PRINCIPAL_HEADER: ""}, {PRINCIPAL_HEADER: "guess"}])
def test_missing_or_unknown_key_is_deny_all(cfg, headers) -> None:
    assert principal_from_headers(cfg, headers) == ANONYMOUS


def _gateway(tmp_path):
    wh = str(tmp_path / "w.duckdb")
    seed_duckdb(wh)
    cfg = make_config(wh, str(tmp_path / "a.jsonl"))
    store = SnapshotStore(str(tmp_path / "s.sqlite"))
    store.install(build_graph())
    return Gateway(cfg, store, DuckdbAdapter(wh), []), cfg


async def test_per_request_auth_never_falls_back_to_the_startup_principal(tmp_path) -> None:
    # The regression this guards: a call that arrives with nothing to authenticate with must be
    # deny-all, not the principal named at startup. build_mcp is given a config (HTTP mode) and
    # "growth-agent" as the startup name; a call with no request in scope must not get its scope.
    gateway, cfg = _gateway(tmp_path)
    mcp = build_mcp(gateway, "growth-agent", cfg)
    result = await mcp.call_tool("warehouse_list_tables", {})
    content = result[1] if isinstance(result, tuple) else result.structuredContent
    await gateway.aclose()
    assert content["principal"] == ANONYMOUS
    assert content["tables"] == []  # deny-all sees nothing, not growth-agent's Marketing tables


async def test_stdio_keeps_the_startup_principal(tmp_path) -> None:
    # Without a config there is no per-request auth: the process boundary is the identity boundary.
    gateway, _ = _gateway(tmp_path)
    mcp = build_mcp(gateway, "growth-agent")
    result = await mcp.call_tool("warehouse_list_tables", {})
    content = result[1] if isinstance(result, tuple) else result.structuredContent
    await gateway.aclose()
    assert content["principal"] == "growth-agent"
    assert "dim_users" in content["tables"]
