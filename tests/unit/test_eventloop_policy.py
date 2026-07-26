"""Windows needs the selector event loop for natively-async drivers.

psycopg refuses the ProactorEventLoop asyncio picks by default on Windows, so `kind: postgres`
raised InterfaceError at the first query on every Windows machine. The demo warehouse is DuckDB, so
nothing in CI touched that path. These tests pin the selection rule itself, which is what regressed.
"""

from __future__ import annotations

import asyncio

import pytest

from airlock.cli._eventloop import _NEEDS_SELECTOR_LOOP, select_event_loop_for


def test_postgres_is_marked_as_needing_the_selector_loop() -> None:
    assert "postgres" in _NEEDS_SELECTOR_LOOP


@pytest.mark.parametrize("kind", ["duckdb", "sqlite", "bigquery", "snowflake", "dbapi"])
def test_thread_backed_warehouses_keep_the_default_loop(kind: str, monkeypatch) -> None:
    # These drivers run on worker threads and never share the loop, so they must not pay the
    # selector loop's 512-socket ceiling.
    monkeypatch.setattr("sys.platform", "win32")
    calls: list[object] = []
    monkeypatch.setattr(asyncio, "set_event_loop_policy", lambda p: calls.append(p))
    select_event_loop_for(kind)
    assert calls == []


def test_non_windows_is_always_a_no_op(monkeypatch) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    calls: list[object] = []
    monkeypatch.setattr(asyncio, "set_event_loop_policy", lambda p: calls.append(p))
    select_event_loop_for("postgres")
    assert calls == []


def test_postgres_on_windows_selects_a_policy(monkeypatch) -> None:
    monkeypatch.setattr("sys.platform", "win32")
    # The class exists only on Windows; supply a stand-in so this asserts the *rule* on every OS.
    sentinel = type("FakePolicy", (), {})
    monkeypatch.setattr(asyncio, "WindowsSelectorEventLoopPolicy", sentinel, raising=False)
    calls: list[object] = []
    monkeypatch.setattr(asyncio, "set_event_loop_policy", lambda p: calls.append(p))
    select_event_loop_for("postgres")
    assert len(calls) == 1 and isinstance(calls[0], sentinel)
