"""Cancelling a Snowflake query has to actually reach Snowflake.

The adapter used to call `connection.cancel()` on a client disconnect. That method does not exist on
snowflake-connector-python's connection, so the call raised AttributeError into a blanket suppress
and cancellation silently did nothing - a dropped client left the query running and billing, while
the docstring and README edge 23 both claimed it had been stopped. Cancellation now goes through the
documented `SYSTEM$CANCEL_QUERY` entry point, keyed on the cursor's public `sfqid`.

Runs without a Snowflake account: the connection is faked behind the same two calls the adapter
makes. Skipped when the optional driver is absent, because the adapter imports it for error types.
"""

from __future__ import annotations

import pytest

pytest.importorskip("snowflake.connector")

from airlock.exec.snowflake_adapter import SnowflakeAdapter

DSN = "snowflake://user:pw@account/db/schema?warehouse=WH"
QUERY_ID = "01b2c3d4-0000-abcd"


class _FakeCursor:
    def __init__(self, log: list[tuple[str, object]], sfqid: str | None = None) -> None:
        self._log = log
        self.sfqid = sfqid
        self.description: list[object] = []

    def execute(self, sql: str, params: object = None, timeout: int | None = None) -> None:
        self._log.append((sql, params))

    def fetchall(self) -> list[object]:
        return []

    def close(self) -> None:
        pass


class _FakeConnection:
    def __init__(self, log: list[tuple[str, object]]) -> None:
        self._log = log
        self.closed = False

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._log)

    def close(self) -> None:
        self.closed = True


def test_the_driver_still_has_no_public_cancel() -> None:
    """Pins the assumption behind the SQL-based cancel.

    If a future driver adds a public cancel(), this fails and the adapter can be simplified - which
    is the point: the workaround should not outlive its reason.
    """
    from snowflake.connector.connection import SnowflakeConnection
    from snowflake.connector.cursor import SnowflakeCursor

    assert not hasattr(SnowflakeConnection, "cancel")
    assert not hasattr(SnowflakeCursor, "cancel")
    assert hasattr(SnowflakeCursor, "sfqid")  # what the cancel path keys on instead


async def test_cancel_issues_system_cancel_query_for_the_running_id(monkeypatch) -> None:
    log: list[tuple[str, object]] = []
    adapter = SnowflakeAdapter(DSN)
    opened: list[_FakeConnection] = []

    def fake_connect() -> _FakeConnection:
        conn = _FakeConnection(log)
        opened.append(conn)
        return conn

    monkeypatch.setattr(adapter, "_connect", fake_connect)
    await adapter._cancel_inflight(_FakeCursor(log, sfqid=QUERY_ID))

    assert log, "no statement was sent to Snowflake"
    sql, params = log[0]
    assert "SYSTEM$CANCEL_QUERY" in sql.upper()
    assert params == (QUERY_ID,)
    # It must run on its own connection - the query's connection is still blocked in execute() -
    # and must not leak it.
    assert opened and opened[0].closed


async def test_cancel_does_nothing_before_the_query_reaches_snowflake(monkeypatch) -> None:
    adapter = SnowflakeAdapter(DSN)

    def must_not_connect() -> _FakeConnection:
        raise AssertionError("opened a connection with no query id to cancel")

    monkeypatch.setattr(adapter, "_connect", must_not_connect)
    await adapter._cancel_inflight(_FakeCursor([], sfqid=None))  # execute() never got an id
    await adapter._cancel_inflight(None)  # thread had not built the cursor yet


async def test_a_failed_cancel_is_logged_not_raised(monkeypatch) -> None:
    # This runs while a CancelledError is already propagating; raising here would replace the real
    # outcome with a cleanup failure.
    adapter = SnowflakeAdapter(DSN)

    def refuse() -> _FakeConnection:
        raise OSError("network gone")

    monkeypatch.setattr(adapter, "_connect", refuse)
    await adapter._cancel_inflight(_FakeCursor([], sfqid=QUERY_ID))


def test_sessions_are_tagged_for_query_history() -> None:
    from airlock.exec.snowflake_adapter import parse_snowflake_dsn

    assert parse_snowflake_dsn(DSN)["session_parameters"]["QUERY_TAG"] == "airlock"
    # A caller-supplied tag wins; a malformed value is replaced rather than crashed on.
    custom = parse_snowflake_dsn(DSN + "&session_parameters=oops")
    assert custom["session_parameters"]["QUERY_TAG"] == "airlock"
