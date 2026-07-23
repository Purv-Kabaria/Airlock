"""The generic DB-API adapter, exercised live through SQLite (stdlib, no dependency).

SQLite is the concrete case for the generic path: `run`, the connection pool, value coercion,
introspection, and the timeout/interrupt machinery are the same code every DB-API driver goes
through, so testing it against a real SQLite database verifies the path that MySQL, Trino, ODBC,
and the rest ride. The parts that can only differ per driver - the paramstyle, the module import -
are unit-tested directly.
"""

from __future__ import annotations

import sqlite3

import pytest

from airlock.errors import ConfigError, WarehouseUnavailableError
from airlock.exec.base import WarehouseAdapter, make_adapter
from airlock.exec.dbapi_adapter import _bind, _sqlite_path, make_sqlite_adapter


def _config(kind: str, dsn: str, **extra):  # type: ignore[no-untyped-def]
    from airlock.config import WarehouseConfig

    return WarehouseConfig(kind=kind, dsn=dsn, **extra)


@pytest.fixture
def sqlite_db(tmp_path):
    path = str(tmp_path / "wh.sqlite")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE users(id INTEGER, name TEXT, email TEXT, joined DATE)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        [(1, "Ada", "ada@corp.com", "2026-01-04"), (2, "Bo", "bo@x.io", "2026-02-11")],
    )
    conn.commit()
    conn.close()
    return path


# -- live behavior through SQLite ------------------------------------------------------------------


async def test_run_returns_shaped_rows(sqlite_db) -> None:
    adapter = make_sqlite_adapter(sqlite_db)
    try:
        result = await adapter.run(
            "SELECT id, name FROM users ORDER BY id", timeout=5, row_limit=10
        )
        assert result.columns == ["id", "name"]
        assert result.rows == [{"id": 1, "name": "Ada"}, {"id": 2, "name": "Bo"}]
        assert result.truncated is False
    finally:
        await adapter.close()


async def test_row_limit_truncates(sqlite_db) -> None:
    adapter = make_sqlite_adapter(sqlite_db)
    try:
        result = await adapter.run("SELECT id FROM users ORDER BY id", timeout=5, row_limit=1)
        assert len(result.rows) == 1
        assert result.truncated is True  # more rows existed than the cap
    finally:
        await adapter.close()


async def test_list_tables_and_describe(sqlite_db) -> None:
    adapter = make_sqlite_adapter(sqlite_db)
    try:
        assert await adapter.list_tables() == ["users"]
        described = dict(await adapter.describe_table("users"))
        assert described["name"] == "TEXT"
        assert described["id"] == "INTEGER"
    finally:
        await adapter.close()


async def test_healthcheck_passes_on_a_live_db(sqlite_db) -> None:
    adapter = make_sqlite_adapter(sqlite_db)
    try:
        await adapter.healthcheck()  # must not raise
    finally:
        await adapter.close()


async def test_a_bad_statement_becomes_a_typed_error(sqlite_db) -> None:
    adapter = make_sqlite_adapter(sqlite_db)
    try:
        with pytest.raises(WarehouseUnavailableError):
            await adapter.run("SELECT * FROM does_not_exist", timeout=5, row_limit=10)
    finally:
        await adapter.close()


async def test_values_are_json_safe(sqlite_db) -> None:
    # A DATE column comes back as a string via coerce_value, not a python date the envelope can't
    # serialize. (SQLite stores it as text, but the shared coercion is what the envelope relies on.)
    adapter = make_sqlite_adapter(sqlite_db)
    try:
        result = await adapter.run("SELECT joined FROM users ORDER BY id", timeout=5, row_limit=10)
        assert all(isinstance(r["joined"], str) for r in result.rows)
    finally:
        await adapter.close()


async def test_pool_reuses_connections_across_queries(sqlite_db) -> None:
    adapter = make_sqlite_adapter(sqlite_db, pool_size=2)
    try:
        for _ in range(5):
            await adapter.run("SELECT COUNT(*) AS n FROM users", timeout=5, row_limit=10)
        assert len(adapter._all) <= 2  # capped by pool_size, reused not re-created
    finally:
        await adapter.close()


# -- factory + config ------------------------------------------------------------------------------


def test_make_adapter_builds_sqlite() -> None:
    adapter = make_adapter(_config("sqlite", ":memory:"))
    assert isinstance(adapter, WarehouseAdapter)
    assert adapter.kind == "sqlite"


def test_sqlite_kind_resolves_to_sqlite_dialect() -> None:
    assert _config("sqlite", ":memory:").dialect == "sqlite"


def test_dbapi_requires_driver_and_dialect() -> None:
    with pytest.raises(Exception, match="driver"):
        _config("dbapi", "host/db", dialect="mysql")  # missing driver
    with pytest.raises(Exception, match="dialect"):
        _config("dbapi", "host/db", driver="pymysql")  # missing dialect


def test_dbapi_dialect_is_independent_of_kind() -> None:
    cfg = _config("dbapi", "host/db", driver="pymysql", dialect="mysql")
    assert cfg.dialect == "mysql"  # not "dbapi"


def test_make_adapter_dbapi_reports_a_missing_driver_clearly() -> None:
    # The escape hatch: a driver that isn't installed fails at build with the install command, not
    # with an opaque ImportError at first query.
    with pytest.raises(ConfigError, match="not importable"):
        make_adapter(
            _config("dbapi", "x", driver="definitely_not_a_real_driver_xyz", dialect="mysql")
        )


# -- paramstyle + dsn (per-driver bits that can't ride the SQLite test) ----------------------------


@pytest.mark.parametrize(
    "style,expected_placeholders",
    [
        ("qmark", ["?", "?"]),
        ("format", ["%s", "%s"]),
        ("numeric", [":1", ":2"]),
        ("named", [":p0", ":p1"]),
        ("pyformat", ["%(p0)s", "%(p1)s"]),
    ],
)
def test_bind_renders_every_dbapi_paramstyle(style, expected_placeholders) -> None:
    placeholders, params = _bind(style, ["a", "b"])
    assert placeholders == expected_placeholders
    if style in ("named", "pyformat"):
        assert params == {"p0": "a", "p1": "b"}
    else:
        assert params == ("a", "b")


def test_bind_rejects_an_unknown_paramstyle() -> None:
    with pytest.raises(ConfigError, match="paramstyle"):
        _bind("mystery", ["a"])


@pytest.mark.parametrize(
    "dsn,expected",
    [
        ("sqlite:///data/wh.db", "data/wh.db"),
        ("sqlite://wh.db", "wh.db"),
        ("sqlite::memory:", ":memory:"),
        (":memory:", ":memory:"),
        ("", ":memory:"),
        ("/abs/path.sqlite", "/abs/path.sqlite"),
    ],
)
def test_sqlite_path_normalization(dsn, expected) -> None:
    assert _sqlite_path(dsn) == expected
