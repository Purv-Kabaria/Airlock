"""The WarehouseAdapter protocol and the adapter factory.

The protocol is deliberately small: run a read statement (with a timeout and honest truncation),
introspect tables/columns for the catalog tools, health-check, and close. Everything the gateway
needs from a warehouse goes through these five methods.
"""

from __future__ import annotations

import datetime as dt
import decimal
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from airlock.config import WarehouseConfig
from airlock.errors import ConfigError


@dataclass(frozen=True, slots=True)
class QueryResult:
    columns: list[str]
    rows: list[dict[str, Any]]
    truncated: bool


def coerce_value(value: Any) -> Any:
    """Make one warehouse cell JSON-safe for the envelope. Shared by every adapter so a date or a
    decimal serializes the same way whichever warehouse produced it."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (dt.date, dt.datetime, dt.time)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return str(value)


@runtime_checkable
class WarehouseAdapter(Protocol):
    kind: str

    async def run(self, sql: str, *, timeout: float, row_limit: int) -> QueryResult: ...

    async def list_tables(self) -> list[str]: ...

    async def describe_table(self, name: str) -> list[tuple[str, str]]: ...

    async def healthcheck(self) -> None: ...

    async def close(self) -> None: ...


def make_adapter(config: WarehouseConfig, *, pool_size: int = 8) -> WarehouseAdapter:
    """Construct the adapter named by `config.kind`. The only place adapters are selected.

    Each adapter imports its driver lazily (inside the adapter, not here), so a gateway that only
    ever talks to DuckDB never needs snowflake-connector-python installed. Cloud drivers ship as
    optional extras (`pip install airlock-gateway[snowflake]`).
    """
    if config.kind == "duckdb":
        from airlock.exec.duckdb_adapter import DuckdbAdapter

        return DuckdbAdapter(config.dsn, pool_size=pool_size)
    if config.kind == "postgres":
        from airlock.exec.postgres_adapter import PostgresAdapter

        return PostgresAdapter(config.dsn, pool_size=pool_size)
    if config.kind == "snowflake":
        from airlock.exec.snowflake_adapter import SnowflakeAdapter

        return SnowflakeAdapter(config.dsn, pool_size=pool_size)
    if config.kind == "bigquery":
        from airlock.exec.bigquery_adapter import BigQueryAdapter

        return BigQueryAdapter(config.dsn)
    if config.kind == "sqlite":
        from airlock.exec.dbapi_adapter import make_sqlite_adapter

        return make_sqlite_adapter(config.dsn, pool_size=pool_size)
    if config.kind == "dbapi":
        from airlock.exec.dbapi_adapter import make_dbapi_adapter

        # Validated at config load: dbapi requires driver and dialect.
        assert config.driver is not None and config.dialect is not None
        return make_dbapi_adapter(
            driver=config.driver,
            dialect=config.dialect,
            dsn=config.dsn,
            connect_args=config.connect_args,
            pool_size=pool_size,
        )
    # Unreachable through config load (the kind is a Literal), but reachable when a WarehouseConfig
    # is built programmatically. Named error over a bare ValueError so the fix is in the message.
    raise ConfigError(
        f"no warehouse adapter for warehouse.kind {config.kind!r}; "
        "supported: duckdb, postgres, snowflake, bigquery, sqlite, dbapi"
    )
