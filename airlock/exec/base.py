"""The WarehouseAdapter protocol and the adapter factory.

The protocol is deliberately small: run a read statement (with a timeout and honest truncation),
introspect tables/columns for the catalog tools, health-check, and close. Everything the gateway
needs from a warehouse goes through these five methods.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from airlock.config import WarehouseConfig
from airlock.errors import ConfigError


@dataclass(frozen=True, slots=True)
class QueryResult:
    columns: list[str]
    rows: list[dict[str, Any]]
    truncated: bool


@runtime_checkable
class WarehouseAdapter(Protocol):
    kind: str

    async def run(self, sql: str, *, timeout: float, row_limit: int) -> QueryResult: ...

    async def list_tables(self) -> list[str]: ...

    async def describe_table(self, name: str) -> list[tuple[str, str]]: ...

    async def healthcheck(self) -> None: ...

    async def close(self) -> None: ...


def make_adapter(config: WarehouseConfig, *, pool_size: int = 8) -> WarehouseAdapter:
    """Construct the adapter named by `config.kind`. The only place adapters are selected."""
    if config.kind == "duckdb":
        from airlock.exec.duckdb_adapter import DuckdbAdapter

        return DuckdbAdapter(config.dsn, pool_size=pool_size)
    if config.kind == "postgres":
        from airlock.exec.postgres_adapter import PostgresAdapter

        return PostgresAdapter(config.dsn, pool_size=pool_size)
    # Unreachable through config load (the kind is a Literal), but reachable when a WarehouseConfig
    # is built programmatically. Named error over a bare ValueError so the fix is in the message.
    raise ConfigError(
        f"no warehouse adapter for warehouse.kind {config.kind!r}; supported: duckdb, postgres"
    )
