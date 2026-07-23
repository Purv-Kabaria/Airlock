"""BigQuery adapter.

The BigQuery client is HTTP/REST, not a socket connection, so there is no pool to manage - one
`Client` is reused and every blocking call runs on a worker thread via `asyncio.to_thread`. A
statement timeout is enforced by `QueryJob.result(timeout=...)`; on timeout or client disconnect
the job is cancelled with `QueryJob.cancel()` so it stops being billed, not just stops being
awaited.

The driver is an optional dependency (`pip install airlock-gateway[bigquery]`), imported lazily so
a gateway that never uses BigQuery need not have it installed and this module's DSN parsing stays
testable without it.

Config: `warehouse.dsn` is

    bigquery://<project>/<dataset>?location=US&credentials_path=/path/to/service-account.json

`<dataset>` is required for table introspection (`warehouse_list_tables` / `describe_table`) because
BigQuery's INFORMATION_SCHEMA is dataset-scoped. Credentials come from `credentials_path` if given,
otherwise from Application Default Credentials (the `GOOGLE_APPLICATION_CREDENTIALS` env var or the
ambient service account), exactly as every other Google client resolves them.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any
from urllib.parse import parse_qs, urlparse

from airlock.errors import ConfigError, WarehouseUnavailableError
from airlock.exec.base import QueryResult, coerce_value
from airlock.logging import get_logger

log = get_logger("airlock.exec.bigquery")


def parse_bigquery_dsn(dsn: str) -> dict[str, str]:
    """Turn a BigQuery URL into connection settings. Pure and driver-free, so it unit-tests without
    the client library installed."""
    parsed = urlparse(dsn)
    if parsed.scheme != "bigquery":
        raise ConfigError(
            f"bigquery dsn must start with 'bigquery://', got {parsed.scheme or '(none)'}://"
        )
    if not parsed.hostname:
        raise ConfigError(
            "bigquery dsn is missing the project (the host part): bigquery://<project>/<dataset>"
        )
    settings: dict[str, str] = {"project": parsed.hostname}
    parts = [p for p in parsed.path.split("/") if p]
    if parts:
        settings["dataset"] = parts[0]
    for key, values in parse_qs(parsed.query).items():
        settings[key] = values[-1]
    return settings


class BigQueryAdapter:
    kind = "bigquery"

    def __init__(self, dsn: str) -> None:
        self._settings = parse_bigquery_dsn(dsn)  # fail fast on a bad DSN at construction
        self._project = self._settings["project"]
        self._dataset = self._settings.get("dataset")
        self._location = self._settings.get("location")
        self._client: Any | None = None
        self._lock = asyncio.Lock()

    async def run(self, sql: str, *, timeout: float, row_limit: int) -> QueryResult:
        import google.api_core.exceptions as gexc

        client = await self._get_client()
        job = await asyncio.to_thread(client.query, sql)
        try:
            row_iter = await asyncio.to_thread(_result, job, timeout, row_limit)
        except asyncio.CancelledError:
            await self._cancel(job)
            raise
        except (TimeoutError, gexc.RetryError) as exc:
            await self._cancel(job)
            raise WarehouseUnavailableError(
                self.kind, f"statement timed out after {timeout:g}s"
            ) from exc
        except gexc.GoogleAPIError as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc

        columns = [field.name for field in row_iter.schema]
        materialized = list(row_iter)
        truncated = len(materialized) >= row_limit
        shaped = [
            {col: coerce_value(row[col]) for col in columns} for row in materialized[:row_limit]
        ]
        return QueryResult(columns=columns, rows=shaped, truncated=truncated)

    async def _cancel(self, job: Any) -> None:
        with contextlib.suppress(Exception):
            await asyncio.to_thread(job.cancel)

    async def list_tables(self) -> list[str]:
        if not self._dataset:
            return []
        _, rows = await self._query(
            f"SELECT table_schema, table_name FROM `{self._project}`.`{self._dataset}`"
            ".INFORMATION_SCHEMA.TABLES ORDER BY 1, 2"
        )
        return [f"{schema}.{name}" for schema, name in rows]

    async def describe_table(self, name: str) -> list[tuple[str, str]]:
        if not self._dataset:
            return []
        _, _, table = name.rpartition(".")
        _, rows = await self._query(
            f"SELECT column_name, data_type FROM `{self._project}`.`{self._dataset}`"
            ".INFORMATION_SCHEMA.COLUMNS WHERE table_name = @table ORDER BY ordinal_position",
            {"table": table},
        )
        return [(c, t) for c, t in rows]

    async def healthcheck(self) -> None:
        import google.api_core.exceptions as gexc

        try:
            await self._query("SELECT 1")
        except gexc.GoogleAPIError as exc:
            raise WarehouseUnavailableError(self.kind, str(exc).splitlines()[0]) from exc

    async def _query(
        self, sql: str, params: dict[str, str] | None = None
    ) -> tuple[list[str], list[tuple[Any, ...]]]:
        from google.cloud import bigquery

        client = await self._get_client()
        job_config = None
        if params:
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter(k, "STRING", v) for k, v in params.items()
                ]
            )
        job = await asyncio.to_thread(client.query, sql, job_config)
        row_iter = await asyncio.to_thread(job.result)
        columns = [field.name for field in row_iter.schema]
        rows = [tuple(row.values()) for row in row_iter]
        return columns, rows

    async def close(self) -> None:
        async with self._lock:
            client, self._client = self._client, None
        if client is not None:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(client.close)

    async def _get_client(self) -> Any:
        async with self._lock:
            if self._client is None:
                self._client = await asyncio.to_thread(self._build_client)
            return self._client

    def _build_client(self) -> Any:
        from google.cloud import bigquery

        credentials = None
        credentials_path = self._settings.get("credentials_path")
        if credentials_path:
            from google.oauth2 import service_account

            credentials = service_account.Credentials.from_service_account_file(credentials_path)
        return bigquery.Client(
            project=self._project, credentials=credentials, location=self._location
        )


def _result(job: Any, timeout: float, row_limit: int) -> Any:
    """Block for the query result within the timeout, capping the rows fetched. Runs on a worker
    thread. `max_results` is a fetch cap over the LIMIT the rewriter already injected - a
    fail-closed backstop, not the primary bound."""
    return job.result(timeout=timeout, max_results=row_limit)
