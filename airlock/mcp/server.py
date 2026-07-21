"""The FastMCP server: three read-only tools, each returning a typed envelope.

Tools are prefixed and action-oriented; every response is `structuredContent` so clients get
typed data, not prose. All three annotate `readOnlyHint: true` / `openWorldHint: false` — Airlock
is read-only in v1. Errors are returned as verdict envelopes, never raised across the wire, so an
agent that hits a deny can read *why* and reformulate. No traceback ever reaches an MCP response.
"""

from __future__ import annotations

import asyncio
import contextlib

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from airlock.config import AirlockConfig
from airlock.engine.verdicts import Envelope, ReasonCode, Subject, Verdict
from airlock.errors import AirlockError
from airlock.gateway import Gateway, new_request_id
from airlock.logging import get_logger
from airlock.mcp.health import start_health_server
from airlock.policy.graph import Principal

log = get_logger("airlock.mcp.server")

_READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


class ColumnInfo(BaseModel):
    name: str
    type: str
    sensitive: bool


class TablesResult(BaseModel):
    principal: str
    tables: list[str]
    note: str


class DescribeResult(BaseModel):
    table: str
    in_scope: bool
    columns: list[ColumnInfo]
    note: str | None = None


def build_mcp(gateway: Gateway, principal_name: str) -> FastMCP:
    mcp = FastMCP(
        name="airlock-warehouse",
        instructions=(
            "A governed SQL warehouse. Send SQL to warehouse_run_query; the gateway enforces "
            "catalog policy (masking, denial, certified-table substitution) and returns rows plus "
            "a machine-readable list of every change it made. Read the verdicts and reformulate if "
            "a column was denied."
        ),
    )

    @mcp.tool(
        name="warehouse_run_query",
        title="Run a governed SQL query",
        description=(
            "Execute one read-only SQL SELECT against the warehouse. The gateway parses the query, "
            "masks or removes columns your policy protects, redirects deprecated tables to certified "
            "equivalents, injects a row limit, runs it, and returns rows plus a `verdicts` list "
            "explaining every modification with a stable reason code and a fix hint. Use this for all "
            "data reads. Do NOT use it for DDL/DML, multi-statement scripts, or natural-language "
            "questions - it takes a single SELECT statement. If a column is denied, read the hint and "
            "resend without it."
        ),
        annotations=_READ_ONLY,
        structured_output=True,
    )
    async def warehouse_run_query(sql: str) -> Envelope:
        try:
            return await gateway.run_query(sql, principal_name)
        except AirlockError as exc:
            return Envelope.error(
                request_id=new_request_id(),
                principal=principal_name,
                original_sql=sql,
                verdict=exc.to_verdict(),
                snapshot=gateway.snapshot_hash(),
            )
        except Exception as exc:
            request_id = new_request_id()
            log.error("tool.unexpected_error", request_id=request_id, detail=str(exc))
            return Envelope.error(
                request_id=request_id,
                principal=principal_name,
                original_sql=sql,
                verdict=Verdict.make(
                    ReasonCode.PARSE_ERROR,
                    "deny_statement",
                    Subject.statement(),
                    "The gateway could not process this request.",
                    hint="Check the SQL is a single valid SELECT and retry.",
                ),
                snapshot=gateway.snapshot_hash(),
            )

    @mcp.tool(
        name="warehouse_list_tables",
        title="List tables you can query",
        description=(
            "List the warehouse tables visible to your principal - those within your catalog scope. "
            "Tables outside your domain are not listed, so this reflects exactly what you may read. "
            "Use it to discover table names before writing a query."
        ),
        annotations=_READ_ONLY,
        structured_output=True,
    )
    async def warehouse_list_tables() -> TablesResult:
        tables = gateway.visible_tables(principal_name)
        return TablesResult(
            principal=principal_name,
            tables=tables,
            note=f"{len(tables)} table(s) within your scope; others are hidden by policy.",
        )

    @mcp.tool(
        name="warehouse_describe_table",
        title="Describe a table's columns",
        description=(
            "Return a table's columns and types from the catalog, flagging which are sensitive "
            "(masked or denied when queried). Use it to plan a query that avoids protected columns. "
            "Tables outside your scope return in_scope=false with no columns."
        ),
        annotations=_READ_ONLY,
        structured_output=True,
    )
    async def warehouse_describe_table(name: str) -> DescribeResult:
        # Pin one snapshot for the whole call so a concurrent refresh cannot make the scope check
        # and the lookup disagree.
        graph = gateway.snapshot()
        if graph is None:
            return DescribeResult(
                table=name, in_scope=False, columns=[], note="No policy snapshot loaded."
            )
        ds = graph.dataset_by_name(name)
        principal = graph.principal(principal_name) or Principal.anonymous()
        if ds is None or not principal.scope.permits(domain=ds.domain, platform=ds.platform):
            return DescribeResult(
                table=name,
                in_scope=False,
                columns=[],
                note="This table is outside your scope; use warehouse_list_tables to see what you can read.",
            )
        columns = [
            ColumnInfo(name=c.name, type=c.data_type, sensitive=bool(c.tags or c.glossary_terms))
            for c in ds.columns
        ]
        return DescribeResult(table=ds.name, in_scope=True, columns=columns)

    return mcp


async def run_server(
    config: AirlockConfig,
    *,
    principal_name: str,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8080,
    health_port: int = 8081,
) -> None:
    """Boot the gateway (fail-fast on no snapshot), start refresh + health, and serve MCP."""
    gateway = Gateway.build(config)
    await gateway.bootstrap()
    refresh_task = asyncio.create_task(gateway.refresh_loop())
    mcp = build_mcp(gateway, principal_name)
    health_server = None

    try:
        if transport == "http":
            _register_http_health(mcp, gateway)
            await mcp.run_streamable_http_async()
        else:
            health_server = start_health_server(host, health_port, gateway.ready)
            await mcp.run_stdio_async()
    finally:
        refresh_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await refresh_task
        if health_server is not None:
            health_server.shutdown()
            health_server.server_close()  # release the port so a quick restart does not collide
        await gateway.aclose()


def _register_http_health(mcp: FastMCP, gateway: Gateway) -> None:
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse

    @mcp.custom_route("/healthz", methods=["GET"])  # type: ignore[untyped-decorator]
    async def healthz(_: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    @mcp.custom_route("/readyz", methods=["GET"])  # type: ignore[untyped-decorator]
    async def readyz(_: Request) -> PlainTextResponse:
        return (
            PlainTextResponse("ready")
            if gateway.ready()
            else PlainTextResponse("not ready", status_code=503)
        )
