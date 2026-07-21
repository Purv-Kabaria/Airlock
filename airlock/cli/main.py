"""airlock CLI. Thin commands over the same runtime the MCP server uses.

Nothing here decides policy; commands load config, compile a snapshot from the live DataHub, and
call the gateway. `check` is a dry run (no execution); `serve` runs the MCP server; `tail`,
`explain`, and `doctor` are the operator surface.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Coroutine, Iterator
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

import airlock.cli._encoding  # noqa: F401  side effect: UTF-8 stdout/stderr, before any Console
from airlock.cli.render import (
    console,
    render_audit_line,
    render_coverage,
    render_envelope,
    render_proposals,
    render_usage,
)
from airlock.config import AirlockConfig, load_config
from airlock.errors import AirlockError, ConfigError, SnapshotUnavailableError
from airlock.policy.coverage import CoverageReport, DatasetGap

app = typer.Typer(
    add_completion=False,
    help="Airlock - the governance gateway between AI agents and your SQL warehouse.",
    no_args_is_help=True,
)
policy_app = typer.Typer(help="Validate and inspect policy.")

# Help panels group commands by the order you actually use them, not by definition order.
_SETUP = "Set up"
_INSPECT = "Query & inspect"
_RUN = "Run the gateway"
_OBSERVE = "Observe & audit"
_MAINTAIN = "Maintain the catalog"

app.add_typer(policy_app, name="policy", rich_help_panel=_INSPECT)

err = Console(stderr=True)

_CONFIG_OPT = typer.Option("airlock.yaml", "--config", "-c", help="Path to airlock.yaml.")


def _show_version(value: bool) -> None:
    if value:
        from airlock import __version__

        console.print(f"airlock {__version__}")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit.", is_eager=True, callback=_show_version
    ),
) -> None:
    """Airlock - policy compiled from DataHub, enforced in-flight, explained to the agent."""


@app.command(rich_help_panel=_SETUP)
def init(
    path: Path = typer.Option("airlock.yaml", "--path", "-p", help="Where to write the config."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Accept defaults without prompting."),
) -> None:
    """Write an airlock.yaml with env-ref secrets. Validates nothing is overwritten silently."""
    if path.exists() and not yes and not typer.confirm(f"{path} exists. Overwrite?"):
        raise typer.Exit(1)
    datahub_url = (
        "http://localhost:8080"
        if yes
        else typer.prompt("DataHub GMS URL", default="http://localhost:8080")
    )
    warehouse_dsn = (
        "./demo/warehouse.duckdb"
        if yes
        else typer.prompt("DuckDB warehouse path", default="./demo/warehouse.duckdb")
    )
    path.write_text(_DEFAULT_CONFIG.format(url=datahub_url, dsn=warehouse_dsn), encoding="utf-8")
    console.print(f"[green]Wrote {path}[/] (secrets stay as ${{...}} env refs, never on disk).")
    _report_reachable(datahub_url, warehouse_dsn)
    console.print("Set env vars for any ${...} refs, then run `airlock doctor` for full checks.")


def _report_reachable(datahub_url: str, warehouse_dsn: str) -> None:
    """Non-blocking connectivity probe so you find a wrong URL/path now, not at first serve."""
    import httpx

    try:
        httpx.get(datahub_url.rstrip("/") + "/config", timeout=3).raise_for_status()
        console.print(f"  [green]ok[/]   DataHub reachable at {datahub_url}")
    except httpx.HTTPError as exc:
        console.print(
            f"  [yellow]warn[/] DataHub not reachable at {datahub_url} ({exc}); "
            "start it, then `airlock doctor`"
        )
    import duckdb

    try:
        conn = duckdb.connect(warehouse_dsn.removeprefix("duckdb:///").removeprefix("duckdb://"))
        conn.execute("SELECT 1")
        conn.close()
        console.print(f"  [green]ok[/]   DuckDB warehouse opens at {warehouse_dsn}")
    except (duckdb.Error, OSError) as exc:
        console.print(f"  [yellow]warn[/] DuckDB warehouse not usable at {warehouse_dsn} ({exc})")


@app.command(rich_help_panel=_INSPECT)
def check(
    sql: str = typer.Argument(..., help="The SQL to evaluate."),
    principal: str = typer.Option("anonymous", "--as", help="Principal to evaluate as."),
    config: Path = _CONFIG_OPT,
    as_json: bool = typer.Option(False, "--json", help="Print the envelope as JSON (for scripts)."),
    offline: bool = typer.Option(
        False, "--offline", help="Use the last cached snapshot instead of recompiling from DataHub."
    ),
) -> None:
    """Dry-run a query: show the full decision and rewritten SQL without executing."""
    cfg = _load(config)
    known = {p.name for p in cfg.principals}
    if principal != "anonymous" and principal not in known:
        err.print(
            f"[yellow]warning:[/] principal {principal!r} is not defined in {config}; "
            f"evaluating as the anonymous (deny-all) principal. Known: {sorted(known) or '[none]'}"
        )

    async def _run() -> None:
        from airlock.gateway import Gateway

        gateway = Gateway.build(cfg)
        try:
            if offline:
                gateway.bootstrap_offline()
            else:
                await gateway.bootstrap()
            envelope = gateway.dry_run(sql, principal)
            if as_json:
                print(envelope.model_dump_json(indent=2))
            else:
                render_envelope(envelope)
        finally:
            await gateway.aclose()

    _run_async(_run())


@app.command(rich_help_panel=_INSPECT)
def coverage(
    config: Path = _CONFIG_OPT,
    as_json: bool = typer.Option(False, "--json", help="Print the report as JSON (for scripts)."),
    fail_under: float | None = typer.Option(
        None,
        "--fail-under",
        help="Exit non-zero if governed-column coverage is below this percentage.",
        min=0.0,
        max=100.0,
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero unless posture is clear (no gaps of any kind)."
    ),
) -> None:
    """Report what this policy can actually enforce, and where the catalog leaves it blind.

    Exits 1 when `--fail-under` or `--strict` is not met, so a pipeline can gate on governance
    posture the same way it gates on test coverage.
    """
    from airlock.policy.compile import compile_snapshot
    from airlock.policy.coverage import measure_coverage

    cfg = _load(config)
    try:
        graph = compile_snapshot(cfg)
    except SnapshotUnavailableError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc

    report = measure_coverage(graph)
    if as_json:
        print(json.dumps(_coverage_payload(report), indent=2))
    else:
        render_coverage(report)

    if fail_under is not None and report.governed_pct < fail_under:
        err.print(
            f"[red]coverage {report.governed_pct:.1f}% is below --fail-under {fail_under:.1f}%[/]"
        )
        raise typer.Exit(1)
    if strict and not report.is_clear:
        err.print(f"[red]posture is {report.grade}; --strict requires clear[/]")
        raise typer.Exit(1)


def _coverage_payload(report: CoverageReport) -> dict[str, Any]:
    return {
        "snapshot_hash": report.snapshot_hash,
        "grade": report.grade,
        "datasets": report.total_datasets,
        "columns": report.total_columns,
        "governed_columns": report.governed_columns,
        "governed_pct": round(report.governed_pct, 2),
        "classified_columns": report.classified_columns,
        "classified_pct": round(report.classified_pct, 2),
        "masked_columns": report.masked_columns,
        "denied_columns": report.denied_columns,
        "suspected_gaps": [
            {
                "subject": g.subject,
                "dataset_urn": g.dataset_urn,
                "column": g.column,
                "data_type": g.data_type,
                "reason": g.reason,
            }
            for g in report.suspected_gaps
        ],
        "dead_rules": list(report.dead_rules),
        "orphan_deprecated": [_gap_payload(g) for g in report.orphan_deprecated],
        "unowned_datasets": [_gap_payload(g) for g in report.unowned_datasets],
        "unreachable_datasets": [_gap_payload(g) for g in report.unreachable_datasets],
    }


def _gap_payload(gap: DatasetGap) -> dict[str, str]:
    return {"name": gap.name, "urn": gap.urn, "detail": gap.detail}


@app.command(rich_help_panel=_MAINTAIN)
def propose(
    config: Path = _CONFIG_OPT,
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be written to DataHub, write nothing."
    ),
) -> None:
    """Propose classifications for suspected-sensitive columns back to DataHub.

    Coverage flags columns whose names read as sensitive but that no rule classifies. This writes
    those findings to each dataset as a structured property, so a steward sees Airlock's suggestion
    in the catalog and can tag the column - the gateway improving the graph it enforces from.
    Idempotent: re-running overwrites the property, and any tagged column drops off the list.
    """
    from airlock.audit.datahub_sink import write_classification_proposals
    from airlock.policy.compile import compile_snapshot
    from airlock.policy.coverage import measure_coverage

    cfg = _load(config)
    try:
        graph = compile_snapshot(cfg)
    except SnapshotUnavailableError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc

    report = measure_coverage(graph)
    render_proposals(report.suspected_gaps, dry_run=dry_run)
    proposals = _proposals_from_gaps(report.suspected_gaps)
    if dry_run or not proposals:
        return
    try:
        written = write_classification_proposals(cfg, proposals)
    except Exception as exc:  # narrow enough: any DataHub write failure is reported, not raised
        err.print(f"[red]Could not write proposals to DataHub: {exc}[/]")
        raise typer.Exit(2) from exc
    console.print(
        f"[green]Wrote suspected-sensitive proposals to {written} dataset(s) in DataHub "
        f"(structured property airlock.suspectedSensitive).[/]"
    )


def _proposals_from_gaps(gaps: tuple[Any, ...]) -> dict[str, tuple[str, ...]]:
    """Group suspected gaps into one structured-property value list per dataset URN."""
    by_dataset: dict[str, list[str]] = {}
    for gap in gaps:
        by_dataset.setdefault(gap.dataset_urn, []).append(f"{gap.column}: looks like {gap.reason}")
    return {urn: tuple(values) for urn, values in by_dataset.items()}


@app.command(rich_help_panel=_OBSERVE)
def usage(
    config: Path = _CONFIG_OPT,
    as_json: bool = typer.Option(False, "--json", help="Print the activity as JSON (for scripts)."),
) -> None:
    """Show the agent read activity DataHub holds, read back out of the catalog.

    Airlock is the only door agents use to reach the warehouse, so it is the only source of this:
    per-dataset query counts, per-column read counts, and a per-agent breakdown, written back as
    DataHub's native datasetUsageStatistics and read straight from the timeseries store here (not the
    GraphQL aggregation, which GMS caches for minutes). Compiles the snapshot only to name datasets.
    """
    from airlock.audit.datahub_sink import read_usage
    from airlock.policy.compile import compile_snapshot

    cfg = _load(config)
    try:
        graph = compile_snapshot(cfg)
    except SnapshotUnavailableError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc

    try:
        activity = read_usage(cfg, {urn: ds.name for urn, ds in graph.datasets.items()})
    except Exception as exc:  # narrow enough: any DataHub read failure is reported, not raised
        err.print(f"[red]Could not read usage from DataHub: {exc}[/]")
        raise typer.Exit(2) from exc

    if as_json:
        print(
            json.dumps(
                [
                    {
                        "dataset": u.name,
                        "queries": u.queries,
                        "principals": [{"name": n, "count": c} for n, c in u.principals],
                        "columns": [{"column": col, "count": c} for col, c in u.columns],
                    }
                    for u in activity
                ],
                indent=2,
            )
        )
    else:
        render_usage(activity)


@app.command(rich_help_panel=_SETUP)
def version() -> None:
    """Print Airlock and key dependency versions."""
    from importlib.metadata import version as pkg_version

    from airlock import __version__

    console.print(f"airlock {__version__}  (sqlglot {pkg_version('sqlglot')})")


@app.command(rich_help_panel=_RUN)
def serve(
    config: Path = _CONFIG_OPT,
    principal: str | None = typer.Option(
        None, "--principal", help="Principal this process serves as."
    ),
    key_env: str | None = typer.Option(
        None, "--key-env", help="Env var holding the principal key."
    ),
    transport: str = typer.Option("stdio", "--transport", help="stdio | http."),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port", help="MCP port (http transport)."),
    health_port: int = typer.Option(8088, "--health-port", help="Health port (stdio transport)."),
) -> None:
    """Run the MCP server. Fails fast if no policy snapshot can be compiled from DataHub."""
    from airlock.mcp.auth import resolve_principal_name
    from airlock.mcp.server import run_server

    cfg = _load(config)
    key = os.environ.get(key_env) if key_env else None
    principal_name = resolve_principal_name(cfg, principal=principal, key=key)
    err.print(f"[bold]airlock[/] serving as [cyan]{principal_name}[/] over {transport}")
    try:
        asyncio.run(
            run_server(
                cfg,
                principal_name=principal_name,
                transport=transport,
                host=host,
                port=port,
                health_port=health_port,
            )
        )
    except SnapshotUnavailableError as exc:
        err.print(f"[red]serve refused to start:[/] {exc}")
        raise typer.Exit(2) from exc
    except KeyboardInterrupt:
        err.print("\n[dim]shutting down[/]")


@app.command(rich_help_panel=_OBSERVE)
def tail(config: Path = _CONFIG_OPT) -> None:
    """Follow the decision stream, colorized, as queries arrive."""
    from airlock.audit.record import AuditRecord

    cfg = _load(config)
    log_path = cfg.audit.jsonl
    console.print(f"[dim]tailing {log_path} (Ctrl+C to stop)[/]")
    try:
        for line in _follow(log_path):
            try:
                render_audit_line(AuditRecord.model_validate_json(line))
            except ValueError:
                continue
    except KeyboardInterrupt:
        pass


@app.command(rich_help_panel=_OBSERVE)
def explain(
    request_id: str = typer.Argument(..., help="The request_id to replay."),
    config: Path = _CONFIG_OPT,
) -> None:
    """Replay a past decision from the audit log."""
    cfg = _load(config)
    record = _find_record(cfg.audit.jsonl, request_id)
    if record is None:
        err.print(f"[red]no audit record for {request_id}[/]")
        raise typer.Exit(1)
    table = Table(show_header=False, box=None)
    for k, v in record.items():
        table.add_row(f"[bold]{k}[/]", json.dumps(v) if not isinstance(v, str) else v)
    console.print(table)


@app.command(rich_help_panel=_MAINTAIN)
def refresh(config: Path = _CONFIG_OPT) -> None:
    """Compile a fresh policy snapshot from DataHub and report it."""
    from airlock.policy.compile import compile_snapshot

    cfg = _load(config)
    try:
        graph = compile_snapshot(cfg)
    except SnapshotUnavailableError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc
    console.print(
        f"[green]compiled[/] {graph.content_hash} - {len(graph.datasets)} datasets, {len(graph.rules)} rules"
    )


@app.command(rich_help_panel=_SETUP)
def doctor(config: Path = typer.Option("airlock.yaml", "--config", "-c")) -> None:
    """Verify the environment item by item and name the fix for anything broken."""
    from airlock.cli.doctor import run_doctor

    ok = run_doctor(config)
    raise typer.Exit(0 if ok else 1)


@policy_app.command("lint")
def policy_lint(config: Path = _CONFIG_OPT) -> None:
    """Validate config and flag ambiguous rules before they surprise anyone at runtime."""
    from airlock.policy.rules import tie_conflicts

    cfg = _load(config)
    rules = cfg.compiled_rules()
    conflicts = tie_conflicts(list(rules))
    if conflicts:
        for a, b in conflicts:
            err.print(
                f"[red]ambiguous:[/] rules {a.id!r} and {b.id!r} tie on precedence with different actions"
            )
        raise typer.Exit(1)
    console.print(
        f"[green]ok[/] - {len(rules)} rules, {len(cfg.principals)} principals, no conflicts"
    )


@policy_app.command("diff")
def policy_diff(
    other: Path = typer.Argument(..., help="Another airlock.yaml to compare against."),
    config: Path = _CONFIG_OPT,
) -> None:
    """Show which rules a config change would add, remove, or alter."""
    base = {r.id: r for r in _load(config).compiled_rules()}
    incoming = {r.id: r for r in _load(other).compiled_rules()}
    for rid in sorted(set(base) | set(incoming)):
        if rid not in incoming:
            console.print(f"[red]- {rid}[/]")
        elif rid not in base:
            console.print(f"[green]+ {rid}[/]")
        elif base[rid] != incoming[rid]:
            console.print(f"[yellow]~ {rid}[/]")


# -- helpers -------------------------------------------------------------------------


def _load(config: Path) -> AirlockConfig:
    _autoload_env(config)
    try:
        return load_config(config)
    except ConfigError as exc:
        err.print(f"[red]config error:[/] {exc}")
        raise typer.Exit(2) from exc


def _autoload_env(config: Path) -> None:
    """Load `.env` (then `.env.example`) from the config's directory and the CWD, without overriding
    anything already set. This makes the demo commands work in a fresh shell right after up.py, so a
    judge can copy-paste `airlock check ... -c demo/airlock.yaml` and it just runs."""
    seen: set[Path] = set()
    for base in (config.resolve().parent, Path.cwd()):
        for name in (".env", ".env.example"):
            path = base / name
            if path in seen or not path.exists():
                continue
            seen.add(path)
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


def _run_async(coro: Coroutine[Any, Any, None]) -> None:
    try:
        asyncio.run(coro)
    except (AirlockError, SnapshotUnavailableError) as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from exc


def _follow(path: Path, poll: float = 0.25) -> Iterator[str]:
    while not path.exists():
        time.sleep(poll)
    with path.open(encoding="utf-8") as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(poll)


def _find_record(path: Path, request_id: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    found = None
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("request_id") == request_id:
                found = rec
    return found


_DEFAULT_CONFIG = """\
# airlock.yaml - checked into Git; secrets via env refs only
datahub:
  url: {url}
  token: ${{DATAHUB_GMS_TOKEN}}
  snapshot:
    refresh_interval: 30s
    max_staleness: 24h
    stale_policy: fail_closed

warehouse:
  kind: duckdb
  dsn: {dsn}
  defaults: {{ row_limit: 10000, statement_timeout: 30s }}

enforcement:
  mode: enforce
  unknown_tables: deny
  statement_classes: [select]
  predicate_policy: deny
  substitution: rewrite

rules:
  - id: pii-default
    match: {{ tag: PII }}
    action: {{ mask: auto }}
  - id: pii-hard-deny
    match: {{ glossary_term: Classification.SSN }}
    action: deny
  - id: deprecated-redirect
    match: {{ lifecycle: DEPRECATED }}
    action: substitute_certified

principals:
  - name: growth-agent
    key: ${{AIRLOCK_KEY_GROWTH}}
    scopes: {{ domains: [Marketing] }}
  - name: finance-agent
    key: ${{AIRLOCK_KEY_FINANCE}}
    scopes: {{ domains: [Finance] }}
    overrides: {{ row_limit: 100000 }}

audit:
  jsonl: ./audit/decisions.jsonl
  datahub_writeback: true
  otel: {{ enabled: false }}
"""


if __name__ == "__main__":
    app()
