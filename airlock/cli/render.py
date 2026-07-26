"""rich rendering for envelopes and audit lines. Shared by check, tail, and explain.

The two readers of a decision - the agent and the human at the terminal - see the same facts.
This is the human view: color by outcome, a verdict table, the executed SQL, and a row preview.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from airlock.audit.datahub_sink import DatasetUsage
from airlock.audit.record import AuditRecord
from airlock.engine.verdicts import Envelope, EnvelopeStatus
from airlock.policy.coverage import CoverageReport, DatasetGap, SuspectedGap

console = Console()

_STATUS_STYLE = {
    EnvelopeStatus.EXECUTED: "green",
    EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS: "yellow",
    EnvelopeStatus.DENIED: "red",
    EnvelopeStatus.ERROR: "red",
}

_ACTION_STYLE = {
    "mask": "yellow",
    "deny_column": "red",
    "deny_statement": "red",
    "scope_deny": "red",
    "substitute": "cyan",
    "limit": "blue",
    "note": "dim",
}


def render_envelope(envelope: Envelope) -> None:
    style = _STATUS_STYLE.get(envelope.status, "white")
    snapshot = _short_hash(envelope.policy_snapshot) if envelope.policy_snapshot else "-"
    console.print(
        f"[bold {style}]{envelope.status.value.upper()}[/] "
        f"[dim]{envelope.request_id} · {envelope.principal} · {snapshot}[/]"
    )
    summary = _summarize(
        [(v.action, v.subject) for v in envelope.verdicts], envelope.status
    )
    if summary:
        console.print(summary)

    if envelope.verdicts:
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("code", style="bold")
        table.add_column("action")
        table.add_column("subject", style="cyan")
        table.add_column("reason / hint")
        for v in envelope.verdicts:
            reason = v.reason + (f"\n[dim]-> {v.hint}[/]" if v.hint else "")
            table.add_row(
                str(v.code),
                f"[{_ACTION_STYLE.get(v.action, 'white')}]{v.action}[/]",
                v.subject,
                reason,
            )
        console.print(table)

    if envelope.executed_sql:
        console.print("[dim]executed_sql:[/]")
        console.print(Syntax(envelope.executed_sql, "sql", theme="ansi_dark", word_wrap=True))

    if envelope.rows is not None:
        _render_rows(envelope.columns or [], envelope.rows, envelope.truncated)


# What happened, in the words a stranger reads first. Derived only from the verdicts the machine
# also reads (taste rule 1: two readers, one set of facts), so the scan line can never drift from
# the table below it. The row-limit and note verdicts are left out on purpose: they are always-on
# noise, not a change the reader has to reason about.
_CHANGE = (("substitute", "table", "redirected"), ("mask", "column", "masked"),
           ("deny_column", "column", "removed"))


def _summarize(pairs: list[tuple[str, str]], status: EnvelopeStatus) -> str | None:
    """One plain-language line of what happened, or None when the status line already says it."""
    if status is EnvelopeStatus.ERROR:
        return None  # the single error verdict's reason is the whole message
    if status is EnvelopeStatus.DENIED:
        blockers = [subj for act, subj in pairs if act in ("deny_statement", "scope_deny")]
        if not blockers:
            return None
        more = f" (+{len(blockers) - 1} more)" if len(blockers) > 1 else ""
        return f"[bold]Blocked on {blockers[0]}{more}.[/]"
    counts = Counter(act for act, _ in pairs)
    parts = [
        f"{counts[act]} {noun}{'' if counts[act] == 1 else 's'} {verb}"
        for act, noun, verb in _CHANGE
        if counts[act]
    ]
    return " · ".join(parts) + "." if parts else "[dim]Nothing hidden or removed.[/]"


def _render_rows(columns: list[str], rows: list[dict[str, Any]], truncated: bool) -> None:
    if not rows:
        console.print("[dim](no rows)[/]")
        return
    table = Table(show_header=True, header_style="bold magenta")
    for col in columns:
        table.add_column(col)
    for row in rows[:20]:
        table.add_row(*[_cell(row.get(c)) for c in columns])
    console.print(table)
    suffix = " [red](truncated)[/]" if truncated else ""
    console.print(f"[dim]{len(rows)} row(s) shown{suffix}[/]")


_GRADE_STYLE = {"clear": "green", "gaps": "yellow", "at-risk": "red"}


def render_coverage(report: CoverageReport) -> None:
    """Posture first, then only the sections that have something to say.

    Ordered by what a reader must act on: blind spots before statistics. An all-clear catalog
    prints four lines, so this stays readable as a habit rather than a once-a-quarter audit.
    """
    console.print(
        f"[bold]governance posture[/] [dim]{_short_hash(report.snapshot_hash)} · "
        f"{report.total_datasets} datasets · {report.total_columns} columns[/]"
    )
    style = _GRADE_STYLE.get(report.grade, "white")
    console.print(
        f"  [bold {style}]{report.grade}[/]  {_bar(report.governed_pct)} "
        f"governed {report.governed_columns}/{report.total_columns} ({report.governed_pct:.0f}%)"
    )
    console.print(
        f"  [dim]masked {report.masked_columns} · denied {report.denied_columns} · "
        f"classified {report.classified_columns}/{report.total_columns} "
        f"({report.classified_pct:.0f}%)[/]"
    )

    if report.suspected_gaps:
        console.print(
            f"\n[bold red]{len(report.suspected_gaps)} column(s) read as sensitive "
            "but no rule governs them[/]"
        )
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("subject", style="cyan")
        table.add_column("type", style="dim")
        table.add_column("looks like")
        for gap in report.suspected_gaps:
            table.add_row(gap.subject, gap.data_type, gap.reason)
        console.print(table)
        console.print(
            "[dim]-> classify these in DataHub, then `airlock refresh`. Airlock enforces what the "
            "catalog states and never guesses, so today these are served in the clear.[/]"
        )

    _render_gap_section("rules that match nothing in this catalog", report.dead_rules, "yellow")
    _render_dataset_gaps("deprecated with no certified substitute", report.orphan_deprecated)
    _render_dataset_gaps("no owner in DataHub", report.unowned_datasets)
    _render_dataset_gaps("unreachable by every principal", report.unreachable_datasets)


def _render_gap_section(title: str, items: tuple[str, ...], style: str) -> None:
    if not items:
        return
    console.print(f"\n[bold {style}]{title}[/]")
    for item in items:
        console.print(f"  {item}")


def _render_dataset_gaps(title: str, gaps: tuple[DatasetGap, ...]) -> None:
    if not gaps:
        return
    console.print(f"\n[bold yellow]{title}[/]")
    for gap in gaps:
        # The detail repeats the heading for single-cause sections; only print what it adds.
        suffix = f" [dim]{gap.detail}[/]" if gap.detail != title else ""
        console.print(f"  [cyan]{gap.name}[/]{suffix}")


def render_proposals(gaps: tuple[SuspectedGap, ...], *, dry_run: bool) -> None:
    """Show the suspected-sensitive columns Airlock will propose back to DataHub."""
    if not gaps:
        console.print(
            "[green]No suspected-sensitive columns without classification. Nothing to propose.[/]"
        )
        return
    verb = "Would propose" if dry_run else "Proposing"
    table = Table(title=f"{verb} {len(gaps)} classification(s) to DataHub", title_justify="left")
    table.add_column("dataset", style="cyan")
    table.add_column("column", style="bold")
    table.add_column("looks like", style="yellow")
    for gap in gaps:
        table.add_row(gap.dataset_name, gap.column, gap.reason)
    console.print(table)


def render_usage(usage: list[DatasetUsage]) -> None:
    """Show the agent read activity DataHub holds, read back out of the catalog."""
    if not usage:
        console.print(
            "[yellow]DataHub has no recorded agent activity yet. Run some queries through the "
            "gateway, then re-run this.[/]"
        )
        return
    table = Table(
        title="Agent read activity, as recorded in DataHub (datasetUsageStatistics)",
        title_justify="left",
    )
    table.add_column("dataset", style="cyan")
    table.add_column("queries", justify="right", style="bold")
    table.add_column("agents")
    table.add_column("columns read")
    for row in usage:
        agents = ", ".join(f"{name} ({count})" for name, count in row.principals) or "-"
        columns = ", ".join(f"{col} ({count})" for col, count in row.columns) or "-"
        table.add_row(row.name, str(row.queries), agents, columns)
    console.print(table)


def render_verify(kind: str, dialect: str, results: list[Any], *, as_json: bool) -> bool:
    """Show whether each masking strategy survived the round trip to this warehouse.

    Returns True when every probe passed, so the command can exit non-zero for CI. The rendered SQL
    is shown for failures only: on success it is noise, and on failure it is the first thing anyone
    debugging a dialect will want.
    """
    if as_json:
        import json

        print(
            json.dumps(
                {
                    "warehouse": kind,
                    "dialect": dialect,
                    "ok": all(r.ok for r in results),
                    "probes": [
                        {"strategy": r.strategy, "ok": r.ok, "detail": r.detail, "sql": r.sql}
                        for r in results
                    ],
                },
                indent=2,
            )
        )
        return all(r.ok for r in results)

    console.print(f"[bold]masking check[/] [dim]{kind} · rendering as the {dialect} dialect[/]")
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("")
    table.add_column("strategy", style="cyan")
    table.add_column("result")
    for r in results:
        mark = "[green]ok[/]" if r.ok else "[red]FAIL[/]"
        table.add_row(mark, r.strategy, r.detail if r.ok else f"[red]{r.detail}[/]")
    console.print(table)

    failed = [r for r in results if not r.ok]
    if not failed:
        console.print(
            f"[green]every masking strategy renders and executes on {kind}.[/] "
            "[dim]Real columns mask through the same templates and renderer.[/]"
        )
        return True
    for r in failed:
        console.print(f"\n[dim]{r.strategy} sent:[/]")
        console.print(Syntax(r.sql, "sql", theme="ansi_dark", word_wrap=True))
    console.print(
        f"\n[red]{len(failed)} strategy/strategies do not work on {kind}.[/] "
        "[dim]Drop them from airlock.yaml's rules, or report the dialect gap - the SQL above is "
        "what the warehouse rejected.[/]"
    )
    return False


def _bar(pct: float, width: int = 20) -> str:
    filled = round(width * pct / 100)
    return f"[green]{'=' * filled}[/][dim]{'-' * (width - filled)}[/]"


def _short_hash(content_hash: str) -> str:
    """Snapshot hashes are 71 chars and would wrap the header. The prefix is enough to correlate
    a report with an envelope's policy_snapshot at a glance; --json carries the full value."""
    algo, _, digest = content_hash.partition(":")
    return f"{algo}:{digest[:12]}" if digest else content_hash


def render_audit_line(record: AuditRecord) -> None:
    style = "red" if record.denied else ("yellow" if record.verdicts else "green")
    codes = ",".join(v.code for v in record.verdicts) or "-"
    console.print(
        f"[dim]{record.ts}[/] [bold {style}]{record.status:>28}[/] "
        f"{record.principal:<16} verdicts=[{codes}] "
        f"rows={record.row_count if record.row_count is not None else '-'} "
        f"lat={record.latency_ms:.1f}ms {record.request_id}"
    )


def _cell(value: Any) -> str:
    if value is None:
        return "[dim]NULL[/]"
    return str(value)


def render_replay(record: dict[str, Any]) -> None:
    """The human view of one archived decision, shaped like `check` so a replay reads the same as
    the live decision did.

    The audit line stores each verdict's code, action, and subject but not its prose - the reason
    sentence is rebuilt per request and would triple the size of every line. The code is the stable
    identity, so the meaning comes from the TITLES table instead of the record.
    """
    status = str(record.get("status", "unknown"))
    known = _status_enum(status)
    style = _STATUS_STYLE.get(known, "white") if known is not None else "white"
    snapshot = record.get("snapshot_hash")
    console.print(
        f"[bold {style}]{status.upper()}[/] [dim]{record.get('request_id', '-')} · "
        f"{record.get('principal', '-')} · {_short_hash(snapshot) if snapshot else '-'} · "
        f"{record.get('ts', '-')}[/]"
    )

    verdicts = record.get("verdicts") or []
    if known is not None:
        summary = _summarize(
            [(str(v.get("action", "")), str(v.get("subject", ""))) for v in verdicts], known
        )
        if summary:
            console.print(summary)
    if verdicts:
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("code", style="bold")
        table.add_column("action")
        table.add_column("subject", style="cyan")
        table.add_column("meaning")
        for v in verdicts:
            action = str(v.get("action", "-"))
            table.add_row(
                str(v.get("code", "-")),
                f"[{_ACTION_STYLE.get(action, 'white')}]{action}[/]",
                str(v.get("subject", "-")),
                _code_title(str(v.get("code", ""))),
            )
        console.print(table)

    for label in ("original_sql", "executed_sql"):
        sql = record.get(label)
        if sql:
            console.print(f"[dim]{label}:[/]")
            console.print(Syntax(str(sql), "sql", theme="ansi_dark", word_wrap=True))

    console.print(f"[dim]{_replay_footer(record)}[/]")


def _replay_footer(record: dict[str, Any]) -> str:
    rows = record.get("row_count")
    parts = [f"{rows} row(s)" if rows is not None else "no rows"]
    if record.get("truncated"):
        parts.append("truncated")
    latency = record.get("latency_ms")
    if latency is not None:
        parts.append(f"{float(latency):.1f}ms")
    if record.get("warehouse"):
        parts.append(str(record["warehouse"]))
    if record.get("coalesced"):
        parts.append("coalesced with an identical in-flight query")
    for urn in record.get("dataset_urns") or []:
        parts.append(str(urn))
    return " · ".join(parts)


def _code_title(code: str) -> str:
    from airlock.engine.verdicts import TITLES, ReasonCode

    try:
        return TITLES.get(ReasonCode(code), "")
    except ValueError:  # a code from an older snapshot that this build no longer allocates
        return ""


def _status_enum(status: str) -> EnvelopeStatus | None:
    try:
        return EnvelopeStatus(status)
    except ValueError:
        return None
