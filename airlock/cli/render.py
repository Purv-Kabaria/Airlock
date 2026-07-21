"""rich rendering for envelopes and audit lines. Shared by check, tail, and explain.

The two readers of a decision - the agent and the human at the terminal - see the same facts.
This is the human view: color by outcome, a verdict table, the executed SQL, and a row preview.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

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
    console.print(
        f"[bold {style}]{envelope.status.value.upper()}[/] "
        f"[dim]{envelope.request_id} · {envelope.principal} · {envelope.policy_snapshot or '-'}[/]"
    )

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
