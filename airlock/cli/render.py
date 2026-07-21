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
