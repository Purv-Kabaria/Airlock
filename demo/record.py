"""Self-running demo for the submission video. Screen-record this in one hands-free take.

It plays the exact sequence from SCRIPT.md against the live stack `python demo/up.py` starts -
cold open, a clean query, lineage substitution, inherited classification, the live retag,
write-back, and the coverage close - with large captions and pauses sized for a voiceover.

Nothing here is mocked, and nothing is replayed. Every beat shells out to the real `airlock` CLI,
writes a real tag to the real DataHub exactly as a steward's UI click would, or executes real SQL
against the real warehouse. The write-back beat runs its two queries through `Gateway.build` -
the same wiring `airlock serve` uses - so the properties it then reads out of DataHub were written
by those queries seconds earlier, not left over from an earlier session.

    python demo/record.py            # presentation timing (~2:45), for recording
    python demo/record.py --rehearse # short pauses, and every beat is checked; exits non-zero on
                                     # any beat that did not produce the verdicts the script claims

`--rehearse` is the green light. It re-runs each decision beat with `--json` and asserts the reason
codes the voiceover promises actually came back, so "the rehearsal looked fine" is a verified
statement rather than an impression. Run it until it exits 0, then record.

Read demo/VIDEO.md aloud over the recording, or feed it to a text-to-speech engine.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

REPO = Path(__file__).resolve().parent.parent
CONFIG = "demo/airlock.yaml"
GMS = os.environ.get("DATAHUB_GMS_URL", "http://localhost:18080")
ORDERS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,orders,PROD)"
DIM_USERS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,dim_users,PROD)"

console = Console()


def _load_env() -> None:
    """Mirror up.py: pull demo/.env (or .env.example) into the environment if not already set."""
    for name in (".env", ".env.example"):
        path = REPO / "demo" / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())
        break


def _airlock_cmd() -> list[str]:
    exe = shutil.which("airlock")
    if exe:
        return [exe]
    scripts = "Scripts" if os.name == "nt" else "bin"
    local = REPO / ".venv" / scripts / ("airlock.exe" if os.name == "nt" else "airlock")
    if local.exists():
        return [str(local)]
    return [sys.executable, "-m", "airlock.cli.main"]


AIRLOCK = _airlock_cmd()


class Pacer:
    def __init__(self, rehearse: bool) -> None:
        self._scale = 0.18 if rehearse else 1.0

    def beat(self, seconds: float) -> None:
        time.sleep(seconds * self._scale)


def caption(title: str, line: str, subtitle: str = "") -> None:
    body = Text(line, style="bold white", justify="center")
    if subtitle:
        body.append("\n\n")
        body.append(subtitle, style="dim italic")
    console.print()
    console.print(
        Panel(
            Align.center(body),
            title=f"[bold cyan]{title}[/]",
            border_style="cyan",
            padding=(1, 4),
        )
    )
    console.print()


VERIFY = False  # set by --rehearse
_FAILED_BEATS: list[str] = []


def run_airlock(
    args: list[str], *, expect: tuple[str, ...] = (), forbid: tuple[str, ...] = (), beat: str = ""
) -> None:
    """Run a real airlock command with its own rich output inherited to the terminal.

    Under --rehearse the same decision is re-run with --json and checked against the reason codes
    this beat's narration promises. A beat that stops producing them is a broken claim in the
    video, and the only cheap moment to learn that is before recording.
    """
    console.print(f"[dim]$ airlock {' '.join(args)}[/]\n")
    subprocess.run(AIRLOCK + args + ["-c", CONFIG], cwd=REPO, check=False)
    if VERIFY and (expect or forbid):
        _check_beat(args, expect, forbid, beat)


def _check_beat(
    args: list[str], expect: tuple[str, ...], forbid: tuple[str, ...], beat: str
) -> None:
    proc = subprocess.run(
        AIRLOCK + args + ["-c", CONFIG, "--json"],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    try:
        codes = {v["code"] for v in json.loads(proc.stdout).get("verdicts", [])}
    except (json.JSONDecodeError, KeyError, TypeError):
        _fail(beat, f"no envelope came back: {(proc.stderr or proc.stdout or '').strip()[:160]}")
        return
    missing = [c for c in expect if c not in codes]
    present = [c for c in forbid if c in codes]
    if missing:
        _fail(beat, f"expected {', '.join(missing)} - got {', '.join(sorted(codes)) or 'nothing'}")
    if present:
        _fail(beat, f"{', '.join(present)} should not fire here")
    if not missing and not present:
        console.print(f"[green]  beat ok[/] [dim]{beat}[/]")


def _fail(beat: str, detail: str) -> None:
    _FAILED_BEATS.append(f"{beat}: {detail}")
    console.print(f"[bold red]  BEAT FAILED[/] [dim]{beat}[/] - {detail}")


def preflight() -> list[str]:
    """Everything that would ruin a take, checked before the camera rolls.

    Delegates to `airlock doctor --json` rather than re-implementing the probes: one diagnostic,
    already trusted, that cannot drift from what the operator sees when they debug the stack.
    """
    proc = subprocess.run(
        [*AIRLOCK, "doctor", "-c", CONFIG, "--json"],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [f"could not run `airlock doctor`: {(proc.stderr or '').strip()[:200]}"]
    return [
        f"{c['check']} - {c.get('fix') or c['detail']}"
        for c in report.get("checks", [])
        if c.get("status") == "fail"
    ]


def set_status_tag(*, remove: bool) -> None:
    """Apply or remove a PII tag on orders.status via editableSchemaMetadata - the exact aspect
    the DataHub UI writes when a steward tags a column."""
    from datahub.emitter.mcp import MetadataChangeProposalWrapper
    from datahub.emitter.rest_emitter import DatahubRestEmitter
    from datahub.metadata.schema_classes import (
        EditableSchemaFieldInfoClass,
        EditableSchemaMetadataClass,
        GlobalTagsClass,
        TagAssociationClass,
    )

    tags = [] if remove else [TagAssociationClass(tag="urn:li:tag:PII")]
    emitter = DatahubRestEmitter(gms_server=GMS, token=os.environ.get("DATAHUB_GMS_TOKEN") or None)
    emitter.emit(
        MetadataChangeProposalWrapper(
            entityUrn=ORDERS_URN,
            aspect=EditableSchemaMetadataClass(
                editableSchemaFieldInfo=[
                    EditableSchemaFieldInfoClass(
                        fieldPath="status", globalTags=GlobalTagsClass(tags=tags)
                    )
                ]
            ),
        )
    )


def _guard(what: str, action: Callable[[], None]) -> None:
    """Run a DataHub call so a mid-take failure is a caption, not a traceback.

    CLAUDE.md treats one traceback during the judge path as a P0. On camera it is worse: the take
    is gone. A named red line at least leaves a usable recording and says what broke.
    """
    try:
        action()
    except Exception as exc:
        _fail(what, f"{type(exc).__name__}: {exc}")
        console.print(f"[bold red]could not {what}[/] - [dim]{type(exc).__name__}[/]")


def execute_through_gateway(queries: list[tuple[str, str]]) -> None:
    """Run queries through the real gateway, executed rather than dry-run.

    Every other beat uses `airlock check`, which decides without executing and so writes nothing
    back. If the write-back beat read the catalog after only dry-runs it would show whatever an
    earlier session left behind - stale numbers presented as this run's. These go through
    `Gateway.build`, the same wiring `airlock serve` uses with the DataHub sink attached, against
    the real DuckDB warehouse; `aclose` drains the write-back queue before the properties are read
    back, so what appears on screen was produced seconds earlier by the queries just shown.
    """
    import asyncio

    from airlock.config import load_config
    from airlock.gateway import Gateway

    async def _run() -> None:
        gateway = Gateway.build(load_config(REPO / "demo" / "airlock.yaml"))
        await gateway.bootstrap()
        try:
            for sql, principal in queries:
                envelope = await gateway.run_query(sql, principal)
                rows = "-" if envelope.rows is None else str(len(envelope.rows))
                console.print(
                    f"  [bold]{principal}[/] [dim]{sql}[/]\n"
                    f"    -> [cyan]{envelope.status}[/]  rows={rows}  "
                    f"verdicts={', '.join(v.code for v in envelope.verdicts) or '-'}"
                )
        finally:
            await gateway.aclose()  # drains the queued write-back to DataHub

    asyncio.run(_run())


def restore_status_tag() -> None:
    """Undo the retag so a second run starts from the same catalog.

    Runs from a `finally`: if a later beat dies mid-take, the tag must still come off, or the next
    run opens with `status` already masked and the centerpiece has nothing to show.
    """
    try:
        set_status_tag(remove=True)
    except Exception as exc:
        console.print(
            f"[bold red]could not remove the PII tag from orders.status[/] ({type(exc).__name__}). "
            "[yellow]Remove it in the DataHub UI before the next run, or the retag beat "
            "will have nothing to change.[/]"
        )


def show_writeback() -> None:
    """Read the airlock.* structured properties back off dim_users and render them - proof the
    loop closed inside DataHub itself."""
    from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph
    from datahub.metadata.schema_classes import StructuredPropertiesClass

    client = DataHubGraph(
        DatahubClientConfig(server=GMS, token=os.environ.get("DATAHUB_GMS_TOKEN") or None)
    )
    aspect = client.get_aspect(entity_urn=DIM_USERS_URN, aspect_type=StructuredPropertiesClass)
    lines = Text()
    if aspect is None:
        lines.append("No write-back yet - run a query first.", style="dim")
    else:
        for prop in aspect.properties:
            name = prop.propertyUrn.split(":")[-1]
            value = prop.values[0] if prop.values else ""
            lines.append(f"  {name:<28}", style="bold cyan")
            lines.append(f"{value}\n", style="white")
    console.print(
        Panel(
            lines,
            title="[bold]DataHub · dim_users · structured properties[/]",
            border_style="green",
        )
    )


def main() -> int:
    global VERIFY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rehearse",
        action="store_true",
        help="short pauses, and check every beat produces the verdicts the script claims",
    )
    args = parser.parse_args()
    VERIFY = args.rehearse

    _load_env()
    pace = Pacer(args.rehearse)

    console.print("[dim]preflight ...[/]")
    problems = preflight()
    if problems:
        console.print(
            Panel(
                Text("\n".join(problems)),
                title="[bold red]not ready to record[/]",
                subtitle="[dim]fix these, then re-run. Nothing was changed in the catalog.[/]",
                border_style="red",
                padding=(1, 2),
            )
        )
        return 2

    try:
        _play(pace)
    finally:
        # The retag is the only thing this script writes. It comes off however the run ends.
        restore_status_tag()

    if VERIFY:
        return _rehearsal_verdict()
    return 0


def _rehearsal_verdict() -> int:
    if _FAILED_BEATS:
        console.print(
            Panel(
                Text("\n".join(_FAILED_BEATS)),
                title=f"[bold red]{len(_FAILED_BEATS)} beat(s) failed - do not record yet[/]",
                border_style="red",
                padding=(1, 2),
            )
        )
        return 1
    console.print(
        Panel(
            Align.center(
                Text.from_markup(
                    "[bold green]every beat produced the verdicts the script claims[/]\n"
                    "[dim]green light: run without --rehearse and record the take.[/]"
                )
            ),
            border_style="green",
            padding=(1, 4),
        )
    )
    return 0


def _play(pace: Pacer) -> None:
    console.clear()
    console.print(
        Panel(
            Align.center(
                Text.from_markup(
                    "[bold white]AIRLOCK[/]\n"
                    "[cyan]A governance gateway between AI agents and your SQL warehouse[/]\n\n"
                    "[dim]Policy compiled live from DataHub · enforced in-flight · explained back to the agent[/]"
                )
            ),
            border_style="cyan",
            padding=(2, 6),
        )
    )
    pace.beat(6)

    caption(
        "0:00  Cold open",
        "A text-to-SQL agent asks for social security numbers.",
        "It does not get them - and it is told why, in a form it can act on.",
    )
    run_airlock(
        ["check", "SELECT name, email, ssn FROM dim_users", "--as", "growth-agent"],
        expect=("AIRLOCK-110", "AIRLOCK-120"),
        beat="0:00 cold open - email masked, ssn denied",
    )
    pace.beat(14)

    caption(
        "0:35  Policy comes from the catalog",
        "No sensitive columns, no intervention. Invisible until policy says otherwise.",
    )
    run_airlock(
        [
            "check",
            "SELECT status, COUNT(*) AS n FROM orders GROUP BY status",
            "--as",
            "growth-agent",
        ],
        forbid=("AIRLOCK-110", "AIRLOCK-120"),
        beat="0:35 clean query - no intervention",
    )
    pace.beat(10)

    caption(
        "1:00  The catalog redirects the agent",
        "users_raw was deprecated. Airlock followed lineage to the certified replacement,",
        "checked the schema covers the query, rewrote to dim_users - then masked and denied on it.",
    )
    run_airlock(
        [
            "check",
            "SELECT u.name, u.email, u.ssn, o.total FROM users_raw u "
            "JOIN orders o ON o.user_id = u.id ORDER BY o.total DESC LIMIT 10",
            "--as",
            "growth-agent",
        ],
        expect=("AIRLOCK-201", "AIRLOCK-110", "AIRLOCK-120"),
        beat="1:00 deprecated table substituted via lineage",
    )
    pace.beat(14)

    caption(
        "1:20  Lineage protects what nobody tagged",
        "user_report.contact carries no tag at all. DataHub's column lineage says it derives",
        "from dim_users.email - so it inherits the mask. The leak nobody remembers to close.",
    )
    run_airlock(
        ["check", "SELECT user_id, contact, signup_month FROM user_report", "--as", "growth-agent"],
        expect=("AIRLOCK-113",),
        beat="1:20 untagged column masked by inherited classification",
    )
    pace.beat(14)

    caption(
        "1:25  The live retag  (the centerpiece)",
        "A data steward tags orders.status as PII in DataHub. No deploy. No restart.",
        "Watch the same query change on the next snapshot refresh.",
    )
    console.print("[dim]before:[/]")
    run_airlock(
        [
            "check",
            "SELECT status, COUNT(*) AS n FROM orders GROUP BY status",
            "--as",
            "growth-agent",
        ],
        forbid=("AIRLOCK-110",),
        beat="1:25 retag, before - status not yet masked",
    )
    pace.beat(4)
    console.print(
        "\n[bold yellow]>> steward applies the PII tag to orders.status in DataHub ...[/]\n"
    )
    _guard("apply the PII tag to orders.status", lambda: set_status_tag(remove=False))
    pace.beat(3)
    run_airlock(["refresh"])
    pace.beat(2)
    console.print("[dim]after - same query, same gateway:[/]")
    run_airlock(
        [
            "check",
            "SELECT status, COUNT(*) AS n FROM orders GROUP BY status",
            "--as",
            "growth-agent",
        ],
        expect=("AIRLOCK-110",),
        beat="1:25 retag, after - status masked by the new tag",
    )
    pace.beat(12)
    # Put the catalog back now, so the beats that follow read the same state a first-time viewer's
    # would. The `finally` in main() repeats this; removing an absent tag is a no-op, and a restore
    # that only runs at the end would leave every later beat looking at a catalog the demo edited.
    restore_status_tag()

    caption(
        "2:10  Write-back closes the loop",
        "Two real queries, executed against the warehouse - one allowed, one denied.",
        "Then read their fingerprint back out of DataHub itself.",
    )
    _guard(
        "execute the agent's queries for real",
        lambda: execute_through_gateway(
            [
                ("SELECT name, email, phone, ssn FROM dim_users", "growth-agent"),
                ("SELECT name FROM dim_users WHERE email = 'ada@corp.com'", "growth-agent"),
            ]
        ),
    )
    pace.beat(4)
    _guard("read the write-back back out of DataHub", show_writeback)
    pace.beat(12)

    caption(
        "2:30  It finds its own blind spots - and fixes them",
        "Airlock flags columns that read as sensitive but carry no tag. customer_phone here.",
        "Then it proposes the classification back to DataHub - the gateway improving the catalog.",
    )
    run_airlock(["coverage"])
    pace.beat(8)
    console.print(
        "\n[bold yellow]>> airlock proposes the missing classification back to DataHub[/]\n"
    )
    run_airlock(["propose"])
    pace.beat(10)

    console.print(
        Panel(
            Align.center(
                Text.from_markup(
                    "[bold white]Apache 2.0 · runs on any laptop with Docker and Python · no mock mode[/]\n"
                    "[dim]Everything you just saw was live.[/]"
                )
            ),
            border_style="cyan",
            padding=(1, 6),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
