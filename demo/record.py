"""Self-running demo for the submission video. Screen-record this in one hands-free take.

It plays the exact sequence from SCRIPT.md against the live stack `python demo/up.py` starts -
cold open, a clean query, lineage substitution, the live retag, write-back, and the coverage
close - with large captions and pauses sized for a voiceover. Nothing here is mocked: every beat
shells out to the real `airlock` CLI or writes a real tag to the real DataHub, exactly as a data
steward's UI click would.

    python demo/record.py            # presentation timing (~2:45), for recording
    python demo/record.py --rehearse # short pauses, to check every beat works first

Read demo/VIDEO.md aloud over the recording, or feed it to a text-to-speech engine.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

REPO = Path(__file__).resolve().parent.parent
CONFIG = "demo/airlock.yaml"
GMS = os.environ.get("DATAHUB_GMS_URL", "http://localhost:8080")
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


def run_airlock(args: list[str]) -> None:
    """Run a real airlock command with its own rich output inherited to the terminal."""
    console.print(f"[dim]$ airlock {' '.join(args)}[/]\n")
    subprocess.run(AIRLOCK + args + ["-c", CONFIG], cwd=REPO, check=False)


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rehearse", action="store_true", help="short pauses to verify beats")
    args = parser.parse_args()

    _load_env()
    pace = Pacer(args.rehearse)

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
    run_airlock(["check", "SELECT name, email, ssn FROM dim_users", "--as", "growth-agent"])
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
        ]
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
        ]
    )
    pace.beat(16)

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
        ]
    )
    pace.beat(4)
    console.print(
        "\n[bold yellow]>> steward applies the PII tag to orders.status in DataHub ...[/]\n"
    )
    set_status_tag(remove=False)
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
        ]
    )
    pace.beat(12)
    set_status_tag(remove=True)  # restore so the demo is idempotent

    caption(
        "2:10  Write-back closes the loop",
        "Every decision writes back to DataHub: last access, the snapshot hash that made it,",
        "a denied-attempts counter. Governance queries what agents did where they already look.",
    )
    show_writeback()
    pace.beat(14)

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
