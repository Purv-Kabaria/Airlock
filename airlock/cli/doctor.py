"""`airlock doctor`: verify the environment item by item, and name the fix for anything broken.

First thing to run, last thing to blame, which sets the bar: it resolves config exactly the way
every other command does, it always prints the whole checklist, and every failure carries the
command that fixes it. A diagnostic that reports a failure no other command sees, or that stops at
the first problem and makes you re-run to discover the next one, costs more trust than it earns.

Checks never raise; a failure is a red row, not a traceback. Nothing here blocks on a call it
already knows will fail.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from airlock.config import AirlockConfig

console = Console()

Status = Literal["pass", "fail", "warn", "skip"]

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"})


@dataclass(slots=True)
class Check:
    name: str
    status: Status
    detail: str
    fix: str | None = None  # the command or edit that resolves a fail/warn


def run_doctor(config_path: Path, *, as_json: bool = False) -> bool:
    """Run every check and report. True when nothing is failing (warnings do not fail doctor)."""
    checks = _collect(config_path)
    if as_json:
        print(json.dumps(_payload(checks), indent=2))
    else:
        _render(checks)
        _render_summary(checks)
    return not any(c.status == "fail" for c in checks)


def _collect(config_path: Path) -> list[Check]:
    checks = [_python()]

    cfg: AirlockConfig | None = None
    try:
        from airlock.config import autoload_env, load_config

        # Same resolution as every other command, .env autoload included. Without this doctor
        # rejects configs that `check`, `serve`, and `coverage` all load happily.
        autoload_env(config_path)
        cfg = load_config(config_path)
        checks.append(Check("config", "pass", f"loaded {config_path}"))
    except Exception as exc:
        checks.append(Check("config", "fail", str(exc), fix=_config_fix(str(exc), config_path)))

    checks.append(_docker(cfg))

    if cfg is None:
        # The rest all need config. Report them as skipped rather than dropping them: the operator
        # should see the full checklist and how far it got, not a table that silently ends early.
        reason = "config did not load"
        checks += [
            Check(name, "skip", reason)
            for name in ("datahub", "warehouse", "snapshot", "mask-salt")
        ]
        return checks

    datahub = _datahub(cfg)
    checks.append(datahub)
    checks.append(_warehouse(cfg))
    # Compiling reads the whole catalog; if the cheap ping already showed DataHub is unreachable,
    # skip it rather than make the operator wait out the client timeout on a call we know fails.
    if datahub.status == "pass":
        checks.append(_snapshot(cfg))
    else:
        checks.append(Check("snapshot", "skip", "needs DataHub; fix the check above first"))
    checks.append(_mask_salt(cfg))
    return checks


def _config_fix(message: str, config_path: Path) -> str:
    if "environment variable" in message:
        return (
            f"export the variable, or copy {config_path.parent / '.env.example'} to "
            f"{config_path.parent / '.env'} and re-run"
        )
    if "not found" in message:
        return "run `airlock init` to write one, or pass --config <path>"
    return "fix the value named above, then re-run `airlock doctor`"


def _python() -> Check:
    """Informational only. `requires-python = >=3.11` means an older interpreter cannot install
    Airlock in the first place, so this row records what you are on rather than gating on it."""
    return Check("python", "pass", sys.version.split()[0])


def _docker(cfg: AirlockConfig | None) -> Check:
    """Docker only matters for the demo stack. Pointed at your own DataHub you never need it, and
    failing doctor over it would train operators to ignore a red row."""
    if cfg is not None and not _is_local(cfg.datahub.url):
        return Check("docker", "skip", f"not needed: DataHub is remote ({cfg.datahub.url})")
    if shutil.which("docker") is None:
        return Check(
            "docker",
            "fail",
            "not on PATH",
            fix="install Docker Desktop; it hosts the local DataHub this config points at",
        )
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return Check("docker", "pass", "daemon running")
    except Exception:
        return Check(
            "docker", "fail", "daemon not reachable", fix="start Docker Desktop, then re-run"
        )


def _is_local(url: str) -> bool:
    return (urlparse(url).hostname or "") in _LOCAL_HOSTS


def _datahub(cfg: AirlockConfig) -> Check:
    from airlock.policy.compile import NotDataHubError, ping

    try:
        ping(cfg)
        return Check("datahub", "pass", f"reachable at {cfg.datahub.url}")
    except NotDataHubError as exc:
        # Reachable, but the wrong service - a port collision, not a down DataHub. Saying
        # "unreachable" here would send the operator to restart a stack that is already up.
        return Check(
            "datahub",
            "fail",
            str(exc),
            fix="another service holds this port; point datahub.url at DataHub's port, or free it. "
            "`python demo/up.py` picks a free GMS port automatically.",
        )
    except Exception as exc:
        fix = (
            "start the stack with `python demo/up.py`"
            if _is_local(cfg.datahub.url)
            else "check datahub.url and the token, and that this host can reach it"
        )
        return Check("datahub", "fail", f"unreachable at {cfg.datahub.url} ({exc})", fix=fix)


def _warehouse(cfg: AirlockConfig) -> Check:
    from airlock.exec.base import make_adapter

    async def _probe() -> None:
        adapter = make_adapter(cfg.warehouse)
        try:
            await adapter.healthcheck()
        finally:
            await adapter.close()

    try:
        asyncio.run(_probe())
        return Check("warehouse", "pass", f"{cfg.warehouse.kind} connectable")
    except Exception as exc:
        return Check(
            "warehouse",
            "fail",
            f"{cfg.warehouse.kind} not connectable ({exc})",
            fix="check warehouse.dsn; for the demo run `python demo/up.py` to seed the DuckDB file",
        )


def _snapshot(cfg: AirlockConfig) -> Check:
    from airlock.policy.compile import compile_snapshot

    try:
        graph = compile_snapshot(cfg)
        return Check(
            "snapshot", "pass", f"{len(graph.datasets)} datasets, {len(graph.rules)} rules"
        )
    except Exception as exc:
        return Check(
            "snapshot",
            "fail",
            f"could not compile ({exc})",
            fix="run `airlock refresh` for the full error, then check the DataHub token's scope",
        )


def _mask_salt(cfg: AirlockConfig) -> Check:
    if cfg.masking.salt:
        return Check("mask-salt", "pass", "configured")
    return Check(
        "mask-salt",
        "warn",
        "unset; hash masking derives a salt from the public snapshot",
        fix="set masking.salt to a deployment secret before production",
    )


_MARK: dict[Status, str] = {
    "pass": "[green]PASS[/]",
    "fail": "[red]FAIL[/]",
    "warn": "[yellow]WARN[/]",
    "skip": "[dim]SKIP[/]",
}


def _render(checks: list[Check]) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    for c in checks:
        detail = c.detail
        if c.fix and c.status in ("fail", "warn"):
            detail = f"{detail}\n[dim]fix:[/] {c.fix}"
        table.add_row(c.name, _MARK[c.status], detail)
    console.print(table)


def _render_summary(checks: list[Check]) -> None:
    """One line naming the next action. A table the operator has to interpret is a dead end."""
    failed = [c for c in checks if c.status == "fail"]
    if failed:
        first = failed[0]
        console.print(
            f"\n[red]{len(failed)} check(s) failing.[/] Start with [bold]{first.name}[/]: "
            f"{first.fix or first.detail}"
        )
        return
    warned = [c for c in checks if c.status == "warn"]
    if warned:
        console.print(f"\n[green]ready[/] - {len(warned)} warning(s); see the fix column above.")
        return
    console.print("\n[green]all checks passed[/] - run `airlock serve` to start the gateway.")


def _payload(checks: list[Check]) -> dict[str, object]:
    return {
        "ok": not any(c.status == "fail" for c in checks),
        "checks": [
            {"check": c.name, "status": c.status, "detail": c.detail, "fix": c.fix} for c in checks
        ],
    }
