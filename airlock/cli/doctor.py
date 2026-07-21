"""`airlock doctor`: verify the environment item by item, and name the fix for anything broken.

First thing to run, last thing to blame. Each check reports pass/fail with the exact remedy, so a
judge on an unfamiliar laptop can self-serve. Checks never raise; a failure is a red row, not a
traceback.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from airlock.config import AirlockConfig

console = Console()


@dataclass(slots=True)
class Check:
    name: str
    ok: bool
    detail: str
    warn: bool = False  # ok=True + warn=True renders as WARN and does not fail doctor


def run_doctor(config_path: Path) -> bool:
    checks: list[Check] = [_python()]

    cfg = None
    try:
        from airlock.config import load_config

        cfg = load_config(config_path)
        checks.append(Check("config", True, f"loaded {config_path}"))
    except Exception as exc:
        checks.append(Check("config", False, f"{exc}"))

    checks.append(_docker())

    if cfg is not None:
        datahub = _datahub(cfg)
        checks.append(datahub)
        checks.append(_warehouse(cfg))
        # Compiling reads the whole catalog; if the cheap ping already showed DataHub is unreachable,
        # skip it rather than make the operator wait out the client timeout on a call we know fails.
        if datahub.ok:
            checks.append(_snapshot(cfg))
        else:
            checks.append(Check("snapshot", False, "skipped - fix DataHub connectivity first"))
        checks.append(_mask_salt(cfg))

    _render(checks)
    return all(c.ok for c in checks)


def _mask_salt(cfg: AirlockConfig) -> Check:
    if cfg.masking.salt:
        return Check("mask-salt", True, "configured")
    return Check(
        "mask-salt",
        True,
        "unset; hash masking derives a salt from the public snapshot - set masking.salt in production",
        warn=True,
    )


def _python() -> Check:
    ok = sys.version_info >= (3, 11)
    return Check("python", ok, f"{sys.version.split()[0]}" + ("" if ok else " (need >=3.11)"))


def _docker() -> Check:
    if shutil.which("docker") is None:
        return Check("docker", False, "docker not on PATH; install Docker Desktop")
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return Check("docker", True, "daemon running")
    except Exception:
        return Check("docker", False, "daemon not reachable; start Docker Desktop")


def _datahub(cfg: AirlockConfig) -> Check:
    from airlock.policy.compile import ping

    try:
        ping(cfg)
        return Check("datahub", True, f"reachable at {cfg.datahub.url}")
    except Exception as exc:
        return Check("datahub", False, f"unreachable ({exc}); is the quickstart up?")


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
        return Check("warehouse", True, f"{cfg.warehouse.kind} connectable")
    except Exception as exc:
        return Check("warehouse", False, f"{cfg.warehouse.kind} not connectable ({exc})")


def _snapshot(cfg: AirlockConfig) -> Check:
    from airlock.policy.compile import compile_snapshot

    try:
        graph = compile_snapshot(cfg)
        return Check("snapshot", True, f"{len(graph.datasets)} datasets, {len(graph.rules)} rules")
    except Exception as exc:
        return Check("snapshot", False, f"could not compile ({exc})")


def _render(checks: list[Check]) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    for c in checks:
        if not c.ok:
            mark = "[red]FAIL[/]"
        elif c.warn:
            mark = "[yellow]WARN[/]"
        else:
            mark = "[green]PASS[/]"
        table.add_row(c.name, mark, c.detail)
    console.print(table)
