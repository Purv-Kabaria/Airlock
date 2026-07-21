"""Shared setup for the integration tools (bench, eval, judge, examples).

Everything here runs against the REAL stack. It seeds the demo catalog into a live DataHub and a
real DuckDB warehouse, then compiles the policy snapshot the exact same way `airlock serve` does.
No PolicyGraph is ever built by hand: if DataHub is unreachable the tool fails with a clear message
instead of fabricating one. That is the whole point - these tools exercise the production path, so
what they measure and capture is what the demo actually does.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_DEMO_ENV = {
    "DATAHUB_GMS_URL": "http://localhost:8080",
    "DATAHUB_GMS_TOKEN": "",
    "WAREHOUSE_DSN": "./demo/warehouse.duckdb",
    "AIRLOCK_KEY_GROWTH": "demo-growth-key",
    "AIRLOCK_KEY_FINANCE": "demo-finance-key",
    "AIRLOCK_MASK_SALT": "demo-salt",
}


def load_demo_config():  # type: ignore[no-untyped-def]
    """Load demo/airlock.yaml with demo env defaults (never overriding anything already set)."""
    for key, value in _DEMO_ENV.items():
        os.environ.setdefault(key, value)
    from airlock.config import load_config

    return load_config(ROOT / "demo" / "airlock.yaml")


def warehouse_path(cfg) -> str:  # type: ignore[no-untyped-def]
    from airlock.exec.duckdb_adapter import _normalize_dsn

    return _normalize_dsn(cfg.warehouse.dsn)


def seed_warehouse(cfg) -> str:  # type: ignore[no-untyped-def]
    """Load the demo rows into the real DuckDB warehouse the config points at. Returns its path."""
    from demo.catalog import seed_duckdb

    path = warehouse_path(cfg)
    seed_duckdb(path)
    return path


def live_snapshot(cfg):  # type: ignore[no-untyped-def]
    """Ingest the demo catalog into DataHub (idempotent) and compile the snapshot from it.

    Returns the real PolicyGraph. Raises with an actionable message if DataHub is not reachable, so
    a tool never silently falls back to a hand-built graph.
    """
    from airlock.errors import SnapshotUnavailableError

    try:
        from demo.seed_catalog import seed as seed_catalog

        seed_catalog()
    except Exception as exc:
        raise SnapshotUnavailableError(
            f"Could not reach DataHub to seed the demo catalog ({exc}). "
            "Start the stack with `python demo/up.py`, then re-run this tool."
        ) from exc

    from airlock.policy.compile import compile_snapshot

    return compile_snapshot(cfg)


def run(main):  # type: ignore[no-untyped-def]
    """Run a tool's `main` (sync or async), turning a missing stack into a clear message + exit 2
    instead of a traceback. Use as `if __name__ == '__main__': run(main)`."""
    import asyncio
    import inspect

    from airlock.errors import SnapshotUnavailableError

    try:
        result = asyncio.run(main()) if inspect.iscoroutinefunction(main) else main()
    except SnapshotUnavailableError as exc:
        print(f"\n{exc}", file=sys.stderr)
        raise SystemExit(2) from None
    raise SystemExit(result or 0)
