"""Return the demo to a clean slate: python demo/reset.py.

Nukes the DataHub containers and removes generated warehouse, audit, and snapshot state. Safe to
run when nothing is up.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    print("Nuking DataHub containers...")
    result = subprocess.run(
        [sys.executable, "-m", "datahub", "docker", "nuke"], capture_output=True, text=True
    )
    if result.returncode != 0:
        print("  DataHub CLI not available or nothing to nuke; skipping container nuke.")

    for target in (
        ROOT / "demo" / "warehouse.duckdb",
        ROOT / "demo" / "warehouse.duckdb.wal",
        ROOT / "demo" / "audit",
        ROOT / ".airlock",
    ):
        _remove(target)
    print("Clean. Run `python demo/up.py` to start fresh.")
    return 0


def _remove(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
        print(f"  removed {path}")
    elif path.exists():
        path.unlink(missing_ok=True)
        print(f"  removed {path}")


if __name__ == "__main__":
    raise SystemExit(main())
