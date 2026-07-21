"""Seed the DuckDB demo warehouse from the shared catalog. Idempotent."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from demo.catalog import seed_duckdb


def seed() -> None:
    dsn = os.environ.get("WAREHOUSE_DSN", "./demo/warehouse.duckdb")
    path = dsn.split("duckdb:///")[-1].split("duckdb://")[-1]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    seed_duckdb(path)
    print(f"seeded DuckDB warehouse at {path}")


if __name__ == "__main__":
    seed()
