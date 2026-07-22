"""Content-addressed snapshot store: an atomic in-memory reference plus SQLite persistence.

Reads take the current `PolicyGraph` with a plain attribute read — no lock, so a thousand
concurrent decisions never contend (README §12). A refresh installs a new graph by swapping the
reference; in-flight requests keep the graph they pinned at ingress. The DataHub-derived catalog
facts are also persisted to SQLite so a restart can serve the last-known snapshot (within the
staleness budget) instead of failing cold when DataHub is briefly unreachable.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from airlock.policy.graph import ColumnFact, DatasetFacts, PolicyGraph

# How many historical snapshots to retain on disk. Only the newest is ever loaded; the rest are
# kept for debugging (`airlock explain` cross-referencing a past snapshot hash).
_KEEP_SNAPSHOTS = 10


@dataclass(frozen=True, slots=True)
class PersistedCatalog:
    datasets: dict[str, DatasetFacts]
    lineage: dict[str, tuple[str, ...]]
    compiled_at: datetime
    source_url: str
    # Column-level edges must survive the round trip with everything else. They carry classification
    # propagation, so a snapshot restored without them decides *less strictly* than the one it was
    # saved from - a column masked live comes back in the clear on the stale path.
    column_lineage: dict[str, tuple[str, ...]] = field(default_factory=dict)


class SnapshotStore:
    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._current: PolicyGraph | None = None
        self._init_db()

    @property
    def current(self) -> PolicyGraph | None:
        return self._current

    def install(self, graph: PolicyGraph) -> None:
        """Swap in a new snapshot and persist its catalog facts. The swap is the atomic point."""
        self._persist(graph)
        self._current = graph

    def persisted_catalog(self) -> PersistedCatalog | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT source_url, compiled_at, payload FROM snapshots ORDER BY compiled_at DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        source_url, compiled_at, payload = row
        data = json.loads(payload)
        datasets = {urn: _dataset_from_json(d) for urn, d in data["datasets"].items()}
        lineage = {k: tuple(v) for k, v in data["lineage"].items()}
        # Snapshots written before column lineage was persisted have no such key; treat them as
        # having none rather than failing to load a catalog that is otherwise usable.
        column_lineage = {k: tuple(v) for k, v in data.get("column_lineage", {}).items()}
        return PersistedCatalog(
            datasets=datasets,
            lineage=lineage,
            compiled_at=datetime.fromisoformat(compiled_at),
            source_url=source_url,
            column_lineage=column_lineage,
        )

    def _persist(self, graph: PolicyGraph) -> None:
        payload = json.dumps(
            {
                "datasets": {urn: _dataset_to_json(ds) for urn, ds in graph.datasets.items()},
                "lineage": {k: list(v) for k, v in graph.lineage.downstream.items()},
                "column_lineage": {k: list(v) for k, v in graph.lineage.column_upstreams.items()},
            },
            separators=(",", ":"),
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO snapshots(hash, source_url, compiled_at, payload) VALUES (?,?,?,?)",
                (graph.content_hash, graph.source_url, graph.compiled_at.isoformat(), payload),
            )
            # Only the newest snapshot is ever read back; keep a small history for debugging and
            # prune the rest so the store cannot grow without bound.
            conn.execute(
                "DELETE FROM snapshots WHERE hash NOT IN "
                f"(SELECT hash FROM snapshots ORDER BY compiled_at DESC LIMIT {_KEEP_SNAPSHOTS})"
            )
            conn.commit()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS snapshots ("
                "hash TEXT PRIMARY KEY, source_url TEXT, compiled_at TEXT, payload TEXT)"
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)


def _dataset_to_json(ds: DatasetFacts) -> dict[str, object]:
    return {
        "urn": ds.urn,
        "platform": ds.platform,
        "name": ds.name,
        "env": ds.env,
        "lifecycle": ds.lifecycle,
        "certification": ds.certification,
        "domain": ds.domain,
        "owners": list(ds.owners),
        "tags": sorted(ds.tags),
        "terms": sorted(ds.glossary_terms),
        "columns": [
            {
                "name": c.name,
                "urn": c.urn,
                "data_type": c.data_type,
                "tags": sorted(c.tags),
                "terms": sorted(c.glossary_terms),
            }
            for c in ds.columns
        ],
    }


def _dataset_from_json(d: dict[str, Any]) -> DatasetFacts:
    columns = tuple(
        ColumnFact(
            name=c["name"],
            urn=c["urn"],
            data_type=c["data_type"],
            tags=frozenset(c["tags"]),
            glossary_terms=frozenset(c["terms"]),
        )
        for c in d["columns"]
    )
    return DatasetFacts(
        urn=d["urn"],
        platform=d["platform"],
        name=d["name"],
        env=d["env"],
        columns=columns,
        tags=frozenset(d["tags"]),
        glossary_terms=frozenset(d["terms"]),
        lifecycle=d["lifecycle"],
        certification=d["certification"],
        domain=d["domain"],
        owners=tuple(d["owners"]),
    )
