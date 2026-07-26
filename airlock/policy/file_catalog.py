"""Compile a PolicyGraph from a reviewed local catalog file, for people without DataHub.

DataHub remains the intended source: it is maintained by the people who own the data, it carries
lineage and ownership Airlock uses for substitution and scope, and it keeps classification in one
place for a whole company. This is the path for a solo developer or a small team who have a database
and an agent and no catalog at all - the people for whom "install DataHub first" means "give up".

The rule this file must not break is that **Airlock enforces what a human declared and never guesses**
(README, CLAUDE.md §10). A local catalog does not weaken that: the file is written and reviewed by a
person, exactly like a tag applied in the DataHub UI. `airlock init --local` can *propose* entries by
reading the warehouse schema, but a proposal is commented out until someone confirms it, so nothing is
ever enforced - or silently not enforced - on the strength of a column's name.

What is genuinely lost without DataHub, and is reported rather than hidden: column-level lineage
(so classification does not propagate to derived columns), ownership (denials cannot name a team),
and the shared catalog itself. `airlock coverage` says so, and every envelope names its source.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from airlock.errors import ConfigError, SnapshotUnavailableError
from airlock.logging import get_logger
from airlock.policy.graph import ColumnFact, DatasetFacts, PolicyGraph
from airlock.urns import dataset_urn, field_urn

log = get_logger("airlock.policy.file_catalog")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ColumnEntry(_Strict):
    name: str
    type: str = "VARCHAR"
    tags: list[str] = Field(default_factory=list)
    terms: list[str] = Field(default_factory=list)


class DatasetEntry(_Strict):
    name: str
    columns: list[ColumnEntry] = Field(default_factory=list)
    domain: str | None = None
    owners: list[str] = Field(default_factory=list)
    deprecated: bool = False
    certified: bool = False
    # The dataset that replaces this one. Stands in for the lineage edge DataHub would carry, so
    # certified-table substitution works here too.
    replaced_by: str | None = None


class CatalogFile(_Strict):
    datasets: list[DatasetEntry] = Field(default_factory=list)


def load_catalog_file(
    path: Path, platform: str
) -> tuple[dict[str, DatasetFacts], dict[str, tuple[str, ...]]]:
    """Read the catalog file into the same facts DataHub compilation produces.

    Returns (datasets, lineage). Raises ConfigError with the offending field named, never a
    traceback: this file is hand-written, so a typo in it is the most likely failure by far.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ConfigError(f"could not read the catalog file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    try:
        parsed = CatalogFile.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise ConfigError(f"{path}: {where}: {first['msg']}") from exc

    if not parsed.datasets:
        raise ConfigError(
            f"{path} lists no datasets, so Airlock would deny every query. "
            "Add the tables the agent may read, or run `airlock init --local` to draft it."
        )

    datasets: dict[str, DatasetFacts] = {}
    by_name: dict[str, str] = {}
    for entry in parsed.datasets:
        urn = dataset_urn(platform, entry.name)
        if urn in datasets:
            raise ConfigError(f"{path}: dataset {entry.name!r} is listed twice")
        datasets[urn] = DatasetFacts(
            urn=urn,
            platform=platform,
            name=entry.name,
            env="PROD",
            columns=tuple(
                ColumnFact(
                    name=column.name,
                    urn=field_urn(urn, column.name),
                    data_type=column.type,
                    tags=frozenset(column.tags),
                    glossary_terms=frozenset(column.terms),
                )
                for column in entry.columns
            ),
            lifecycle="DEPRECATED" if entry.deprecated else None,
            certification="CERTIFIED" if entry.certified else None,
            domain=entry.domain,
            owners=tuple(entry.owners),
        )
        by_name[entry.name] = urn

    lineage: dict[str, tuple[str, ...]] = {}
    for entry in parsed.datasets:
        if entry.replaced_by is None:
            continue
        target = by_name.get(entry.replaced_by)
        if target is None:
            raise ConfigError(
                f"{path}: {entry.name}.replaced_by points at {entry.replaced_by!r}, "
                "which is not a dataset in this file"
            )
        lineage[by_name[entry.name]] = (target,)
    return datasets, lineage


def compile_from_file(config: Any) -> PolicyGraph:
    """Build a snapshot from the local catalog file named in config.catalog.file."""
    path = Path(config.catalog.file)
    if not path.exists():
        raise SnapshotUnavailableError(
            f"The catalog file {path} does not exist. Create it, or run "
            "`airlock init --local` to draft one from your warehouse schema."
        )
    datasets, lineage = load_catalog_file(path, config.warehouse.kind)
    graph = PolicyGraph.build(
        datasets=datasets,
        lineage=lineage,
        # No column-level lineage without DataHub: a derived column inherits nothing, so an
        # unclassified copy of a PII column is served in the clear. `coverage` reports this.
        column_lineage={},
        rules=config.compiled_rules(),
        enforcement=config.enforcement_settings(),
        principals=config.compiled_principals(),
        compiled_at=datetime.now(UTC),
        source_url=str(path),
    )
    log.info(
        "snapshot.compiled",
        source="file",
        path=str(path),
        datasets=len(datasets),
        rules=len(graph.rules),
    )
    return graph
