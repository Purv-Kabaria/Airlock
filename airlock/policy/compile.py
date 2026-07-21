"""Compile a PolicyGraph from a live DataHub. The only module that reads DataHub.

Catalog facts (schemas, column tags, glossary terms, deprecation, certification, domains, and
lineage) come from DataHub via GraphQL; rules, principals, and enforcement come from config.
The two are combined into one content-addressed `PolicyGraph`. There is no code path that
produces a graph without DataHub — `serve` fails fast if this cannot complete (README §10).

Names for tags/terms/domains are derived from their URNs so we do not depend on optional
GraphQL display-name fields being populated.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from airlock.config import AirlockConfig
from airlock.errors import SnapshotUnavailableError
from airlock.logging import get_logger
from airlock.policy.graph import ColumnFact, DatasetFacts, PolicyGraph
from airlock.urns import domain_name, glossary_name, tag_name

log = get_logger("airlock.policy.compile")

# Bound the DataHub client so a slow or still-booting GMS fails in seconds, not after the SDK's
# default 30s read timeout times four retries (~2 min) - which would freeze `airlock doctor`, the
# one command an operator runs when things are already wrong. One retry absorbs a transient blip.
_CLIENT_TIMEOUT_SEC = 15.0
_CLIENT_RETRIES = 1

_LIST_QUERY = """
query listDatasets($platform: String!, $start: Int!, $count: Int!) {
  search(input: {type: DATASET, query: "*", start: $start, count: $count,
    orFilters: [{and: [{field: "platform", values: [$platform]}]}]}) {
    start count total
    searchResults { entity { urn } }
  }
}
"""

_DATASET_QUERY = """
query ds($urn: String!) {
  dataset(urn: $urn) {
    urn
    name
    properties { qualifiedName }
    deprecation { deprecated }
    domain { domain { urn properties { name } } }
    ownership { owners { owner { ... on CorpUser { urn } ... on CorpGroup { urn } } } }
    tags { tags { tag { urn } } }
    glossaryTerms { terms { term { urn } } }
    schemaMetadata {
      fields { fieldPath nativeDataType
        tags { tags { tag { urn } } }
        glossaryTerms { terms { term { urn } } } }
    }
    editableSchemaMetadata {
      editableSchemaFieldInfo { fieldPath
        tags { tags { tag { urn } } }
        glossaryTerms { terms { term { urn } } } }
    }
  }
}
"""


def _datahub_failure(exc: Exception) -> str:
    """A one-line, actionable reason from a DataHub client exception - never the multi-line urllib3
    connection-pool dump. The full exception is preserved on the chain (`from exc`) for the log."""
    text = str(exc).lower()
    if any(
        s in text for s in ("refused", "failed to establish", "newconnectionerror", "max retries")
    ):
        return (
            "connection refused. Is DataHub running? Start it with `python demo/up.py`, then retry"
        )
    if "timed out" in text or "timeout" in text:
        return "timed out. DataHub is slow or still booting; wait for it to be healthy, then retry"
    if "unauthorized" in text or "401" in text:
        return "authentication rejected. Check datahub.token"
    if "forbidden" in text or "403" in text:
        return "access forbidden. Check the datahub.token permissions"
    return str(exc).splitlines()[0][:200]


def ping(config: AirlockConfig, *, timeout: float = 5.0) -> None:
    """Cheap connectivity check for `airlock doctor` and startup. Raises on failure."""
    url = config.datahub.url.rstrip("/") + "/config"
    headers = {"Authorization": f"Bearer {config.datahub.token}"} if config.datahub.token else {}
    resp = httpx.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()


def compile_snapshot(config: AirlockConfig) -> PolicyGraph:
    """Read DataHub and build a PolicyGraph. Raises SnapshotUnavailableError on any failure."""
    from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph

    try:
        client = DataHubGraph(
            DatahubClientConfig(
                server=config.datahub.url,
                token=config.datahub.token,
                timeout_sec=_CLIENT_TIMEOUT_SEC,
                retry_max_times=_CLIENT_RETRIES,
            )
        )
        platform_urn = f"urn:li:dataPlatform:{config.warehouse.kind}"
        urns = _list_dataset_urns(client, platform_urn)
        if not urns:
            raise SnapshotUnavailableError(
                f"DataHub has no datasets for platform '{config.warehouse.kind}'. "
                "Ingest the warehouse catalog before starting Airlock."
            )
        datasets: dict[str, DatasetFacts] = {}
        for urn in urns:
            facts = _fetch_dataset(client, urn, config.warehouse.kind)
            if facts is not None:
                datasets[urn] = facts
        lineage = _fetch_lineage(client, list(datasets.keys()))
        column_lineage = _fetch_column_lineage(client, list(datasets.keys()))
    except SnapshotUnavailableError:
        raise
    except Exception as exc:
        raise SnapshotUnavailableError(
            f"Could not compile a policy snapshot from DataHub at {config.datahub.url}: "
            f"{_datahub_failure(exc)}"
        ) from exc

    graph = PolicyGraph.build(
        datasets=datasets,
        lineage=lineage,
        column_lineage=column_lineage,
        rules=config.compiled_rules(),
        enforcement=config.enforcement_settings(),
        principals=config.compiled_principals(),
        compiled_at=datetime.now(UTC),
        source_url=config.datahub.url,
    )
    log.info(
        "snapshot.compiled",
        datasets=len(datasets),
        rules=len(graph.rules),
        principals=len(graph.principals),
        hash=graph.content_hash,
    )
    return graph


def _list_dataset_urns(client: Any, platform_urn: str) -> list[str]:
    urns: list[str] = []
    start, count = 0, 200
    while True:
        result = client.execute_graphql(
            _LIST_QUERY, variables={"platform": platform_urn, "start": start, "count": count}
        )
        search = result["search"]
        page = [r["entity"]["urn"] for r in search["searchResults"]]
        urns += page
        start += count
        # Stop when we have them all, or when a page comes back empty (guards against a total that
        # never gets reached, which would otherwise loop forever).
        if not page or start >= search["total"]:
            break
    return urns


def _fetch_dataset(client: Any, urn: str, platform: str) -> DatasetFacts | None:
    data = client.execute_graphql(_DATASET_QUERY, variables={"urn": urn})
    ds = data.get("dataset")
    if ds is None:
        return None

    name = _qualified_name(ds)
    tags = _entity_urns(ds.get("tags"), "tags", "tag")
    terms = _entity_urns(ds.get("glossaryTerms"), "terms", "term")
    lifecycle = "DEPRECATED" if (ds.get("deprecation") or {}).get("deprecated") else None
    certification = "CERTIFIED" if _is_certified(tags, terms) else None
    domain = _domain(ds)
    owners = _owners(ds)
    columns = _columns(ds)

    return DatasetFacts(
        urn=urn,
        platform=platform,
        name=name,
        env="PROD",
        columns=columns,
        tags=frozenset(tag_name(t) for t in tags),
        glossary_terms=frozenset(glossary_name(t) for t in terms),
        lifecycle=lifecycle,
        certification=certification,
        domain=domain,
        owners=owners,
    )


def _fetch_lineage(client: Any, urns: list[str]) -> dict[str, tuple[str, ...]]:
    """Downstream edges per dataset. Best-effort: a lineage API hiccup degrades substitution,
    it does not fail the whole snapshot."""
    from datahub.ingestion.graph.client import DataHubGraph

    direction = DataHubGraph.RelationshipDirection.INCOMING
    downstream: dict[str, list[str]] = {}
    for urn in urns:
        try:
            related = client.get_related_entities(
                entity_urn=urn, relationship_types=["DownstreamOf"], direction=direction
            )
            for entry in related:
                downstream.setdefault(urn, []).append(entry.urn)
        except Exception as exc:
            log.warning("lineage.fetch_failed", urn=urn, detail=str(exc))
    return {k: tuple(v) for k, v in downstream.items()}


def _fetch_column_lineage(client: Any, urns: list[str]) -> dict[str, tuple[str, ...]]:
    """Fine-grained (column-level) upstream edges: a downstream schemaField URN mapped to the field
    URNs it derives from, read from each dataset's UpstreamLineage aspect. This is what lets Airlock
    inherit a classification onto a derived column the catalog never tagged. Best-effort: a lineage
    read failing degrades propagation for that dataset, it does not fail the snapshot."""
    from datahub.metadata.schema_classes import UpstreamLineageClass

    edges: dict[str, list[str]] = {}
    for urn in urns:
        try:
            aspect = client.get_aspect(entity_urn=urn, aspect_type=UpstreamLineageClass)
        except Exception as exc:
            log.warning("column_lineage.fetch_failed", urn=urn, detail=str(exc))
            continue
        for fine in (aspect.fineGrainedLineages if aspect else None) or []:
            for downstream in fine.downstreams or []:
                edges.setdefault(downstream, []).extend(fine.upstreams or [])
    return {downstream: tuple(ups) for downstream, ups in edges.items()}


def _columns(ds: dict[str, Any]) -> tuple[ColumnFact, ...]:
    fields = (ds.get("schemaMetadata") or {}).get("fields") or []
    editable = {
        _field_name(f["fieldPath"]): f
        for f in (ds.get("editableSchemaMetadata") or {}).get("editableSchemaFieldInfo") or []
    }
    out: list[ColumnFact] = []
    for field in fields:
        name = _field_name(field["fieldPath"])
        tags = set(_entity_urns(field.get("tags"), "tags", "tag"))
        terms = set(_entity_urns(field.get("glossaryTerms"), "terms", "term"))
        extra = editable.get(name)
        if extra is not None:
            tags |= set(_entity_urns(extra.get("tags"), "tags", "tag"))
            terms |= set(_entity_urns(extra.get("glossaryTerms"), "terms", "term"))
        out.append(
            ColumnFact(
                name=name,
                urn=f"urn:li:schemaField:({ds['urn']},{name})",
                data_type=field.get("nativeDataType") or "VARCHAR",
                tags=frozenset(tag_name(t) for t in tags),
                glossary_terms=frozenset(glossary_name(t) for t in terms),
            )
        )
    return tuple(out)


def _entity_urns(container: Any, list_key: str, item_key: str) -> list[str]:
    if not container:
        return []
    return [item[item_key]["urn"] for item in container.get(list_key) or []]


def _qualified_name(ds: dict[str, Any]) -> str:
    props = ds.get("properties") or {}
    return str(props.get("qualifiedName") or ds.get("name") or ds["urn"])


def _domain(ds: dict[str, Any]) -> str | None:
    node = ((ds.get("domain") or {}).get("domain")) or None
    if node is None:
        return None
    props = node.get("properties") or {}
    return str(props.get("name") or domain_name(node["urn"]))


def _owners(ds: dict[str, Any]) -> tuple[str, ...]:
    owners = (ds.get("ownership") or {}).get("owners") or []
    return tuple(o["owner"]["urn"].split(":")[-1] for o in owners if o.get("owner"))


def _is_certified(tags: list[str], terms: list[str]) -> bool:
    names = {tag_name(t).lower() for t in tags} | {glossary_name(t).lower() for t in terms}
    return any("certified" in n for n in names)


def _field_name(field_path: str) -> str:
    # v2 field paths look like [version=2.0].[type=...].email; the column is the last segment.
    return field_path.split(".")[-1]
