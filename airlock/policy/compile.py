"""Compile a PolicyGraph from a live DataHub. The only module that reads DataHub.

Catalog facts (schemas, column tags, glossary terms, deprecation, certification, domains, and
lineage) come from DataHub via GraphQL; rules, principals, and enforcement come from config.
The two are combined into one content-addressed `PolicyGraph`. There is no code path that
produces a graph without DataHub — `serve` fails fast if this cannot complete (README §10).

Names for tags/terms/domains are derived from their URNs so we do not depend on optional
GraphQL display-name fields being populated.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any, TypeVar

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

# The filter array is a variable so one query serves both the whole-platform case and a
# domain-scoped one. Filtering server-side matters at real catalog sizes: an org with thousands of
# datasets running Airlock for one team should not pay to compile - or hold in memory - the rest.
_LIST_QUERY = """
query listDatasets($and: [FacetFilterInput!]!, $start: Int!, $count: Int!) {
  search(input: {type: DATASET, query: "*", start: $start, count: $count,
    orFilters: [{and: $and}]}) {
    start count total
    searchResults { entity { urn } }
  }
}
"""

_DOMAIN_QUERY = """
query findDomain($name: String!) {
  search(input: {type: DOMAIN, query: $name, start: 0, count: 25}) {
    searchResults { entity { urn ... on Domain { properties { name } } } }
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


class NotDataHubError(RuntimeError):
    """The URL answered, but the thing answering is not a DataHub GMS."""


# GMS `/config` returns a JSON object carrying these; a frontend, a proxy, or an unrelated service
# on the same port returns HTML or different JSON. Checking identity - not just a 200 - is what
# stops `doctor` reporting "DataHub reachable" when another service has taken the port.
_GMS_MARKERS = ("noCode", "versions", "statsCollectionEnabled", "datahub")


def _is_gms_config(body: str) -> bool:
    import json

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(data, dict) and any(k in data for k in _GMS_MARKERS)


def ping(config: AirlockConfig, *, timeout: float = 5.0) -> None:
    """Cheap connectivity check for `airlock doctor` and startup.

    Raises on an unreachable URL, and `NotDataHubError` when something answers but is not GMS - a
    200 from an unrelated service on the same port must not read as success.
    """
    datahub = config.require_datahub()
    url = datahub.url.rstrip("/") + "/config"
    headers = {"Authorization": f"Bearer {datahub.token}"} if datahub.token else {}
    resp = httpx.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    if not _is_gms_config(resp.text):
        raise NotDataHubError(
            f"{datahub.url} answered but is not a DataHub GMS (another service may hold this port)"
        )


def compile_snapshot(config: AirlockConfig) -> PolicyGraph:
    """Build a PolicyGraph from the configured catalog source.

    The single entry point for producing a snapshot. DataHub reads live in this module; the local
    file source lives in `policy/file_catalog.py`, so "the only module that reads DataHub" stays
    true of this one. Raises SnapshotUnavailableError on any failure.
    """
    if config.catalog is not None:
        from airlock.policy.file_catalog import compile_from_file

        return compile_from_file(config)
    assert config.datahub is not None  # config validation guarantees exactly one source
    return _compile_from_datahub(config)


def _compile_from_datahub(config: AirlockConfig) -> PolicyGraph:
    from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph

    datahub = config.require_datahub()

    try:
        client = DataHubGraph(
            DatahubClientConfig(
                server=datahub.url,
                token=datahub.token,
                timeout_sec=_CLIENT_TIMEOUT_SEC,
                retry_max_times=_CLIENT_RETRIES,
            )
        )
        platform_urn = f"urn:li:dataPlatform:{config.warehouse.kind}"
        urns = _list_dataset_urns(client, platform_urn, datahub.domains)
        if not urns:
            scope = f" in domains {datahub.domains}" if datahub.domains else ""
            raise SnapshotUnavailableError(
                f"DataHub has no datasets for platform '{config.warehouse.kind}'{scope}. "
                "If you just ingested them, DataHub's search index may still be catching up - "
                "wait a few seconds and retry. Otherwise ingest the warehouse catalog first"
                + (", or widen datahub.domains." if datahub.domains else ".")
            )
        kind = config.warehouse.kind
        datasets = {
            urn: facts
            for urn, facts in zip(
                urns, _map_urns(urns, lambda u: _fetch_dataset(client, u, kind)), strict=True
            )
            if facts is not None
        }
        known = list(datasets.keys())
        lineage = _fetch_lineage(client, known)
        column_lineage = _fetch_column_lineage(client, known)
    except SnapshotUnavailableError:
        raise
    except Exception as exc:
        raise SnapshotUnavailableError(
            f"Could not compile a policy snapshot from DataHub at {datahub.url}: "
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
        source_url=datahub.url,
    )
    log.info(
        "snapshot.compiled",
        datasets=len(datasets),
        rules=len(graph.rules),
        principals=len(graph.principals),
        hash=graph.content_hash,
    )
    return graph


# Catalog reads are one network round-trip per dataset, three times over (facts, lineage, column
# lineage). Serially that is O(3N) round-trips, so cold start grows linearly with catalog size and a
# few hundred datasets over a network is minutes. Fetch with a bounded pool instead: the DataHub
# client is HTTP-over-requests, safe for concurrent reads, and GMS is the bottleneck we cap against.
_FETCH_WORKERS = 8

_T = TypeVar("_T")


def _map_urns(urns: list[str], fn: Callable[[str], _T]) -> list[_T]:
    """Apply `fn` to every urn with bounded parallelism, preserving input order. `fn` owns its own
    error handling — this helper only schedules; a per-urn failure is that call's to swallow."""
    if not urns:
        return []
    with ThreadPoolExecutor(
        max_workers=min(_FETCH_WORKERS, len(urns)), thread_name_prefix="airlock-compile"
    ) as pool:
        return list(pool.map(fn, urns))


def _domain_filter(client: Any, domains: list[str]) -> list[str]:
    """Resolve configured domain names to their URNs.

    A URN is passed through untouched, because DataHub often assigns domains a GUID rather than a
    readable id and an operator who already knows it should not have to look up a name. A name that
    matches nothing raises rather than silently narrowing the catalog to nothing: an empty filter
    would compile an empty policy, which denies every query - fail-closed, but for a reason nobody
    could diagnose from the outside.
    """
    resolved: list[str] = []
    for name in domains:
        if name.startswith("urn:li:domain:"):
            resolved.append(name)
            continue
        result = client.execute_graphql(_DOMAIN_QUERY, variables={"name": name})
        matches = [
            r["entity"]["urn"]
            for r in result["search"]["searchResults"]
            if ((r["entity"].get("properties") or {}).get("name") or "").lower() == name.lower()
        ]
        if not matches:
            raise SnapshotUnavailableError(
                f"datahub.domains lists {name!r}, which is not a domain in this DataHub. "
                "Check the spelling in the DataHub UI, or use the domain's urn."
            )
        resolved += matches
    return resolved


def _list_dataset_urns(
    client: Any, platform_urn: str, domains: list[str] | None = None
) -> list[str]:
    filters: list[dict[str, Any]] = [{"field": "platform", "values": [platform_urn]}]
    if domains:
        filters.append({"field": "domains", "values": _domain_filter(client, domains)})
    urns: list[str] = []
    start, count = 0, 200
    while True:
        result = client.execute_graphql(
            _LIST_QUERY, variables={"and": filters, "start": start, "count": count}
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

    def one(urn: str) -> tuple[str, tuple[str, ...]]:
        try:
            related = client.get_related_entities(
                entity_urn=urn, relationship_types=["DownstreamOf"], direction=direction
            )
            return urn, tuple(entry.urn for entry in related)
        except Exception as exc:
            log.warning("lineage.fetch_failed", urn=urn, detail=str(exc))
            return urn, ()

    return {urn: edges for urn, edges in _map_urns(urns, one) if edges}


def _fetch_column_lineage(client: Any, urns: list[str]) -> dict[str, tuple[str, ...]]:
    """Fine-grained (column-level) upstream edges: a downstream schemaField URN mapped to the field
    URNs it derives from, read from each dataset's UpstreamLineage aspect. This is what lets Airlock
    inherit a classification onto a derived column the catalog never tagged. Best-effort: a lineage
    read failing degrades propagation for that dataset, it does not fail the snapshot."""
    from datahub.metadata.schema_classes import UpstreamLineageClass

    def one(urn: str) -> list[tuple[str, tuple[str, ...]]]:
        try:
            aspect = client.get_aspect(entity_urn=urn, aspect_type=UpstreamLineageClass)
        except Exception as exc:
            log.warning("column_lineage.fetch_failed", urn=urn, detail=str(exc))
            return []
        return [
            (downstream, tuple(fine.upstreams or []))
            for fine in (aspect.fineGrainedLineages if aspect else None) or []
            for downstream in fine.downstreams or []
        ]

    edges: dict[str, list[str]] = {}
    for pairs in _map_urns(urns, one):
        for downstream, ups in pairs:
            edges.setdefault(downstream, []).extend(ups)
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
