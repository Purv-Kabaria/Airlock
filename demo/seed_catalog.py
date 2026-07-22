"""Ingest the demo retail catalog into DataHub through the real ingestion API.

This is what makes DataHub load-bearing: schemas, column tags (PII), glossary terms
(Classification.SSN), deprecation, certification, domains, ownership, and lineage all come from
here and drive enforcement. Idempotent - emitting the same aspects again just converges.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datahub.emitter.mce_builder import (
    make_dataset_urn,
    make_domain_urn,
    make_tag_urn,
    make_term_urn,
)
from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph
from datahub.metadata.schema_classes import (
    AuditStampClass,
    DatasetLineageTypeClass,
    DateTypeClass,
    DeprecationClass,
    DomainPropertiesClass,
    DomainsClass,
    FineGrainedLineageClass,
    FineGrainedLineageDownstreamTypeClass,
    FineGrainedLineageUpstreamTypeClass,
    GlobalTagsClass,
    GlossaryTermAssociationClass,
    GlossaryTermInfoClass,
    GlossaryTermsClass,
    NumberTypeClass,
    OtherSchemaClass,
    OwnerClass,
    OwnershipClass,
    OwnershipTypeClass,
    SchemaFieldClass,
    SchemaFieldDataTypeClass,
    SchemaMetadataClass,
    StringTypeClass,
    TagAssociationClass,
    TagPropertiesClass,
    UpstreamClass,
    UpstreamLineageClass,
)
from demo.catalog import DATASETS, PLATFORM, Dataset

_ACTOR = "urn:li:corpuser:airlock"
_NOW = int(time.time() * 1000)
_STAMP = AuditStampClass(time=_NOW, actor=_ACTOR)


def _field_type(sql_type: str) -> SchemaFieldDataTypeClass:
    upper = sql_type.upper()
    if any(t in upper for t in ("INT", "DOUBLE", "DECIMAL", "FLOAT", "NUM")):
        return SchemaFieldDataTypeClass(type=NumberTypeClass())
    if "DATE" in upper or "TIME" in upper:
        return SchemaFieldDataTypeClass(type=DateTypeClass())
    return SchemaFieldDataTypeClass(type=StringTypeClass())


def _dataset_mcps(ds: Dataset) -> list[MetadataChangeProposalWrapper]:
    urn = make_dataset_urn(platform=PLATFORM, name=ds.name, env="PROD")
    fields = [
        SchemaFieldClass(
            fieldPath=c.name,
            type=_field_type(c.type),
            nativeDataType=c.type,
            globalTags=GlobalTagsClass(
                tags=[TagAssociationClass(tag=make_tag_urn(t)) for t in c.tags]
            )
            if c.tags
            else None,
            glossaryTerms=GlossaryTermsClass(
                terms=[GlossaryTermAssociationClass(urn=make_term_urn(t)) for t in c.terms],
                auditStamp=_STAMP,
            )
            if c.terms
            else None,
        )
        for c in ds.columns
    ]
    aspects: list[object] = [
        SchemaMetadataClass(
            schemaName=ds.name,
            platform=f"urn:li:dataPlatform:{PLATFORM}",
            version=0,
            hash="",
            platformSchema=OtherSchemaClass(rawSchema=""),
            fields=fields,
        ),
        DomainsClass(domains=[make_domain_urn(ds.domain)]),
    ]
    if ds.certification == "CERTIFIED":
        aspects.append(GlobalTagsClass(tags=[TagAssociationClass(tag=make_tag_urn("Certified"))]))
    if ds.lifecycle == "DEPRECATED":
        aspects.append(
            DeprecationClass(deprecated=True, note="Superseded by dim_users.", actor=_ACTOR)
        )
    if ds.owners:
        aspects.append(
            OwnershipClass(
                owners=[OwnerClass(owner=o, type=OwnershipTypeClass.DATAOWNER) for o in ds.owners]
            )
        )
    return [MetadataChangeProposalWrapper(entityUrn=urn, aspect=a) for a in aspects]


def _field_urn(dataset_urn: str, column: str) -> str:
    return f"urn:li:schemaField:({dataset_urn},{column})"


def _lineage_mcps() -> list[MetadataChangeProposalWrapper]:
    """One UpstreamLineage aspect per downstream dataset, merging table-level edges (declared as
    `downstream` on the upstream) with column-level edges (declared as `derives_from` on each
    downstream column). Column lineage is what lets Airlock inherit a classification onto a derived
    column the catalog never tagged."""
    table_upstreams: dict[str, set[str]] = {}
    fine: dict[str, list[FineGrainedLineageClass]] = {}
    for ds in DATASETS:
        down_urn = make_dataset_urn(platform=PLATFORM, name=ds.name, env="PROD")
        for downstream in ds.downstream:
            up_urn = make_dataset_urn(platform=PLATFORM, name=ds.name, env="PROD")
            d_urn = make_dataset_urn(platform=PLATFORM, name=downstream, env="PROD")
            table_upstreams.setdefault(d_urn, set()).add(up_urn)
        for col in ds.columns:
            for ref in col.derives_from:
                up_name, up_col = ref.split(".")
                up_urn = make_dataset_urn(platform=PLATFORM, name=up_name, env="PROD")
                table_upstreams.setdefault(down_urn, set()).add(up_urn)
                fine.setdefault(down_urn, []).append(
                    FineGrainedLineageClass(
                        upstreamType=FineGrainedLineageUpstreamTypeClass.FIELD_SET,
                        downstreamType=FineGrainedLineageDownstreamTypeClass.FIELD,
                        upstreams=[_field_urn(up_urn, up_col)],
                        downstreams=[_field_urn(down_urn, col.name)],
                    )
                )
    mcps: list[MetadataChangeProposalWrapper] = []
    for entity_urn in sorted(set(table_upstreams) | set(fine)):
        mcps.append(
            MetadataChangeProposalWrapper(
                entityUrn=entity_urn,
                aspect=UpstreamLineageClass(
                    upstreams=[
                        UpstreamClass(dataset=u, type=DatasetLineageTypeClass.TRANSFORMED)
                        for u in sorted(table_upstreams.get(entity_urn, set()))
                    ],
                    fineGrainedLineages=fine.get(entity_urn) or None,
                ),
            )
        )
    return mcps


def _vocab_mcps() -> list[MetadataChangeProposalWrapper]:
    """Definitions for the tags, term, and domains so they render with names in the UI."""
    return [
        MetadataChangeProposalWrapper(
            entityUrn=make_tag_urn("PII"),
            aspect=TagPropertiesClass(
                name="PII", description="Personally identifiable information."
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=make_tag_urn("Certified"),
            aspect=TagPropertiesClass(name="Certified", description="Reviewed, production-ready."),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=make_term_urn("Classification.SSN"),
            aspect=GlossaryTermInfoClass(
                name="Classification.SSN",
                definition="US Social Security Number. Never exposed through Airlock.",
                termSource="INTERNAL",
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=make_domain_urn("Marketing"),
            aspect=DomainPropertiesClass(name="Marketing"),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=make_domain_urn("Finance"),
            aspect=DomainPropertiesClass(name="Finance"),
        ),
    ]


def seed() -> None:
    url = os.environ.get("DATAHUB_GMS_URL", "http://localhost:18080")
    token = os.environ.get("DATAHUB_GMS_TOKEN") or None
    client = DataHubGraph(DatahubClientConfig(server=url, token=token))

    mcps: list[MetadataChangeProposalWrapper] = list(_vocab_mcps())
    for ds in DATASETS:
        mcps += _dataset_mcps(ds)
    mcps += _lineage_mcps()

    for mcp in mcps:
        client.emit_mcp(mcp)
    print(f"seeded {len(DATASETS)} datasets and {len(mcps)} aspects into DataHub at {url}")


if __name__ == "__main__":
    seed()
