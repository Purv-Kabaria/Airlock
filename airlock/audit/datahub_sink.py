"""DataHub write-back: the loop-closing sink. The only module that writes to DataHub.

Every decision updates the datasets it touched with structured properties the governance team can
see and query in DataHub itself:
  * airlock.lastAgentAccess   - "<iso-ts> by <principal>"
  * airlock.lastPolicySnapshot - the snapshot hash that made the decision
  * airlock.deniedAttempts    - a cumulative count, incremented on every denial
and appends a one-line institutional-memory ledger element. Write-back is off the request path
and best-effort: any failure is logged and never fails a query (README §12). Property definitions
are created idempotently on first use so the properties render on the dataset page.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from airlock.audit.record import AuditRecord
from airlock.config import AirlockConfig
from airlock.logging import get_logger

log = get_logger("airlock.audit.datahub")

_ACTOR = "urn:li:corpuser:airlock"
_ENTITY_TYPES = ["urn:li:entityType:datahub.dataset"]
_PROP_LAST_ACCESS = "airlock.lastAgentAccess"
_PROP_SNAPSHOT = "airlock.lastPolicySnapshot"
_PROP_DENIED = "airlock.deniedAttempts"


class DatahubLedgerSink:
    background = True  # runs off the request path; see Gateway._audit

    def __init__(self, config: AirlockConfig) -> None:
        self._config = config
        self._client: Any | None = None
        self._defined = False
        # Serialize write-backs: each one is a read-modify-write on per-dataset structured
        # properties (the denied-attempts counter), so concurrent writes would race and lose
        # increments. This is off the request path, so serializing costs nothing that matters.
        self._lock = asyncio.Lock()

    async def write(self, record: AuditRecord) -> None:
        try:
            async with self._lock:
                await asyncio.to_thread(self._write_sync, record)
        except Exception as exc:
            log.warning("writeback.failed", request_id=record.request_id, detail=str(exc))

    def _write_sync(self, record: AuditRecord) -> None:
        client = self._ensure_client()
        self._ensure_definitions(client)
        for urn in record.dataset_urns:
            self._write_dataset(client, urn, record)

    def _write_dataset(self, client: Any, urn: str, record: AuditRecord) -> None:
        from datahub.emitter.mcp import MetadataChangeProposalWrapper
        from datahub.metadata.schema_classes import (
            AuditStampClass,
            InstitutionalMemoryClass,
            InstitutionalMemoryMetadataClass,
            StructuredPropertiesClass,
            StructuredPropertyValueAssignmentClass,
        )

        stamp = AuditStampClass(time=int(time.time() * 1000), actor=_ACTOR)
        denied_count = self._next_denied_count(client, urn, record.denied)
        assignments = [
            StructuredPropertyValueAssignmentClass(
                propertyUrn=_prop_urn(_PROP_LAST_ACCESS),
                values=[f"{record.ts} by {record.principal}"],
            ),
            StructuredPropertyValueAssignmentClass(
                propertyUrn=_prop_urn(_PROP_SNAPSHOT), values=[record.snapshot_hash or "unknown"]
            ),
            StructuredPropertyValueAssignmentClass(
                propertyUrn=_prop_urn(_PROP_DENIED), values=[float(denied_count)]
            ),
        ]
        client.emit_mcp(
            MetadataChangeProposalWrapper(
                entityUrn=urn, aspect=StructuredPropertiesClass(properties=assignments)
            )
        )

        summary = (
            f"{record.principal} ran {record.request_id} ({record.status}); "
            f"verdicts: {', '.join(v.code for v in record.verdicts) or 'none'}"
        )
        elements = self._existing_memory(client, urn)
        elements.append(
            InstitutionalMemoryMetadataClass(
                url=f"{self._config.datahub.url.rstrip('/')}/airlock/{record.request_id}",
                description=f"airlock: {summary}",
                createStamp=stamp,
            )
        )
        client.emit_mcp(
            MetadataChangeProposalWrapper(
                entityUrn=urn, aspect=InstitutionalMemoryClass(elements=elements[-50:])
            )
        )

    def _next_denied_count(self, client: Any, urn: str, denied: bool) -> int:
        if not denied:
            return self._current_denied(client, urn)
        return self._current_denied(client, urn) + 1

    def _current_denied(self, client: Any, urn: str) -> int:
        from datahub.metadata.schema_classes import StructuredPropertiesClass

        current = client.get_aspect(entity_urn=urn, aspect_type=StructuredPropertiesClass)
        if current is None:
            return 0
        for prop in current.properties:
            if prop.propertyUrn == _prop_urn(_PROP_DENIED) and prop.values:
                try:
                    return int(float(prop.values[0]))
                except (TypeError, ValueError):
                    return 0
        return 0

    def _existing_memory(self, client: Any, urn: str) -> list[Any]:
        from datahub.metadata.schema_classes import InstitutionalMemoryClass

        current = client.get_aspect(entity_urn=urn, aspect_type=InstitutionalMemoryClass)
        return list(current.elements) if current is not None else []

    def _ensure_definitions(self, client: Any) -> None:
        if self._defined:
            return
        from datahub.emitter.mcp import MetadataChangeProposalWrapper
        from datahub.metadata.schema_classes import StructuredPropertyDefinitionClass

        defs = [
            (_PROP_LAST_ACCESS, "urn:li:dataType:datahub.string", "Airlock last agent access"),
            (_PROP_SNAPSHOT, "urn:li:dataType:datahub.string", "Airlock policy snapshot"),
            (_PROP_DENIED, "urn:li:dataType:datahub.number", "Airlock denied attempts"),
        ]
        for qualified, value_type, display in defs:
            client.emit_mcp(
                MetadataChangeProposalWrapper(
                    entityUrn=_prop_urn(qualified),
                    aspect=StructuredPropertyDefinitionClass(
                        qualifiedName=qualified,
                        valueType=value_type,
                        entityTypes=_ENTITY_TYPES,
                        displayName=display,
                    ),
                )
            )
        self._defined = True

    def _ensure_client(self) -> Any:
        if self._client is None:
            from datahub.ingestion.graph.client import DatahubClientConfig, DataHubGraph

            self._client = DataHubGraph(
                DatahubClientConfig(
                    server=self._config.datahub.url, token=self._config.datahub.token
                )
            )
        return self._client

    async def close(self) -> None:
        return None


def _prop_urn(qualified: str) -> str:
    return f"urn:li:structuredProperty:{qualified}"
