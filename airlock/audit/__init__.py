"""Audit pipeline: append-only JSONL, optional OpenTelemetry, and DataHub write-back.

Every decision produces one `AuditRecord`. Sinks run off the request path (README §12); a sink
failure is logged and never fails a query. `audit.datahub_sink` is the only module that writes
to DataHub, closing the loop so agent behavior becomes queryable inside the graph itself.
"""

from airlock.audit.jsonl import JsonlSink
from airlock.audit.record import AuditRecord, Sink

__all__ = ["AuditRecord", "JsonlSink", "Sink"]
