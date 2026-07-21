"""The audit record and the Sink protocol.

One record per decision, carrying the policy-snapshot hash so any decision can be tied to the
exact policy version that produced it (README §"Audit & write-back"). Records are the only thing
sinks ever see; the wire envelope stays separate.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from airlock.engine.verdicts import Envelope, Verdict


class VerdictDigest(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    action: str
    subject: str


class AuditRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str
    ts: str
    principal: str
    status: str
    original_sql: str
    executed_sql: str | None
    snapshot_hash: str | None
    verdicts: list[VerdictDigest]
    subjects: list[str]
    row_count: int | None
    truncated: bool
    latency_ms: float
    coalesced: bool
    warehouse: str
    dataset_urns: list[str] = []
    denied: bool = False
    # dataset urn -> columns this query read. Drives the DataHub usage write-back, and makes the
    # local log answer "which columns has this agent actually read" without re-parsing the SQL.
    column_reads: dict[str, list[str]] = {}

    @classmethod
    def from_envelope(
        cls,
        envelope: Envelope,
        *,
        latency_ms: float,
        warehouse: str,
        coalesced: bool = False,
        dataset_urns: list[str] | None = None,
        column_reads: Iterable[tuple[str, str]] = (),
    ) -> AuditRecord:
        reads: dict[str, list[str]] = {}
        for urn, column in column_reads:
            reads.setdefault(urn, []).append(column)
        return cls(
            request_id=envelope.request_id,
            ts=datetime.now(UTC).isoformat(),
            principal=envelope.principal,
            status=str(envelope.status),
            original_sql=envelope.original_sql,
            executed_sql=envelope.executed_sql,
            snapshot_hash=envelope.policy_snapshot,
            verdicts=[_digest(v) for v in envelope.verdicts],
            subjects=sorted({v.subject for v in envelope.verdicts}),
            row_count=envelope.row_count,
            truncated=envelope.truncated,
            latency_ms=round(latency_ms, 3),
            coalesced=coalesced,
            warehouse=warehouse,
            dataset_urns=sorted(set(dataset_urns or [])),
            denied=str(envelope.status) in ("denied", "error"),
            column_reads={urn: sorted(cols) for urn, cols in sorted(reads.items())},
        )


def _digest(v: Verdict) -> VerdictDigest:
    return VerdictDigest(code=str(v.code), action=v.action, subject=v.subject)


class Sink(Protocol):
    # True for sinks that do slow, remote I/O (DataHub write-back, OTel export); the gateway runs
    # those off the request path. Absent/False means local and fast enough to await inline.
    background: bool

    async def write(self, record: AuditRecord) -> None: ...

    async def close(self) -> None: ...
