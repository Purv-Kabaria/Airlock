"""Optional OpenTelemetry sink: decision latency, verdict counts, deny rate.

Off by default. When `audit.otel.enabled` is set and the OTel SDK is installed, this records a
histogram of decision latency and counters for verdicts and denials. It never fails a request:
if the SDK is absent or export fails, the sink degrades to a no-op with a single warning.
"""

from __future__ import annotations

from airlock.audit.record import AuditRecord
from airlock.logging import get_logger

log = get_logger("airlock.audit.otel")


class OtelSink:
    background = True  # runs off the request path; see Gateway._audit

    def __init__(self, endpoint: str | None = None) -> None:
        self._enabled = False
        try:
            from opentelemetry import metrics
            from opentelemetry.sdk.metrics import MeterProvider

            metrics.set_meter_provider(MeterProvider())
            meter = metrics.get_meter("airlock")
            self._latency = meter.create_histogram("airlock.decision.latency_ms")
            self._verdicts = meter.create_counter("airlock.verdicts")
            self._denials = meter.create_counter("airlock.denials")
            self._enabled = True
        except Exception as exc:
            log.warning("otel.disabled", detail=str(exc))

    async def write(self, record: AuditRecord) -> None:
        if not self._enabled:
            return
        self._latency.record(record.latency_ms, {"principal": record.principal})
        self._verdicts.add(len(record.verdicts), {"principal": record.principal})
        if record.denied:
            self._denials.add(1, {"principal": record.principal})

    async def close(self) -> None:
        return None
