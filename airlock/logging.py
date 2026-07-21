"""structlog wiring. Log lines are events with fields, never interpolated sentences.

    log.info("decision.made", request_id=rid, principal=p.name, verdicts=n, latency_ms=ms)

renders (dev) or emits JSON (serve). Configure once at process start via `configure`.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_configured = False


def configure(*, json_logs: bool = False, level: str = "INFO") -> None:
    """Wire structlog + stdlib logging. Idempotent; safe to call more than once."""
    global _configured
    if _configured:
        return

    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level.upper())

    # Quiet chatty third-party loggers; Airlock surfaces its own clear errors.
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # The connection-pool retry chatter ("Retrying (Retry(total=2, ...))") is WARNING-level and not
    # actionable - Airlock reports its own named DataHub error when the retries are exhausted.
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]
    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    if not _configured:
        configure()
    return structlog.get_logger(name)  # type: ignore[no-any-return]
