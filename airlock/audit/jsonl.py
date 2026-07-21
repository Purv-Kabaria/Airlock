"""Append-only JSONL audit sink. Writes are line-atomic: a kill can never corrupt the log.

Each record is serialized to one line and appended under a lock, off the event loop. A single
`write()` emits exactly one newline-terminated line, so a crash mid-run leaves a truncated file
at worst a whole-line boundary, never a half-written record (README edge 26).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from airlock.audit.record import AuditRecord
from airlock.logging import get_logger

log = get_logger("airlock.audit.jsonl")


class JsonlSink:
    background = False  # local and line-atomic; awaited inline so every answer is logged first

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def write(self, record: AuditRecord) -> None:
        line = record.model_dump_json() + "\n"
        async with self._lock:
            await asyncio.to_thread(self._append, line)

    def _append(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    async def close(self) -> None:
        return None
