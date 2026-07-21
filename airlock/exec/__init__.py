"""Warehouse adapters. One file per warehouse, all satisfying the WarehouseAdapter protocol.

No adapter-specific logic leaks outside this package; the rest of Airlock speaks only the
protocol. Execution is off the event loop (pooled connections via `asyncio.to_thread`) with a
per-statement timeout and cancellation that reaches the warehouse (README §12).
"""

from airlock.exec.base import QueryResult, WarehouseAdapter, make_adapter

__all__ = ["QueryResult", "WarehouseAdapter", "make_adapter"]
