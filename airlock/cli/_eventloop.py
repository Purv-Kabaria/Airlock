"""Pick an event loop the configured warehouse driver can actually run on.

psycopg's async mode refuses the ProactorEventLoop that asyncio selects by default on Windows, so a
`kind: postgres` gateway raises `InterfaceError: Psycopg cannot use the 'ProactorEventLoop'` at the
first query on every Windows machine. The demo warehouse is DuckDB, so no demo or CI run exercised
that path and the break was invisible until someone pointed Airlock at Postgres from Windows.

Scoped to the drivers that need it rather than set for everyone: the selector loop caps at 512
sockets on Windows, which is ample for a bounded connection pool but a pointless downgrade for
backends that never open an async socket (DuckDB and SQLite run their driver on worker threads).
"""

from __future__ import annotations

import asyncio
import sys

# Warehouse kinds whose driver speaks asyncio natively and so must share the loop with Airlock.
_NEEDS_SELECTOR_LOOP = frozenset({"postgres"})


def select_event_loop_for(kind: str) -> None:
    """Set the process event-loop policy for `kind`. No-op off Windows; safe to call repeatedly.

    Must run before the first loop is created - a policy set after `asyncio.run` has started has no
    effect on the loop already running.
    """
    if sys.platform != "win32" or kind not in _NEEDS_SELECTOR_LOOP:
        return
    # Resolved by name: the class only exists on Windows, and a direct reference would not type-check
    # on the Linux and macOS legs of the CI matrix.
    policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
    if policy is not None:
        asyncio.set_event_loop_policy(policy())
