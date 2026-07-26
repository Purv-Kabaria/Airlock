"""Integration-suite setup.

Anything that creates its own event loop - a test runner, or an application embedding Airlock - owns
the loop policy, because a policy set after the loop exists has no effect. Airlock's CLI does this
for you (`airlock/cli/_eventloop.py`); here the test runner is the one creating the loop, so the
suite does what an embedder on Windows must do. Without it, psycopg refuses the ProactorEventLoop
that asyncio picks by default on Windows.
"""

from __future__ import annotations

from airlock.cli._eventloop import select_event_loop_for

select_event_loop_for("postgres")
