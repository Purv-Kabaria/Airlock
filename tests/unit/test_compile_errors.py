"""DataHub failures compile into one actionable line, never the urllib3 connection-pool dump."""

from __future__ import annotations

import pytest

from airlock.policy.compile import _datahub_failure


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            "HTTPConnectionPool(host='localhost', port=9999): Max retries exceeded with url: "
            "/api/graphql (Caused by NewConnectionError('... actively refused it'))",
            "connection refused",
        ),
        ("HTTPConnectionPool(...): Read timed out. (read timeout=15.0)", "timed out"),
        ("401 Client Error: Unauthorized for url: /api/graphql", "authentication rejected"),
        ("403 Client Error: Forbidden", "access forbidden"),
    ],
)
def test_datahub_failure_is_one_actionable_line(raw: str, expected: str) -> None:
    msg = _datahub_failure(Exception(raw))
    assert expected in msg
    assert "\n" not in msg  # never the multi-line dump
    assert "HTTPConnectionPool" not in msg  # library internals stay in the log, not on the wire


def test_unrecognized_failure_falls_back_to_a_terse_first_line() -> None:
    msg = _datahub_failure(Exception("something odd\nwith a second line\nand a third"))
    assert msg == "something odd"
