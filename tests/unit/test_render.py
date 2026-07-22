"""The replay renderer reads archived audit records, which outlive the build that wrote them.

A record from an older snapshot can carry a reason code this build no longer allocates, or omit a
field a later version added. `airlock explain` is the command you reach for when something already
went wrong; it must not be the second thing that breaks.
"""

from __future__ import annotations

from airlock.cli.render import _code_title, render_replay

_FULL = {
    "request_id": "req_abc123",
    "ts": "2026-07-21T09:48:42+00:00",
    "principal": "growth-agent",
    "status": "executed_with_modifications",
    "original_sql": "SELECT email FROM dim_users",
    "executed_sql": "SELECT mask(email) FROM dim_users LIMIT 10000",
    "snapshot_hash": "sha256:59ff77489820396518d47fecb476acc2b3d9f844",
    "verdicts": [{"code": "AIRLOCK-110", "action": "mask", "subject": "column:dim_users.email"}],
    "row_count": 4,
    "truncated": False,
    "latency_ms": 40.637,
    "coalesced": False,
    "warehouse": "duckdb",
    "dataset_urns": ["urn:li:dataset:(urn:li:dataPlatform:duckdb,dim_users,PROD)"],
}


def test_renders_a_complete_record() -> None:
    render_replay(dict(_FULL))


def test_renders_a_record_missing_every_optional_field() -> None:
    render_replay({"request_id": "req_abc123"})


def test_survives_an_unknown_status_and_reason_code() -> None:
    record = dict(_FULL, status="from_the_future")
    record["verdicts"] = [{"code": "AIRLOCK-999", "action": "mask", "subject": "column:x.y"}]
    render_replay(record)


def test_code_title_resolves_known_codes_and_tolerates_unknown() -> None:
    assert _code_title("AIRLOCK-110") == "column masked"
    assert _code_title("AIRLOCK-999") == ""
    assert _code_title("") == ""
