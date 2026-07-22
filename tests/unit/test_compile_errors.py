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


def test_is_gms_config_accepts_gms_json_and_rejects_others() -> None:
    from airlock.policy.compile import _is_gms_config

    assert _is_gms_config('{"noCode":"true","versions":{}}')
    assert _is_gms_config('{"statsCollectionEnabled":true}')
    assert not _is_gms_config("<!doctype html><html>...")  # a frontend / proxy / SigNoz on the port
    assert not _is_gms_config('{"unrelated":"service"}')  # JSON, but not GMS
    assert not _is_gms_config("")


def test_ping_rejects_a_non_datahub_service(monkeypatch) -> None:
    # A 200 from something that is not GMS - the classic port collision - must raise, not pass, or
    # doctor reports "DataHub reachable" for a service that cannot answer a single GraphQL query.
    import httpx

    from airlock.config import AirlockConfig
    from airlock.policy.compile import NotDataHubError, ping

    cfg = AirlockConfig.model_validate(
        {
            "datahub": {"url": "http://localhost:8080"},
            "warehouse": {"kind": "duckdb", "dsn": "x.duckdb"},
            "rules": [{"id": "r", "match": {"tag": "PII"}, "action": {"mask": "auto"}}],
            "principals": [{"name": "a", "key": "k"}],
            "audit": {"jsonl": "a.jsonl", "datahub_writeback": False},
        }
    )

    class _Resp:
        text = "<!doctype html><html>SigNoz</html>"

        def raise_for_status(self) -> None:
            return None

    monkeypatch.setattr(httpx, "get", lambda *_a, **_k: _Resp())
    with pytest.raises(NotDataHubError):
        ping(cfg)
