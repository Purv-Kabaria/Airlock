"""The masking salt must reach the warehouse but never ride back out.

The `hash` strategy is a keyed hash: its privacy rests on the salt being a secret the agent does not
have. It is rendered as a literal in the SQL because the warehouse computes the hash, so the salt is
unavoidably in `executed_sql`. Everything downstream of execution — the envelope the agent reads, the
audit record, the DataHub usage write-back — must use `display_sql`, where the salt is redacted, or
the agent is handed the very secret the strategy defends against.
"""

from __future__ import annotations

from tests.unit.conftest import build_graph

from airlock.analyzer.resolve import resolve
from airlock.analyzer.rewrite import _SALT_PLACEHOLDER, rewrite
from airlock.config import AirlockConfig
from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.policy.store import SnapshotStore

_SALT = "super-secret-do-not-leak"


def _rewrite(sql: str):
    graph = build_graph()
    resolved = resolve(sql, dialect="duckdb", graph=graph, enforcement=graph.enforcement)
    return rewrite(resolved, graph.principal("finance-agent"), graph, salt=_SALT)


def test_executed_sql_carries_the_real_salt() -> None:
    # payroll.salary is PII -> hash; the warehouse needs the real salt to compute the digest.
    rr = _rewrite("SELECT salary FROM payroll")
    assert _SALT in rr.executed_sql


def test_display_sql_redacts_the_salt() -> None:
    rr = _rewrite("SELECT salary FROM payroll")
    assert _SALT not in rr.display_sql
    assert _SALT_PLACEHOLDER in rr.display_sql
    # Same query, otherwise identical: only the salt literal differs between the two forms.
    assert rr.display_sql == rr.executed_sql.replace(f"'{_SALT}'", _SALT_PLACEHOLDER)


def test_unsalted_query_has_identical_forms() -> None:
    # No hash mask -> no salt literal -> nothing to redact; the two forms match exactly.
    rr = _rewrite("SELECT emp_id FROM payroll")
    assert rr.display_sql == rr.executed_sql
    assert _SALT not in rr.display_sql


def _salted_config(dsn: str, jsonl: str) -> AirlockConfig:
    return AirlockConfig.model_validate(
        {
            "datahub": {"url": "http://localhost:8080"},
            "warehouse": {"kind": "duckdb", "dsn": dsn},
            "enforcement": {"mode": "enforce"},
            "rules": [{"id": "pii", "match": {"tag": "PII"}, "action": {"mask": "auto"}}],
            "principals": [
                {"name": "finance-agent", "key": "f", "scopes": {"domains": ["Finance"]}}
            ],
            "masking": {"salt": _SALT},
            "audit": {"jsonl": jsonl, "datahub_writeback": False},
        }
    )


def test_gateway_envelope_and_audit_never_carry_the_salt(tmp_path, warehouse) -> None:
    # dry_run exercises the same plan path the executed path builds the envelope from, without a
    # warehouse round-trip -- enough to prove the envelope and the audit record it feeds are redacted.
    from airlock.audit.record import AuditRecord

    cfg = _salted_config(warehouse, str(tmp_path / "a.jsonl"))
    store = SnapshotStore(str(tmp_path / "s.sqlite"))
    store.install(build_graph())
    gateway = Gateway(cfg, store, DuckdbAdapter(warehouse), [])
    try:
        env = gateway.dry_run(
            "SELECT salary FROM payroll", "finance-agent"
        )  # salary is PII -> hash
        assert env.executed_sql is not None
        assert _SALT not in env.executed_sql  # the agent must not receive the secret
        assert _SALT_PLACEHOLDER in env.executed_sql
        record = AuditRecord.from_envelope(env, latency_ms=0.0, warehouse="duckdb")
        assert record.executed_sql is not None and _SALT not in record.executed_sql
    finally:
        import asyncio

        asyncio.run(gateway.aclose())
