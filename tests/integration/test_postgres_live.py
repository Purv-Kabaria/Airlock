"""End-to-end conformance against a real Postgres server.

Skipped unless AIRLOCK_TEST_POSTGRES_DSN is set, because it needs a live server:

    docker run -d --name airlock-pg -e POSTGRES_PASSWORD=airlock -e POSTGRES_USER=airlock \
        -e POSTGRES_DB=airlockdemo -p 55432:5432 postgres:16-alpine
    AIRLOCK_TEST_POSTGRES_DSN=postgresql://airlock:airlock@localhost:55432/airlockdemo \
        uv run pytest tests/integration -q

What it proves that no unit test can: the masking templates, written once in the canonical dialect,
render into *Postgres* SQL that Postgres actually executes (`POSITION`/`SUBSTRING ... FROM ... FOR`,
not DuckDB's `STRPOS`/`SUBSTRING(x, 1, 1)`), the async driver shares Airlock's event loop, and the
introspection tools read a real information_schema. This is the "adding a warehouse is a connection,
not a policy port" claim, checked rather than asserted.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

import pytest

from airlock.config import AirlockConfig
from airlock.gateway import Gateway
from airlock.policy.graph import (
    ColumnFact,
    DatasetFacts,
    EnforcementSettings,
    PolicyGraph,
    Principal,
    Scope,
)
from airlock.policy.rules import ActionKind, ActionSpec, Match, Rule
from airlock.policy.store import SnapshotStore
from airlock.urns import dataset_urn, field_urn

DSN = os.environ.get("AIRLOCK_TEST_POSTGRES_DSN", "")
pytestmark = pytest.mark.skipif(
    not DSN, reason="set AIRLOCK_TEST_POSTGRES_DSN to run (see module docstring)"
)

DIM = dataset_urn("postgres", "dim_users")
SALT = "postgres-conformance-salt"


def _col(
    name: str, dtype: str, tags: tuple[str, ...] = (), terms: tuple[str, ...] = ()
) -> ColumnFact:
    return ColumnFact(
        name=name,
        urn=field_urn(DIM, name),
        data_type=dtype,
        tags=frozenset(tags),
        glossary_terms=frozenset(terms),
    )


def _graph() -> PolicyGraph:
    dataset = DatasetFacts(
        urn=DIM,
        platform="postgres",
        name="dim_users",
        env="PROD",
        columns=(
            _col("id", "BIGINT"),
            _col("name", "TEXT"),
            _col("email", "TEXT", tags=("PII",)),
            _col("ssn", "TEXT", terms=("Classification.SSN",)),
            _col("salary", "NUMERIC", tags=("PII",)),
        ),
        domain="Marketing",
    )
    return PolicyGraph.build(
        datasets={DIM: dataset},
        lineage={},
        column_lineage={},
        rules=(
            Rule.make("pii", Match(tag="PII"), ActionSpec(ActionKind.MASK, "auto")),
            Rule.make(
                "ssn", Match(glossary_term="Classification.SSN"), ActionSpec(ActionKind.DENY)
            ),
        ),
        enforcement=EnforcementSettings(),
        principals={"agent": Principal("agent", Scope(domains=frozenset({"Marketing"})))},
        compiled_at=datetime.now(UTC),
        source_url="http://localhost:18080",
    )


async def _seed() -> None:
    import psycopg

    async with await psycopg.AsyncConnection.connect(DSN, autocommit=True) as conn:
        await conn.execute("DROP TABLE IF EXISTS dim_users")
        await conn.execute(
            "CREATE TABLE dim_users (id BIGINT, name TEXT, email TEXT, ssn TEXT, salary NUMERIC)"
        )
        await conn.execute(
            "INSERT INTO dim_users VALUES (1,'Ada Lovelace','ada@corp.com','111-22-3333',120000),"
            "(2,'Bo Diddley','bo@x.io','999-88-7777',95000)"
        )


def _gateway(tmp_path) -> Gateway:
    from airlock.exec.postgres_adapter import PostgresAdapter

    config = AirlockConfig.model_validate(
        {
            "datahub": {"url": "http://localhost:18080"},
            "warehouse": {"kind": "postgres", "dsn": DSN},
            "rules": [{"id": "pii", "match": {"tag": "PII"}, "action": {"mask": "auto"}}],
            "principals": [{"name": "agent", "key": "k", "scopes": {"domains": ["Marketing"]}}],
            "masking": {"salt": SALT},
            "audit": {"jsonl": str(tmp_path / "audit.jsonl"), "datahub_writeback": False},
        }
    )
    store = SnapshotStore(str(tmp_path / "snapshot.sqlite"))
    store.install(_graph())
    return Gateway(config, store, PostgresAdapter(DSN, pool_size=2), [])


async def test_masking_executes_natively_on_postgres(tmp_path) -> None:
    await _seed()
    gateway = _gateway(tmp_path)
    try:
        env = await gateway.run_query(
            "SELECT name, email, ssn, salary FROM dim_users ORDER BY id", "agent"
        )
        assert env.rows, "no rows came back from Postgres"
        row = env.rows[0]
        assert row["name"] == "Ada Lovelace"  # unclassified column is byte-identical
        assert row["email"] == "a***@corp.com"  # partial_email, rendered in the postgres dialect
        assert row["ssn"] is None  # denied column nulled
        assert isinstance(row["salary"], str) and len(row["salary"]) == 32  # salted hash

        sql = env.executed_sql or ""
        assert "POSITION(" in sql.upper(), f"not transpiled to postgres: {sql}"
        assert "STRPOS" not in sql.upper(), f"leaked the canonical dialect: {sql}"
        assert SALT not in sql, "the masking salt must never reach the envelope"
    finally:
        await gateway.aclose()


async def test_a_dropped_client_stops_the_query_inside_postgres() -> None:
    """README edge 23, checked against the server rather than assumed.

    Cancelling the caller has to reach Postgres, or a disconnected agent leaves a statement running
    and billing. pg_stat_activity is the only honest witness for that.
    """
    import psycopg

    from airlock.exec.postgres_adapter import PostgresAdapter

    async def sleeping_queries() -> list[str]:
        async with await psycopg.AsyncConnection.connect(DSN, autocommit=True) as conn:
            cur = await conn.execute(
                "SELECT query FROM pg_stat_activity WHERE state = 'active' "
                "AND query LIKE '%pg_sleep%' AND pid <> pg_backend_pid()"
            )
            return [row[0] for row in await cur.fetchall()]

    adapter = PostgresAdapter(DSN, pool_size=2)
    try:
        task = asyncio.ensure_future(adapter.run("SELECT pg_sleep(60)", timeout=120, row_limit=10))
        await asyncio.sleep(2.0)
        assert await sleeping_queries(), "the query never reached the server"

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        await asyncio.sleep(2.0)  # let Postgres process the cancellation request
        assert not await sleeping_queries(), "the statement survived the disconnect"
    finally:
        await adapter.close()


async def test_introspection_reads_the_real_information_schema(tmp_path) -> None:
    await _seed()
    gateway = _gateway(tmp_path)
    try:
        adapter = gateway._adapter
        assert "dim_users" in await adapter.list_tables()
        columns = dict(await adapter.describe_table("dim_users"))
        assert columns["email"] == "text" and columns["salary"] == "numeric"
    finally:
        await gateway.aclose()
