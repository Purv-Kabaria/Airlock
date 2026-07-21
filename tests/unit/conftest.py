"""Shared fixtures: a hand-built PolicyGraph and a seeded DuckDB warehouse.

Fakes live here, under tests/unit, behind the same types the real implementations satisfy
(README §10). Unit tests never touch the network: the graph is built directly rather than compiled
from DataHub, and the warehouse is a local DuckDB file.
"""

from __future__ import annotations

from datetime import UTC, datetime

import duckdb
import pytest

from airlock.audit.record import AuditRecord
from airlock.policy.graph import (
    ColumnFact,
    DatasetFacts,
    EnforcementSettings,
    PolicyGraph,
    Principal,
    Scope,
)
from airlock.policy.rules import ActionKind, ActionSpec, Match, Rule
from airlock.urns import dataset_urn, field_urn


def _col(ds_urn: str, name: str, dtype: str, tags=(), terms=()) -> ColumnFact:
    return ColumnFact(
        name=name,
        urn=field_urn(ds_urn, name),
        data_type=dtype,
        tags=frozenset(tags),
        glossary_terms=frozenset(terms),
    )


USERS_RAW = dataset_urn("duckdb", "users_raw")
DIM_USERS = dataset_urn("duckdb", "dim_users")
ORDERS = dataset_urn("duckdb", "orders")
PAYROLL = dataset_urn("duckdb", "payroll")


def build_graph(
    *,
    mode: str = "enforce",
    predicate_policy: str = "deny",
    substitution: str = "rewrite",
    compiled_at: datetime | None = None,
) -> PolicyGraph:
    users_raw = DatasetFacts(
        urn=USERS_RAW,
        platform="duckdb",
        name="users_raw",
        env="PROD",
        columns=(
            _col(USERS_RAW, "id", "BIGINT"),
            _col(USERS_RAW, "name", "VARCHAR"),
            _col(USERS_RAW, "email", "VARCHAR", tags=["PII"]),
            _col(USERS_RAW, "ssn", "VARCHAR", terms=["Classification.SSN"]),
        ),
        lifecycle="DEPRECATED",
        domain="Marketing",
        owners=("data-eng",),
    )
    dim_users = DatasetFacts(
        urn=DIM_USERS,
        platform="duckdb",
        name="dim_users",
        env="PROD",
        columns=(
            _col(DIM_USERS, "id", "BIGINT"),
            _col(DIM_USERS, "name", "VARCHAR"),
            _col(DIM_USERS, "email", "VARCHAR", tags=["PII"]),
            _col(DIM_USERS, "ssn", "VARCHAR", terms=["Classification.SSN"]),
        ),
        certification="CERTIFIED",
        domain="Marketing",
    )
    orders = DatasetFacts(
        urn=ORDERS,
        platform="duckdb",
        name="orders",
        env="PROD",
        columns=(
            _col(ORDERS, "id", "BIGINT"),
            _col(ORDERS, "user_id", "BIGINT"),
            _col(ORDERS, "total", "DOUBLE"),
        ),
        domain="Marketing",
    )
    payroll = DatasetFacts(
        urn=PAYROLL,
        platform="duckdb",
        name="payroll",
        env="PROD",
        columns=(
            _col(PAYROLL, "emp_id", "BIGINT"),
            _col(PAYROLL, "salary", "DOUBLE", tags=["PII"]),
        ),
        domain="Finance",
        owners=("finance-team",),
    )
    rules = (
        Rule.make("pii-default", Match(tag="PII"), ActionSpec(ActionKind.MASK, "auto")),
        Rule.make(
            "ssn-deny", Match(glossary_term="Classification.SSN"), ActionSpec(ActionKind.DENY)
        ),
        Rule.make(
            "dep-redirect",
            Match(lifecycle="DEPRECATED"),
            ActionSpec(ActionKind.SUBSTITUTE_CERTIFIED),
        ),
    )
    principals = {
        "growth-agent": Principal("growth-agent", Scope(domains=frozenset({"Marketing"}))),
        "finance-agent": Principal(
            "finance-agent", Scope(domains=frozenset({"Finance"})), row_limit=100000
        ),
        "wide-agent": Principal("wide-agent", Scope()),
    }
    return PolicyGraph.build(
        datasets={USERS_RAW: users_raw, DIM_USERS: dim_users, ORDERS: orders, PAYROLL: payroll},
        lineage={USERS_RAW: (DIM_USERS,)},
        rules=rules,
        enforcement=EnforcementSettings(
            mode=mode, predicate_policy=predicate_policy, substitution=substitution
        ),
        principals=principals,
        compiled_at=compiled_at or datetime.now(UTC),
        source_url="http://localhost:9002",
    )


@pytest.fixture
def graph() -> PolicyGraph:
    return build_graph()


@pytest.fixture
def growth(graph: PolicyGraph) -> Principal:
    return graph.principal("growth-agent")


def seed_duckdb(path: str) -> None:
    con = duckdb.connect(path)
    con.execute("CREATE TABLE dim_users(id BIGINT, name VARCHAR, email VARCHAR, ssn VARCHAR)")
    con.execute(
        "INSERT INTO dim_users VALUES (1,'Ada','ada@corp.com','111-22-3333'),"
        "(2,'Bo','bo@x.io','999-88-7777'),(3,'Cy','cy@corp.com','555-44-3333')"
    )
    con.execute("CREATE TABLE users_raw AS SELECT * FROM dim_users")
    con.execute("CREATE TABLE orders(id BIGINT, user_id BIGINT, total DOUBLE)")
    con.execute("INSERT INTO orders VALUES (10,1,42.0),(11,2,7.5),(12,1,99.0)")
    con.close()


@pytest.fixture
def warehouse(tmp_path) -> str:
    path = str(tmp_path / "wh.duckdb")
    seed_duckdb(path)
    return path


def make_config(dsn: str, jsonl: str, *, mode: str = "enforce", max_staleness: int = 86400):
    """A valid AirlockConfig for gateway tests. Decisions use the installed graph, not this."""
    from airlock.config import AirlockConfig

    return AirlockConfig.model_validate(
        {
            "datahub": {
                "url": "http://localhost:8080",
                "snapshot": {
                    "refresh_interval": 30,
                    "max_staleness": max_staleness,
                    "stale_policy": "fail_closed",
                },
            },
            "warehouse": {
                "kind": "duckdb",
                "dsn": dsn,
                "defaults": {"row_limit": 10000, "statement_timeout": 30},
            },
            "enforcement": {"mode": mode},
            "rules": [
                {"id": "pii", "match": {"tag": "PII"}, "action": {"mask": "auto"}},
                {"id": "ssn", "match": {"glossary_term": "Classification.SSN"}, "action": "deny"},
                {
                    "id": "dep",
                    "match": {"lifecycle": "DEPRECATED"},
                    "action": "substitute_certified",
                },
            ],
            "principals": [
                {"name": "growth-agent", "key": "g", "scopes": {"domains": ["Marketing"]}},
                {"name": "finance-agent", "key": "f", "scopes": {"domains": ["Finance"]}},
            ],
            "audit": {"jsonl": jsonl, "datahub_writeback": False},
        }
    )


class RecordingSink:
    """A fake audit sink capturing records for assertions. Satisfies the Sink protocol."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def write(self, record: AuditRecord) -> None:
        self.records.append(record)

    async def close(self) -> None:
        return None
