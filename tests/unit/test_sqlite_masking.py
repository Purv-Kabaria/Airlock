"""Masking has to actually execute on SQLite, not just render.

SQLite ships almost no string or hash builtins. The adapter's other tests cover connections, pooling,
and row shaping, so nothing ever ran the SQL that masking emits - and `hash`, the default strategy for
any PII column that is not an email, phone, or date, failed at query time with "no such function:
MD5". The gateway was therefore unusable for PII on the warehouse the README recommends for a laptop
or an ARM box. These run each strategy's real rendered SQL against a real SQLite connection.
"""

from __future__ import annotations

import hashlib

import pytest
from sqlglot import exp

from airlock.cli.verify import PROBES, check_value, probe_statement
from airlock.exec.dbapi_adapter import make_sqlite_adapter
from airlock.masking import mask_expression

SALT = "sqlite-probe-salt"


async def _mask(sql: str) -> object:
    adapter = make_sqlite_adapter(":memory:")
    try:
        result = await adapter.run(sql, timeout=10, row_limit=1)
        return result.rows[0]["masked"] if result.rows else None
    finally:
        await adapter.close()


@pytest.mark.parametrize(
    "probe", [p for p in PROBES if p.strategy != "generalize_date"], ids=lambda p: f"{p.strategy}"
)
async def test_every_supported_strategy_executes_on_sqlite(probe) -> None:
    sql = probe_statement(probe, dialect="sqlite", salt=SALT)
    value = await _mask(sql)
    ok, detail = check_value(probe, value)
    assert ok, f"{probe.strategy} on sqlite: {detail}\n{sql}"


async def test_hash_matches_the_digest_every_other_warehouse_produces() -> None:
    # The registered MD5 must agree with the warehouses that have one natively, or the same value
    # masks to two different pseudonyms depending on where the query ran.
    sql = probe_statement(PROBES[0], dialect="sqlite", salt=SALT)
    assert PROBES[0].strategy == "hash"
    expected = hashlib.md5(f"{SALT}ada@corp.com".encode()).hexdigest()
    assert await _mask(sql) == expected


async def test_right_handles_a_value_shorter_than_the_window() -> None:
    # The masking template guards this with a LENGTH check, but the registered function must not
    # blow up if it is ever called directly with a short value.
    node = mask_expression("partial_phone", exp.column("c"), salt=SALT)
    inner = exp.select(exp.alias_(exp.Literal.string("12"), "c"))
    stmt = exp.select(exp.alias_(node, "masked")).from_(
        exp.Subquery(this=inner, alias=exp.TableAlias(this=exp.to_identifier("t")))
    )
    assert await _mask(stmt.sql(dialect="sqlite")) == "***"


async def test_null_input_stays_null() -> None:
    node = mask_expression("hash", exp.column("c"), salt=SALT)
    inner = exp.select(exp.alias_(exp.null(), "c"))
    stmt = exp.select(exp.alias_(node, "masked")).from_(
        exp.Subquery(this=inner, alias=exp.TableAlias(this=exp.to_identifier("t")))
    )
    # NULL || anything is NULL in SQLite, so the digest is never taken over the literal "None".
    assert await _mask(stmt.sql(dialect="sqlite")) is None
