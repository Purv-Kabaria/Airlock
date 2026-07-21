"""Masking strategy selection, SQL rendering, and post-flight shape verification."""

from __future__ import annotations

import duckdb
import pytest
from sqlglot import exp

from airlock.masking import mask_expression, resolve_strategy, verify_value


@pytest.mark.parametrize(
    "name,dtype,expected",
    [
        ("email", "VARCHAR", "partial_email"),
        ("phone", "VARCHAR", "partial_phone"),
        ("signup_date", "DATE", "generalize_date"),
        ("customer_id", "BIGINT", "hash"),
    ],
)
def test_auto_strategy_selection(name, dtype, expected) -> None:
    assert resolve_strategy("auto", column_name=name, data_type=dtype) == expected


def test_explicit_strategy_passes_through() -> None:
    assert resolve_strategy("hash", column_name="anything", data_type="X") == "hash"
    with pytest.raises(ValueError):
        resolve_strategy("bogus", column_name="x", data_type="X")


@pytest.mark.parametrize(
    "strategy", ["null", "hash", "partial_email", "partial_phone", "fixed_string"]
)
def test_mask_expression_executes_on_duckdb(strategy) -> None:
    con = duckdb.connect()
    con.execute("CREATE TABLE t(email VARCHAR)")
    con.execute("INSERT INTO t VALUES ('ada@corp.com')")
    col = exp.column("email", table="t")
    masked = mask_expression(strategy, col, dialect="duckdb", salt="salt")
    value = con.execute(f"SELECT {masked.sql(dialect='duckdb')} FROM t").fetchone()[0]
    assert value != "ada@corp.com"
    assert verify_value(strategy, value)


def test_hash_is_equality_preserving() -> None:
    con = duckdb.connect()
    con.execute("CREATE TABLE t(x VARCHAR)")
    con.execute("INSERT INTO t VALUES ('a'),('a'),('b')")
    col = exp.column("x", table="t")
    e = mask_expression("hash", col, dialect="duckdb", salt="s").sql(dialect="duckdb")
    distinct = con.execute(f"SELECT COUNT(DISTINCT {e}) FROM t").fetchone()[0]
    assert distinct == 2  # two distinct raw values remain two distinct masked values


def test_verify_value_rejects_unmasked() -> None:
    assert not verify_value("partial_email", "raw@leak.com")
    assert not verify_value("hash", "not-a-hash")


def test_hash_salt_with_apostrophe_stays_a_single_literal() -> None:
    # A salt containing an apostrophe must not break out of the SQL string literal it is inlined
    # into; the rendered expression stays a single, executable hash.
    con = duckdb.connect()
    con.execute("CREATE TABLE t(x VARCHAR)")
    con.execute("INSERT INTO t VALUES ('a')")
    col = exp.column("x", table="t")
    e = mask_expression("hash", col, dialect="duckdb", salt="o'brien").sql(dialect="duckdb")
    value = con.execute(f"SELECT {e} FROM t").fetchone()[0]
    assert verify_value("hash", value)
    assert verify_value("null", None)
