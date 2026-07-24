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
    masked = mask_expression(strategy, col, salt="salt")
    value = con.execute(f"SELECT {masked.sql(dialect='duckdb')} FROM t").fetchone()[0]
    assert value != "ada@corp.com"
    assert verify_value(strategy, value)


def test_hash_is_equality_preserving() -> None:
    con = duckdb.connect()
    con.execute("CREATE TABLE t(x VARCHAR)")
    con.execute("INSERT INTO t VALUES ('a'),('a'),('b')")
    col = exp.column("x", table="t")
    e = mask_expression("hash", col, salt="s").sql(dialect="duckdb")
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
    e = mask_expression("hash", col, salt="o'brien").sql(dialect="duckdb")
    value = con.execute(f"SELECT {e} FROM t").fetchone()[0]
    assert verify_value("hash", value)
    assert verify_value("null", None)


def test_partial_phone_redacts_short_values_whole() -> None:
    # RIGHT(x, 4) returns the entire value when the value is four characters or fewer, so without
    # a length guard the strategy stops masking exactly the values it most needs to.
    con = duckdb.connect()
    for raw, expected in [("5551234567", "***-4567"), ("12.5", "***"), ("hello", "***")]:
        sql = mask_expression("partial_phone", exp.column("c"), salt="s").sql(dialect="duckdb")
        got = con.execute(f"SELECT {sql} FROM (SELECT '{raw}' AS c)").fetchone()[0]
        assert got == expected
        assert verify_value("partial_phone", got)
    con.close()


@pytest.mark.parametrize("dtype", ["VARCHAR", "BIGINT", "DOUBLE"])
def test_generalize_date_degrades_on_non_temporal_column(dtype) -> None:
    # DATE_TRUNC cannot bind against these, and a strategy typo in airlock.yaml must not turn into
    # a failing query on every read of the column. hash is at least as private.
    assert resolve_strategy("generalize_date", column_name="c", data_type=dtype) == "hash"


@pytest.mark.parametrize("dtype", ["DATE", "TIMESTAMP"])
def test_generalize_date_kept_on_temporal_column(dtype) -> None:
    assert (
        resolve_strategy("generalize_date", column_name="c", data_type=dtype) == "generalize_date"
    )


# The dialects Airlock claims to render correct masking SQL for. DuckDB and Postgres execute in
# unit tests; the rest are asserted to transpile without leaving a function that does not exist on
# the target (the SPLIT_PART-on-BigQuery class of bug).
_SUPPORTED_DIALECTS = [
    "duckdb",
    "postgres",
    "snowflake",
    "bigquery",
    "mysql",
    "trino",
    "spark",
    "redshift",
    "clickhouse",
]

# Functions that sqlglot passes through unchanged when it has no transpilation for a target - their
# presence in rendered output means the mask would fail at execution on that warehouse.
_UNTRANSPILABLE = ("SPLIT_PART",)


@pytest.mark.parametrize("dialect", _SUPPORTED_DIALECTS)
@pytest.mark.parametrize(
    "strategy", ["hash", "partial_email", "partial_phone", "generalize_date", "fixed_string"]
)
def test_masking_is_dialect_portable(strategy, dialect) -> None:
    """Every mask renders into every supported warehouse dialect, and never leaves a function that
    dialect cannot run. This is the guarantee behind 'plug into almost any warehouse': one set of
    templates, transpiled per target, verified - not hoped for."""
    import sqlglot

    col = exp.column("email", table="t")
    rendered = mask_expression(strategy, col, salt="s").sql(dialect=dialect)
    assert not any(fn in rendered.upper() for fn in _UNTRANSPILABLE), (
        f"{strategy} left an untranspilable function for {dialect}: {rendered}"
    )
    # It must also parse back in that dialect - a render that does not round-trip is invalid SQL.
    assert sqlglot.parse_one(rendered, dialect=dialect) is not None


def test_hash_is_lowercase_hex_across_dialects() -> None:
    # verify_value asserts 32 lowercase hex; a dialect whose MD5 spelling produced uppercase or a
    # different length would slip past the post-flight shape check. Confirm the rendered SQL keeps
    # the hex-lowering wrappers sqlglot inserts (TO_HEX / LOWER(HEX(...))).
    col = exp.column("x", table="t")
    for dialect in ("bigquery", "trino", "clickhouse"):
        rendered = mask_expression("hash", col, salt="s").sql(dialect=dialect).upper()
        assert "MD5" in rendered
        # each of these dialects needs a hex conversion around MD5; bare MD5 returns bytes/uppercase
        assert "HEX" in rendered


@pytest.mark.parametrize(
    "raw,expect_contains",
    [("ada@corp.com", "***@corp.com"), ("bo@x.io", "***@x.io")],
)
def test_partial_email_domain_survives_without_split_part(raw, expect_contains) -> None:
    # The STRPOS-based domain extraction must behave exactly like the old SPLIT_PART on real data.
    con = duckdb.connect()
    sql = mask_expression("partial_email", exp.column("c"), salt="s").sql(dialect="duckdb")
    got = con.execute(f"SELECT {sql} FROM (SELECT '{raw}' AS c)").fetchone()[0]
    assert expect_contains in got
    assert raw not in got  # the local part is gone


@pytest.mark.parametrize("raw", ["SECRET-TOKEN-12345", "no-at-here", "1234567890"])
def test_partial_email_fully_redacts_non_email_values(raw) -> None:
    # A column mis-tagged as an email but holding free text (no '@') must not leak the whole value
    # after the '***@' marker. With no domain to reveal, the value is redacted to '***'.
    con = duckdb.connect()
    sql = mask_expression("partial_email", exp.column("c"), salt="s").sql(dialect="duckdb")
    got = con.execute(f"SELECT {sql} FROM (SELECT '{raw}' AS c)").fetchone()[0]
    assert got == "***"
    assert raw not in got
