"""Snowflake and BigQuery adapters: DSN parsing and protocol conformance, with no driver installed.

These adapters import their driver lazily (only when a connection is actually made), so everything
short of running a query must work without snowflake-connector-python or google-cloud-bigquery on
the machine. The gateway builds them, validates their DSN, and treats them as WarehouseAdapters
regardless of whether the optional extra is present; only a live query needs the package. That is
what these tests pin - the live behavior is verified against real accounts, not here.
"""

from __future__ import annotations

import pytest

from airlock.errors import ConfigError
from airlock.exec.base import WarehouseAdapter, make_adapter
from airlock.exec.bigquery_adapter import BigQueryAdapter, parse_bigquery_dsn
from airlock.exec.snowflake_adapter import SnowflakeAdapter, parse_snowflake_dsn


def _warehouse_config(kind: str, dsn: str):  # type: ignore[no-untyped-def]
    from airlock.config import WarehouseConfig

    return WarehouseConfig(kind=kind, dsn=dsn)


# -- Snowflake DSN --------------------------------------------------------------------------------


def test_snowflake_dsn_full() -> None:
    args = parse_snowflake_dsn(
        "snowflake://alice:s3cret@acme-prod/analytics/marketing?warehouse=WH_XS&role=READER"
    )
    assert args["account"] == "acme-prod"
    assert args["user"] == "alice"
    assert args["password"] == "s3cret"
    assert args["database"] == "analytics"
    assert args["schema"] == "marketing"
    assert args["warehouse"] == "WH_XS"
    assert args["role"] == "READER"


def test_snowflake_dsn_url_encoded_password() -> None:
    # A password with '@' or '/' must survive the URL round-trip, or the connect silently uses the
    # wrong credential and every query fails with an opaque auth error.
    args = parse_snowflake_dsn("snowflake://bob:p%40ss%2Fword@acct/db/sch")
    assert args["password"] == "p@ss/word"


def test_snowflake_dsn_passes_through_extra_connect_args() -> None:
    args = parse_snowflake_dsn("snowflake://u@acct/db/sch?authenticator=externalbrowser")
    assert args["authenticator"] == "externalbrowser"


def test_snowflake_dsn_rejects_wrong_scheme() -> None:
    with pytest.raises(ConfigError, match="snowflake://"):
        parse_snowflake_dsn("postgres://acct/db")


def test_snowflake_dsn_requires_account() -> None:
    with pytest.raises(ConfigError, match="account"):
        parse_snowflake_dsn("snowflake:///db/sch")


# -- BigQuery DSN ---------------------------------------------------------------------------------


def test_bigquery_dsn_full() -> None:
    settings = parse_bigquery_dsn(
        "bigquery://my-project/retail?location=EU&credentials_path=/k.json"
    )
    assert settings["project"] == "my-project"
    assert settings["dataset"] == "retail"
    assert settings["location"] == "EU"
    assert settings["credentials_path"] == "/k.json"


def test_bigquery_dsn_project_only() -> None:
    settings = parse_bigquery_dsn("bigquery://my-project")
    assert settings["project"] == "my-project"
    assert "dataset" not in settings


def test_bigquery_dsn_rejects_wrong_scheme() -> None:
    with pytest.raises(ConfigError, match="bigquery://"):
        parse_bigquery_dsn("snowflake://acct/db")


def test_bigquery_dsn_requires_project() -> None:
    with pytest.raises(ConfigError, match="project"):
        parse_bigquery_dsn("bigquery:///dataset")


# -- Construction & protocol conformance (no driver needed) ---------------------------------------


def test_adapters_construct_and_satisfy_the_protocol_without_the_driver() -> None:
    sf = SnowflakeAdapter("snowflake://u:p@acct/db/sch?warehouse=W&role=R")
    bq = BigQueryAdapter("bigquery://proj/ds")
    assert isinstance(sf, WarehouseAdapter)
    assert isinstance(bq, WarehouseAdapter)
    assert sf.kind == "snowflake"
    assert bq.kind == "bigquery"


def test_make_adapter_selects_cloud_kinds() -> None:
    sf = make_adapter(_warehouse_config("snowflake", "snowflake://u:p@acct/db/sch"))
    bq = make_adapter(_warehouse_config("bigquery", "bigquery://proj/ds"))
    assert sf.kind == "snowflake"
    assert bq.kind == "bigquery"


def test_warehouse_kind_is_the_sqlglot_dialect() -> None:
    # decide/rewrite parse and render in warehouse.dialect; a kind that was not a real sqlglot
    # dialect would silently mis-parse every query.
    import sqlglot

    for kind in ("duckdb", "postgres", "snowflake", "bigquery"):
        cfg = _warehouse_config(kind, "x://y")
        assert sqlglot.Dialect.get(cfg.dialect) is not None
