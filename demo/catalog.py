"""The demo retail catalog: one definition, two consumers.

`seed_duckdb` creates the DuckDB tables and rows; `seed_catalog` ingests the same shape into DataHub
(tags, terms, deprecation, certification, domains, lineage). Airlock then compiles its policy from
DataHub the normal way - there is no separate hand-built graph, so the warehouse, the catalog, and
enforcement can never drift. Nothing in `airlock/` imports this; only demo and tools do.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PLATFORM = "duckdb"


@dataclass(frozen=True, slots=True)
class Column:
    name: str
    type: str
    tags: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Dataset:
    name: str
    domain: str
    columns: tuple[Column, ...]
    rows: tuple[tuple[object, ...], ...]
    lifecycle: str | None = None
    certification: str | None = None
    owners: tuple[str, ...] = ()
    downstream: tuple[str, ...] = field(default=())


DATASETS: tuple[Dataset, ...] = (
    Dataset(
        name="dim_users",
        domain="Marketing",
        certification="CERTIFIED",
        columns=(
            Column("id", "BIGINT"),
            Column("name", "VARCHAR"),
            Column("email", "VARCHAR", tags=("PII",)),
            Column("phone", "VARCHAR", tags=("PII",)),
            Column("ssn", "VARCHAR", terms=("Classification.SSN",)),
            Column("signup_date", "DATE"),
        ),
        rows=(
            (1, "Ada Lovelace", "ada@corp.com", "555-100-2001", "111-22-3333", "2026-01-04"),
            (2, "Bo Diddley", "bo@x.io", "555-100-2002", "999-88-7777", "2026-02-11"),
            (3, "Cy Young", "cy@corp.com", "555-100-2003", "555-44-3333", "2026-03-20"),
            (4, "Di Prince", "di@corp.com", "555-100-2004", "222-33-4444", "2026-03-28"),
        ),
    ),
    Dataset(
        name="users_raw",
        domain="Marketing",
        lifecycle="DEPRECATED",
        owners=("urn:li:corpGroup:data-eng",),
        downstream=("dim_users",),
        columns=(
            Column("id", "BIGINT"),
            Column("name", "VARCHAR"),
            Column("email", "VARCHAR", tags=("PII",)),
            Column("phone", "VARCHAR", tags=("PII",)),
            Column("ssn", "VARCHAR", terms=("Classification.SSN",)),
            Column("signup_date", "DATE"),
        ),
        rows=(
            (1, "Ada Lovelace", "ada@corp.com", "555-100-2001", "111-22-3333", "2026-01-04"),
            (2, "Bo Diddley", "bo@x.io", "555-100-2002", "999-88-7777", "2026-02-11"),
            (3, "Cy Young", "cy@corp.com", "555-100-2003", "555-44-3333", "2026-03-20"),
            (4, "Di Prince", "di@corp.com", "555-100-2004", "222-33-4444", "2026-03-28"),
        ),
    ),
    Dataset(
        name="orders",
        domain="Marketing",
        columns=(
            Column("id", "BIGINT"),
            Column("user_id", "BIGINT"),
            Column("total", "DOUBLE"),
            Column("status", "VARCHAR"),
            # Intentionally untagged: a real order-contact phone nobody classified. Coverage flags
            # it as a suspected gap and `airlock propose` writes the suggestion back to DataHub.
            Column("customer_phone", "VARCHAR"),
        ),
        rows=(
            (10, 1, 420.00, "shipped", "555-100-2001"),
            (11, 2, 17.50, "shipped", "555-100-2002"),
            (12, 1, 99.00, "returned", "555-100-2001"),
            (13, 3, 250.75, "shipped", "555-100-2003"),
            (14, 4, 8.25, "cancelled", "555-100-2004"),
        ),
    ),
    Dataset(
        name="payroll",
        domain="Finance",
        owners=("urn:li:corpGroup:finance",),
        columns=(
            Column("emp_id", "BIGINT"),
            Column("name", "VARCHAR"),
            Column("salary", "DOUBLE", tags=("PII",)),
            Column("ssn", "VARCHAR", terms=("Classification.SSN",)),
        ),
        rows=(
            (100, "Ada Lovelace", 185000.0, "111-22-3333"),
            (101, "Bo Diddley", 142000.0, "999-88-7777"),
        ),
    ),
)


def seed_duckdb(path: str) -> None:
    """Create the demo tables and rows. Idempotent: drops and recreates so re-runs converge."""
    import duckdb

    con = duckdb.connect(path)
    try:
        for ds in DATASETS:
            cols = ", ".join(f"{c.name} {c.type}" for c in ds.columns)
            con.execute(f"DROP TABLE IF EXISTS {ds.name}")
            con.execute(f"CREATE TABLE {ds.name} ({cols})")
            placeholders = ", ".join("?" for _ in ds.columns)
            con.executemany(
                f"INSERT INTO {ds.name} VALUES ({placeholders})", [list(r) for r in ds.rows]
            )
    finally:
        con.close()
