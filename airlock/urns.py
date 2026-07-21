"""DataHub URN construction and parsing, plus table-name normalization.

A DataHub dataset URN looks like:
    urn:li:dataset:(urn:li:dataPlatform:duckdb,retail.dim_users,PROD)
and a schema field URN like:
    urn:li:schemaField:(urn:li:dataset:(...),email)

Airlock resolves warehouse table references (which may be bare, `schema.table`, or
`catalog.schema.table`) to dataset URNs via a normalized-name index built at compile
time. Normalization here is deliberately dialect-agnostic and lossless-lowercasing only
for the *index key*; dialect-correct identifier semantics live in the analyzer.
"""

from __future__ import annotations

from dataclasses import dataclass

_DATASET_PREFIX = "urn:li:dataset:"
_PLATFORM_PREFIX = "urn:li:dataPlatform:"


@dataclass(frozen=True, slots=True)
class DatasetUrnParts:
    platform: str
    name: str
    env: str


def dataset_urn(platform: str, name: str, env: str = "PROD") -> str:
    return f"{_DATASET_PREFIX}({_PLATFORM_PREFIX}{platform},{name},{env})"


def parse_dataset_urn(urn: str) -> DatasetUrnParts:
    """Parse a dataset URN into (platform, name, env). Raises ValueError if malformed."""
    if not urn.startswith(_DATASET_PREFIX + "("):
        raise ValueError(f"not a dataset urn: {urn!r}")
    inner = urn[len(_DATASET_PREFIX) + 1 : -1]  # strip 'urn:li:dataset:(' and trailing ')'
    platform_part, _, rest = inner.partition(",")
    name, _, env = rest.rpartition(",")
    platform = platform_part.removeprefix(_PLATFORM_PREFIX)
    if not platform or not name or not env:
        raise ValueError(f"malformed dataset urn: {urn!r}")
    return DatasetUrnParts(platform=platform, name=name, env=env)


def field_urn(dataset: str, field: str) -> str:
    return f"urn:li:schemaField:({dataset},{field})"


def tag_name(urn_or_name: str) -> str:
    """`urn:li:tag:PII` -> `PII`; a bare name is returned unchanged."""
    return urn_or_name.removeprefix("urn:li:tag:")


def glossary_name(urn_or_name: str) -> str:
    """`urn:li:glossaryTerm:Classification.SSN` -> `Classification.SSN`."""
    return urn_or_name.removeprefix("urn:li:glossaryTerm:")


def domain_name(urn_or_name: str) -> str:
    return urn_or_name.removeprefix("urn:li:domain:")


def normalize_table_key(name: str) -> str:
    """Index key for a dataset name: lowercased, unquoted, dot-separated.

    This is only for building the name->URN lookup. It is intentionally forgiving so
    that `Retail.Dim_Users`, `retail.dim_users`, and `"retail"."dim_users"` collide to
    one key. The analyzer, not this function, enforces dialect case semantics.
    """
    return ".".join(
        part.strip().strip('"').strip("`").strip("[]").lower() for part in name.split(".")
    )
