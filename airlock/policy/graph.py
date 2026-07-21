"""Catalog facts and the frozen, content-addressed PolicyGraph.

The graph is the compiled snapshot the decision engine reads: dataset schemas and
classifications from DataHub, plus the rules, enforcement settings, and principal registry
from `airlock.yaml`. It is immutable by construction — mapping fields are wrapped in
`MappingProxyType`, sequences are tuples, sets are frozensets — so a stray mutation raises
rather than silently corrupting a shared snapshot (README §7, §12). Identity is the
`content_hash`: any change to facts, rules, enforcement, or principals yields a new hash,
which is exactly what makes the decision cache safe to key on.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType

from airlock.policy.rules import Rule
from airlock.urns import normalize_table_key


@dataclass(frozen=True, slots=True)
class ColumnFact:
    name: str
    urn: str
    data_type: str
    tags: frozenset[str] = frozenset()
    glossary_terms: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class DatasetFacts:
    urn: str
    platform: str
    name: str  # warehouse-qualified name, e.g. "retail.dim_users"
    env: str
    columns: tuple[ColumnFact, ...]
    tags: frozenset[str] = frozenset()
    glossary_terms: frozenset[str] = frozenset()
    lifecycle: str | None = None  # e.g. "DEPRECATED"
    certification: str | None = None  # e.g. "CERTIFIED"
    domain: str | None = None
    owners: tuple[str, ...] = ()

    def column(self, name: str) -> ColumnFact | None:
        key = name.strip().strip('"').strip("`").lower()
        for c in self.columns:
            if c.name.lower() == key:
                return c
        return None

    @property
    def is_deprecated(self) -> bool:
        return (self.lifecycle or "").upper() == "DEPRECATED"

    @property
    def is_certified(self) -> bool:
        return (self.certification or "").upper() == "CERTIFIED"


@dataclass(frozen=True, slots=True)
class Scope:
    """A principal's confinement. `None` means unrestricted on that axis; a set confines."""

    domains: frozenset[str] | None = None
    platforms: frozenset[str] | None = None

    def permits(self, *, domain: str | None, platform: str | None) -> bool:
        domain_ok = self.domains is None or (domain is not None and domain in self.domains)
        platform_ok = self.platforms is None or (
            platform is not None and platform in self.platforms
        )
        return domain_ok and platform_ok


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated agent identity. The anonymous principal denies everything."""

    name: str
    scope: Scope = Scope()
    statement_classes: frozenset[str] = frozenset({"select"})
    row_limit: int | None = None  # overrides the enforcement default when set
    statement_timeout: float | None = None
    deny_all: bool = False

    @classmethod
    def anonymous(cls) -> Principal:
        return cls(name="anonymous", scope=Scope(domains=frozenset()), deny_all=True)


@dataclass(frozen=True, slots=True)
class EnforcementSettings:
    mode: str = "enforce"  # enforce | monitor
    unknown_tables: str = "deny"  # deny | allow
    statement_classes: frozenset[str] = frozenset({"select"})
    predicate_policy: str = "deny"  # deny | transform
    substitution: str = "rewrite"  # rewrite | warn | off
    table_matching: str = "exact"  # exact | suffix
    default_row_limit: int = 10000
    default_statement_timeout: float = 30.0

    @property
    def is_monitor(self) -> bool:
        return self.mode == "monitor"


@dataclass(frozen=True, slots=True)
class Lineage:
    """Downstream edges keyed by upstream URN, used to find certified substitutes."""

    downstream: Mapping[str, tuple[str, ...]]

    def downstream_of(self, urn: str) -> tuple[str, ...]:
        return self.downstream.get(urn, ())


@dataclass(frozen=True, slots=True)
class PolicyGraph:
    datasets: Mapping[str, DatasetFacts]
    name_index: Mapping[str, str]  # normalized name -> dataset urn
    lineage: Lineage
    rules: tuple[Rule, ...]
    enforcement: EnforcementSettings
    principals: Mapping[str, Principal]
    content_hash: str
    compiled_at: datetime
    source_url: str

    @classmethod
    def build(
        cls,
        *,
        datasets: dict[str, DatasetFacts],
        lineage: dict[str, tuple[str, ...]],
        rules: tuple[Rule, ...],
        enforcement: EnforcementSettings,
        principals: dict[str, Principal],
        compiled_at: datetime,
        source_url: str,
    ) -> PolicyGraph:
        # Index every suffix of each dataset name (full, then progressively shorter), so both an
        # over-qualified query (catalog.schema.t) and a bare one (t) can resolve. A suffix shared by
        # two datasets is marked _AMBIGUOUS and never resolves — qualification is then required.
        name_index: dict[str, str] = {}
        for urn, ds in datasets.items():
            parts = normalize_table_key(ds.name).split(".")
            for i in range(len(parts)):
                key = ".".join(parts[i:])
                if key not in name_index:
                    name_index[key] = urn
                elif name_index[key] != urn:
                    name_index[key] = _AMBIGUOUS

        content_hash = _hash_graph(datasets, rules, enforcement, principals)
        return cls(
            datasets=MappingProxyType(dict(datasets)),
            name_index=MappingProxyType(name_index),
            lineage=Lineage(downstream=MappingProxyType(dict(lineage))),
            rules=rules,
            enforcement=enforcement,
            principals=MappingProxyType(dict(principals)),
            content_hash=content_hash,
            compiled_at=compiled_at,
            source_url=source_url,
        )

    def dataset(self, urn: str) -> DatasetFacts | None:
        return self.datasets.get(urn)

    def dataset_by_name(self, name: str) -> DatasetFacts | None:
        key = normalize_table_key(name)
        urn = self.name_index.get(key)
        if urn is not None:
            return None if urn is _AMBIGUOUS else self.datasets.get(urn)
        if self.enforcement.table_matching != "suffix":
            return None
        # Suffix mode: the query is more qualified than the catalog entry. Drop leading qualifiers
        # (catalog, then schema) one at a time and take the first unambiguous hit; stop at ambiguity.
        parts = key.split(".")
        for i in range(1, len(parts)):
            urn = self.name_index.get(".".join(parts[i:]))
            if urn is _AMBIGUOUS:
                return None
            if urn is not None:
                return self.datasets.get(urn)
        return None

    def name_is_ambiguous(self, name: str) -> bool:
        return self.name_index.get(normalize_table_key(name)) is _AMBIGUOUS

    def principal(self, name: str) -> Principal | None:
        return self.principals.get(name)

    def certified_substitute(self, urn: str) -> DatasetFacts | None:
        """A certified dataset directly downstream of `urn`, if one exists."""
        for downstream_urn in self.lineage.downstream_of(urn):
            ds = self.datasets.get(downstream_urn)
            if ds is not None and ds.is_certified and not ds.is_deprecated:
                return ds
        return None


# Sentinel stored in name_index when a bare name maps to more than one dataset.
_AMBIGUOUS = "urn:li:airlock:ambiguous"


def _hash_graph(
    datasets: dict[str, DatasetFacts],
    rules: tuple[Rule, ...],
    enforcement: EnforcementSettings,
    principals: dict[str, Principal],
) -> str:
    payload = {
        "datasets": [
            {
                "urn": ds.urn,
                "name": ds.name,
                "platform": ds.platform,
                "env": ds.env,
                "lifecycle": ds.lifecycle,
                "certification": ds.certification,
                "domain": ds.domain,
                "tags": sorted(ds.tags),
                "terms": sorted(ds.glossary_terms),
                "owners": sorted(ds.owners),
                "columns": [
                    {
                        "name": c.name,
                        "type": c.data_type,
                        "tags": sorted(c.tags),
                        "terms": sorted(c.glossary_terms),
                    }
                    for c in ds.columns
                ],
            }
            for ds in sorted(datasets.values(), key=lambda d: d.urn)
        ],
        "rules": [
            {
                "id": r.id,
                "match": {
                    "tag": r.match.tag,
                    "glossary_term": r.match.glossary_term,
                    "lifecycle": r.match.lifecycle,
                    "certification": r.match.certification,
                    "domain": r.match.domain,
                },
                "action": {"kind": r.action.kind.value, "strategy": r.action.strategy},
            }
            for r in rules
        ],
        "enforcement": {
            "mode": enforcement.mode,
            "unknown_tables": enforcement.unknown_tables,
            "statement_classes": sorted(enforcement.statement_classes),
            "predicate_policy": enforcement.predicate_policy,
            "substitution": enforcement.substitution,
            "default_row_limit": enforcement.default_row_limit,
            "default_statement_timeout": enforcement.default_statement_timeout,
        },
        "principals": [
            {
                "name": p.name,
                "domains": sorted(p.scope.domains) if p.scope.domains is not None else None,
                "platforms": sorted(p.scope.platforms) if p.scope.platforms is not None else None,
                "statement_classes": sorted(p.statement_classes),
                "row_limit": p.row_limit,
                "statement_timeout": p.statement_timeout,
                "deny_all": p.deny_all,
            }
            for p in sorted(principals.values(), key=lambda x: x.name)
        ],
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()
