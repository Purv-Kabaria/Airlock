"""Governance posture of a compiled snapshot: what Airlock can and cannot enforce.

Airlock decides from catalog classifications, so a sparsely tagged catalog produces a gateway
that quietly passes sensitive data through. This module answers the question a platform engineer
asks before adopting anything inline: *if I turn this on, what actually happens?*

Coverage here is **rule-aware**, not a generic catalog audit. A column counts as governed only
when some loaded rule would act on it. A column carrying a `Finance` tag that no rule mentions is
classified but ungoverned, and that distinction is the whole point.

`suspected_gaps` is the one advisory signal: columns whose *name* looks sensitive while carrying no
classification any rule matches. It is a reporting hint that produces a to-do list in DataHub - it
never reaches the decision engine, and nothing here is used to classify, mask, or deny. Airlock
still enforces only what the catalog states (README "No mock mode"). Keeping this heuristic in
`policy/` rather than `engine/` is the structural guarantee of that boundary.

Pure by construction: `(PolicyGraph) -> CoverageReport`, no I/O and no clock, so the report is a
deterministic function of the snapshot hash and can be asserted on in CI.
"""

from __future__ import annotations

from dataclasses import dataclass

from airlock.policy.graph import DatasetFacts, PolicyGraph
from airlock.policy.rules import ActionKind, Rule, matching_rules

# Column-name tokens that imply a sensitive column. Deliberately small and boring: every entry
# earns its place by being unambiguous in a warehouse column name. Matching is on separator-split
# tokens, so `user_email` hits and `emailer_config` does not.
_SENSITIVE_TOKENS: dict[str, str] = {
    "email": "email address",
    "ssn": "national identifier",
    "phone": "phone number",
    "msisdn": "phone number",
    "dob": "date of birth",
    "birthdate": "date of birth",
    "salary": "compensation",
    "compensation": "compensation",
    "iban": "bank account",
    "passport": "government identifier",
    "latitude": "precise location",
    "longitude": "precise location",
}

# Multi-token names that only read as sensitive together, checked against the joined token stream.
_SENSITIVE_PHRASES: dict[tuple[str, ...], str] = {
    ("date", "of", "birth"): "date of birth",
    ("credit", "card"): "payment instrument",
    ("card", "number"): "payment instrument",
    ("home", "address"): "postal address",
    ("street", "address"): "postal address",
    ("tax", "id"): "government identifier",
    ("account", "number"): "bank account",
}

_GRADE_CLEAR = "clear"
_GRADE_GAPS = "gaps"
_GRADE_AT_RISK = "at-risk"


@dataclass(frozen=True, slots=True)
class SuspectedGap:
    """A column that reads as sensitive but that no rule would act on."""

    dataset_name: str
    dataset_urn: str
    column: str
    data_type: str
    reason: str

    @property
    def subject(self) -> str:
        return f"column:{self.dataset_name}.{self.column}"


@dataclass(frozen=True, slots=True)
class DatasetGap:
    name: str
    urn: str
    detail: str


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """What a snapshot can enforce, and where it is blind."""

    snapshot_hash: str
    total_datasets: int
    total_columns: int
    classified_columns: int  # carry any tag or term, whether or not a rule acts on it
    governed_columns: int  # a loaded rule would mask or deny them
    masked_columns: int
    denied_columns: int
    suspected_gaps: tuple[SuspectedGap, ...]
    dead_rules: tuple[str, ...]
    unowned_datasets: tuple[DatasetGap, ...]
    unreachable_datasets: tuple[DatasetGap, ...]
    orphan_deprecated: tuple[DatasetGap, ...]

    @property
    def governed_pct(self) -> float:
        return 100.0 * self.governed_columns / self.total_columns if self.total_columns else 0.0

    @property
    def classified_pct(self) -> float:
        return 100.0 * self.classified_columns / self.total_columns if self.total_columns else 0.0

    @property
    def grade(self) -> str:
        """Posture in one word.

        Driven by blind spots, not by raw percentage: a small catalog that classifies everything
        sensitive is `clear` at 4% coverage, while one unclassified SSN column is `at-risk` at 90%.
        Percentage alone would reward tagging noise and hide the only failure that leaks data.
        """
        if self.suspected_gaps:
            return _GRADE_AT_RISK
        if self.dead_rules or self.orphan_deprecated or self.unowned_datasets:
            return _GRADE_GAPS
        return _GRADE_CLEAR

    @property
    def is_clear(self) -> bool:
        return self.grade == _GRADE_CLEAR


def measure_coverage(graph: PolicyGraph) -> CoverageReport:
    """Compute the governance posture of a compiled snapshot. Pure; safe to call on any snapshot."""
    total_columns = 0
    classified = 0
    masked = 0
    denied = 0
    gaps: list[SuspectedGap] = []
    fired_rules: set[str] = set()
    unowned: list[DatasetGap] = []
    orphan_deprecated: list[DatasetGap] = []

    for ds in _sorted_datasets(graph):
        if not ds.owners:
            unowned.append(DatasetGap(ds.name, ds.urn, "no owner in DataHub"))
        if ds.is_deprecated and not graph.certified_substitutes(ds.urn):
            orphan_deprecated.append(
                DatasetGap(ds.name, ds.urn, "deprecated with no certified downstream")
            )
        # Substitution rules act on dataset facts (lifecycle), never on a column, so they are only
        # credited here. Column-scoped rules are credited in the column loop below, where they act.
        for rule in _table_rules(graph, ds):
            fired_rules.add(rule.id)

        for col in ds.columns:
            total_columns += 1
            if col.tags or col.glossary_terms:
                classified += 1
            # Exactly the inputs engine.column_outcome uses: the column's own tags and terms plus
            # the dataset domain. Not the dataset's tags/lifecycle - those do not mask columns, and
            # counting them here would report protection the engine never applies.
            for rule in matching_rules(
                graph.rules, tags=col.tags, terms=col.glossary_terms, domain=ds.domain
            ):
                fired_rules.add(rule.id)
            # governing_rule includes classification inherited along column lineage, so a column
            # masked only because it derives from PII is counted as governed, not flagged as a gap.
            winner, _ = graph.governing_rule(ds, col)
            kind = winner.action.kind if winner is not None else None
            if kind is ActionKind.DENY:
                denied += 1
            elif kind is ActionKind.MASK:
                masked += 1
            else:
                suspicion = _suspect(col.name)
                if suspicion is not None:
                    gaps.append(SuspectedGap(ds.name, ds.urn, col.name, col.data_type, suspicion))

    return CoverageReport(
        snapshot_hash=graph.content_hash,
        total_datasets=len(graph.datasets),
        total_columns=total_columns,
        classified_columns=classified,
        governed_columns=masked + denied,
        masked_columns=masked,
        denied_columns=denied,
        suspected_gaps=tuple(gaps),
        dead_rules=tuple(sorted(r.id for r in graph.rules if r.id not in fired_rules)),
        unowned_datasets=tuple(unowned),
        unreachable_datasets=tuple(_unreachable(graph)),
        orphan_deprecated=tuple(orphan_deprecated),
    )


def _sorted_datasets(graph: PolicyGraph) -> list[DatasetFacts]:
    return sorted(graph.datasets.values(), key=lambda d: d.name)


def _table_rules(graph: PolicyGraph, ds: DatasetFacts) -> list[Rule]:
    """Substitution rules that fire on this dataset's facts. Only table-scoped kinds are returned:
    a mask/deny rule that happens to match a dataset-level tag masks nothing (masking is
    column-scoped), so crediting it here would call a dead rule live."""
    matches = matching_rules(
        graph.rules,
        tags=ds.tags,
        terms=ds.glossary_terms,
        lifecycle=ds.lifecycle,
        certification=ds.certification,
        domain=ds.domain,
    )
    return [r for r in matches if r.action.kind is ActionKind.SUBSTITUTE_CERTIFIED]


def _unreachable(graph: PolicyGraph) -> list[DatasetGap]:
    """Datasets no named principal can reach. Named principals only - the anonymous principal
    denies everything by definition, so including it would mark the whole catalog unreachable."""
    named = [p for p in graph.principals.values() if not p.deny_all]
    if not named:
        return []
    out: list[DatasetGap] = []
    for ds in _sorted_datasets(graph):
        if not any(p.scope.permits(domain=ds.domain, platform=ds.platform) for p in named):
            where = ds.domain or "no domain"
            out.append(DatasetGap(ds.name, ds.urn, f"outside every principal's scope ({where})"))
    return out


def _suspect(column_name: str) -> str | None:
    """Why a column name reads as sensitive, or None. Advisory only - never used to enforce."""
    tokens = _tokenize(column_name)
    for token in tokens:
        hit = _SENSITIVE_TOKENS.get(token)
        if hit is not None:
            return hit
    for phrase, hit in _SENSITIVE_PHRASES.items():
        if _contains_run(tokens, phrase):
            return hit
    return None


def _tokenize(name: str) -> tuple[str, ...]:
    out: list[str] = []
    current: list[str] = []
    for ch in name:
        if ch.isalnum():
            current.append(ch.lower())
        elif current:
            out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return tuple(out)


def _contains_run(tokens: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    n = len(phrase)
    return any(tokens[i : i + n] == phrase for i in range(len(tokens) - n + 1))
