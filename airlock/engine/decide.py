"""The pure decision function. No I/O, no clock, no globals.

`decide(resolved, principal, graph) -> list[Verdict]` is a total function of its inputs, which
is what makes any decision replayable from `(sql, principal, snapshot_hash)`. The per-column
and per-limit helpers are shared with the rewriter so the explanation and the executed SQL can
never disagree: both derive from the same `column_outcome`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from airlock.analyzer.resolve import ColumnRef, Context, GuardedRef, ResolvedQuery
from airlock.engine.verdicts import ReasonCode, Subject, Verdict
from airlock.masking import resolve_strategy, strategy_hint
from airlock.policy.graph import (
    ColumnFact,
    DatasetFacts,
    EnforcementSettings,
    PolicyGraph,
    Principal,
)
from airlock.policy.rules import ActionKind, matching_rules, winning_action


@dataclass(frozen=True, slots=True)
class Outcome:
    kind: Literal["allow", "mask", "deny"]
    strategy: str | None = None
    rule_id: str | None = None


_ALLOW = Outcome("allow")


def column_outcome(
    dataset: DatasetFacts,
    fact_name: str,
    fact_type: str,
    tags: frozenset[str],
    terms: frozenset[str],
    graph: PolicyGraph,
) -> Outcome:
    """The action for one column, independent of principal. Shared by decide and rewrite."""
    candidates = matching_rules(graph.rules, tags=tags, terms=terms, domain=dataset.domain)
    winner = winning_action(candidates)
    if winner is None or winner.action.kind is ActionKind.ALLOW:
        return _ALLOW
    if winner.action.kind is ActionKind.DENY:
        return Outcome("deny", rule_id=winner.id)
    if winner.action.kind is ActionKind.MASK:
        strategy = resolve_strategy(
            winner.action.strategy, column_name=fact_name, data_type=fact_type
        )
        return Outcome("mask", strategy=strategy, rule_id=winner.id)
    return _ALLOW


def outcome_for(col: ColumnRef, graph: PolicyGraph) -> Outcome:
    ds = col.table.effective
    assert ds is not None  # a ColumnRef is only built when the effective dataset exists
    return column_outcome(
        ds, col.fact.name, col.fact.data_type, col.fact.tags, col.fact.glossary_terms, graph
    )


def effective_row_limit(principal: Principal, enforcement: EnforcementSettings) -> int:
    return principal.row_limit if principal.row_limit is not None else enforcement.default_row_limit


def statement_is_denied(verdicts: list[Verdict]) -> bool:
    return any(v.action in ("deny_statement", "scope_deny") for v in verdicts)


def decide(resolved: ResolvedQuery, principal: Principal, graph: PolicyGraph) -> list[Verdict]:
    enforcement = graph.enforcement

    if principal.deny_all:
        return [
            Verdict.make(
                ReasonCode.UNKNOWN_PRINCIPAL,
                "deny_statement",
                Subject.statement(),
                "No valid principal key was presented; the anonymous policy denies all access.",
                hint="Register the agent as a principal in airlock.yaml and send its key.",
            )
        ]

    if resolved.statement_class not in principal.statement_classes:
        return [
            Verdict.make(
                ReasonCode.STATEMENT_CLASS,
                "deny_statement",
                Subject.statement(),
                f"Statement class '{resolved.statement_class}' is not permitted for {principal.name}.",
                hint="Send a read-only SELECT, or grant this class under principals[].overrides.statement_classes.",
            )
        ]

    verdicts: list[Verdict] = []
    verdicts += _scope_verdicts(resolved, principal, graph)
    verdicts += _substitution_verdicts(resolved, graph)
    verdicts += _column_verdicts(resolved, graph, enforcement)
    verdicts += _guarded_verdicts(resolved, graph, enforcement)
    verdicts += _limit_verdicts(resolved, principal, enforcement)
    return verdicts


def _scope_verdicts(
    resolved: ResolvedQuery, principal: Principal, graph: PolicyGraph
) -> list[Verdict]:
    out: list[Verdict] = []
    for table in resolved.tables:
        ds = table.effective
        if ds is None:
            continue
        if not principal.scope.permits(domain=ds.domain, platform=ds.platform):
            owner = ", ".join(ds.owners) if ds.owners else "the owning team"
            out.append(
                Verdict.make(
                    ReasonCode.SCOPE_DENY,
                    "scope_deny",
                    Subject.table(ds.name),
                    f"{ds.name} is in domain '{ds.domain}', outside {principal.name}'s scope.",
                    hint=f"Request access from {owner}, or query a table within your domain.",
                    catalog_url=_catalog_url(graph, ds.urn),
                )
            )
    return out


def _substitution_verdicts(resolved: ResolvedQuery, graph: PolicyGraph) -> list[Verdict]:
    out: list[Verdict] = []
    for table in resolved.tables:
        if table.substitute_to is not None:
            orig = table.dataset
            sub = table.substitute_to
            assert orig is not None
            out.append(
                Verdict.make(
                    ReasonCode.SUBSTITUTE,
                    "substitute",
                    Subject.table(orig.name),
                    f"{orig.name} is deprecated (lifecycle {orig.lifecycle}); certified equivalent "
                    f"{sub.name} selected via lineage with all referenced columns present.",
                    hint=f"Point future queries at {sub.name} to avoid the redirect.",
                    catalog_url=_catalog_url(graph, orig.urn),
                )
            )
        elif table.substitute_note is not None and table.dataset is not None:
            out.append(
                Verdict.make(
                    ReasonCode.SUBSTITUTE_DOWNGRADE,
                    "note",
                    Subject.table(table.dataset.name),
                    f"{table.dataset.name} is deprecated but was not substituted: {table.substitute_note}.",
                    hint="Ask data engineering for a certified replacement, or update the query.",
                    catalog_url=_catalog_url(graph, table.dataset.urn),
                )
            )
    return out


_OUTCOME_RANK = {"allow": 0, "mask": 1, "deny": 2}


def _worst_outcome(base: list[tuple[str, ColumnFact]], graph: PolicyGraph) -> Outcome:
    worst = _ALLOW
    for urn, fact in base:
        ds = graph.dataset(urn)
        if ds is None:
            continue
        outcome = column_outcome(
            ds, fact.name, fact.data_type, fact.tags, fact.glossary_terms, graph
        )
        if _OUTCOME_RANK[outcome.kind] > _OUTCOME_RANK[worst.kind]:
            worst = outcome
    return worst


def _guarded_verdicts(
    resolved: ResolvedQuery, graph: PolicyGraph, enforcement: EnforcementSettings
) -> list[Verdict]:
    """Guard predicates/aggregates on sensitive columns laundered through CTEs or subqueries.

    Output masking already happens at the base column; this closes the leak where the base value
    is filtered on, or aggregated, after being aliased away (README edge 4, 6, 7).
    """
    seen: set[tuple[str, str, str]] = set()
    out: list[Verdict] = []
    for ref in resolved.guarded:
        outcome = _worst_outcome(ref.base, graph)
        if outcome.kind == "allow":
            continue
        urn, fact = ref.base[0]
        ds = graph.dataset(urn)
        if ds is None:
            continue
        verdict = _guarded_verdict(
            outcome, ref, ds.name, fact, _catalog_url(graph, ds.urn), enforcement
        )
        if verdict is None:
            continue
        # Key on action too: the same (subject, code) can yield both a nulling deny_column and a
        # statement-denying deny_column (a denied column projected AND used in GROUP BY). Deduping
        # on (subject, code) alone would drop the stronger deny_statement and let the query run.
        key = (verdict.subject, str(verdict.code), verdict.action)
        if key not in seen:
            seen.add(key)
            out.append(verdict)
    return out


def _guarded_verdict(
    outcome: Outcome,
    ref: GuardedRef,
    table: str,
    fact: ColumnFact,
    url: str,
    enforcement: EnforcementSettings,
) -> Verdict | None:
    subject = Subject.column(table, fact.name)
    if outcome.kind == "deny":
        if ref.in_aggregate:
            return Verdict.make(
                ReasonCode.DENY_AGGREGATE,
                "deny_statement",
                subject,
                f"Aggregating over {table}.{fact.name} is denied, even laundered through a subquery.",
                hint="Use COUNT(*) or aggregate over a non-sensitive key.",
                catalog_url=url,
            )
        return Verdict.make(
            ReasonCode.DENY_COLUMN,
            "deny_statement",
            subject,
            f"{table}.{fact.name} is denied and cannot be used in a {ref.context.value}, even via a subquery.",
            hint="Remove it from the filter/ordering.",
            catalog_url=url,
        )
    if ref.context == Context.PREDICATE and enforcement.predicate_policy == "deny":
        return Verdict.make(
            ReasonCode.PREDICATE_GUARD,
            "deny_statement",
            subject,
            f"{table}.{fact.name} is masked; filtering on it (even via a subquery) would leak membership.",
            hint="Remove the predicate, or set predicate_policy: transform.",
            catalog_url=url,
        )
    return None  # masked value laundered into GROUP BY / ORDER BY operates on masked data: allowed


def _column_verdicts(
    resolved: ResolvedQuery, graph: PolicyGraph, enforcement: EnforcementSettings
) -> list[Verdict]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Verdict] = []
    for col in resolved.columns:
        outcome = outcome_for(col, graph)
        if outcome.kind == "allow":
            continue
        verdict = _verdict_for_column(col, outcome, graph, enforcement)
        if verdict is None:
            continue
        # Include the action: a denied column both projected (nulled -> deny_column) and used in
        # GROUP BY (deny_statement) shares (subject, code); deduping on those two alone would drop
        # the deny_statement and let the query run against the raw column.
        key = (verdict.subject, str(verdict.code), verdict.action)
        if key in seen:
            continue
        seen.add(key)
        out.append(verdict)
    return out


def _verdict_for_column(
    col: ColumnRef, outcome: Outcome, graph: PolicyGraph, enforcement: EnforcementSettings
) -> Verdict | None:
    ds = col.table.effective
    assert ds is not None
    subject = Subject.column(ds.name, col.fact.name)
    url = _catalog_url(graph, ds.urn)
    classification = _classification_phrase(col)

    if outcome.kind == "deny":
        if col.context == Context.PROJECTION and not col.in_aggregate:
            return Verdict.make(
                ReasonCode.DENY_COLUMN,
                "deny_column",
                subject,
                f"{ds.name}.{col.fact.name} is {classification}; it is nulled for every principal.",
                hint="For cardinality, aggregate over a non-sensitive column instead.",
                catalog_url=url,
            )
        if col.in_aggregate:
            return Verdict.make(
                ReasonCode.DENY_AGGREGATE,
                "deny_statement",
                subject,
                f"Aggregating over {ds.name}.{col.fact.name} ({classification}) is denied.",
                hint="Use COUNT(*) or aggregate over a non-sensitive key.",
                catalog_url=url,
            )
        return Verdict.make(
            ReasonCode.DENY_COLUMN,
            "deny_statement",
            subject,
            f"{ds.name}.{col.fact.name} ({classification}) cannot be used in a {col.context.value}.",
            hint="Remove the column from the filter/ordering, or query a non-sensitive column.",
            catalog_url=url,
        )

    # mask outcome
    if col.context == Context.PREDICATE:
        if enforcement.predicate_policy == "deny":
            return Verdict.make(
                ReasonCode.PREDICATE_GUARD,
                "deny_statement",
                subject,
                f"{ds.name}.{col.fact.name} is masked; filtering on it would leak row membership.",
                hint="Remove the predicate, or set predicate_policy: transform to compare masked values.",
                catalog_url=url,
            )
        return Verdict.make(
            ReasonCode.PREDICATE_GUARD,
            "note",
            subject,
            f"{ds.name}.{col.fact.name} is masked; the predicate compares masked values.",
            hint="Results reflect masked comparisons, not raw values.",
            catalog_url=url,
        )
    if col.context == Context.ORDER_BY:
        return Verdict.make(
            ReasonCode.MASK_ORDER_NOTE,
            "note",
            subject,
            f"{ds.name}.{col.fact.name} is masked; ordering by it is allowed but not meaningful.",
            catalog_url=url,
        )
    return Verdict.make(
        ReasonCode.MASK,
        "mask",
        subject,
        f"{ds.name}.{col.fact.name} is {classification}; masked with strategy {outcome.strategy}.",
        hint=strategy_hint(outcome.strategy or "hash"),
        catalog_url=url,
    )


def _limit_verdicts(
    resolved: ResolvedQuery, principal: Principal, enforcement: EnforcementSettings
) -> list[Verdict]:
    from airlock.analyzer.rewrite import existing_limit  # local import avoids a cycle

    limit = effective_row_limit(principal, enforcement)
    existing = existing_limit(resolved.expression)
    if existing is not None and existing <= limit:
        return []
    return [
        Verdict.make(
            ReasonCode.ROW_LIMIT,
            "limit",
            Subject.statement(),
            f"A row limit of {limit} was applied.",
            hint="Ask for a narrower query or an aggregate if you need the full population.",
        )
    ]


def _classification_phrase(col: ColumnRef) -> str:
    if col.fact.glossary_terms:
        return f"classified {sorted(col.fact.glossary_terms)[0]}"
    if col.fact.tags:
        return f"tagged {sorted(col.fact.tags)[0]}"
    return "sensitive"


def _catalog_url(graph: PolicyGraph, urn: str) -> str:
    return f"{graph.source_url.rstrip('/')}/dataset/{urn}"
