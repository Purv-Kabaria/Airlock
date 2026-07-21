"""Resolve a statement to catalog facts: qualify, expand *, and bind every base-table column.

Output is a `ResolvedQuery`: the qualified AST plus, for each physical-table column reference,
the dataset URN, the `ColumnFact`, and the clause it appears in. Table substitution (deprecated
-> certified) is decided here because it changes which dataset a column's facts come from; the
choice is principal-independent, so decide and rewrite consume it without recomputing.

Enforcement of *what happens* to a resolved column lives in `engine.decide` / `analyzer.rewrite`.
This module only answers "what is this, and what is it classified as."
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlglot import exp
from sqlglot.errors import OptimizeError
from sqlglot.errors import ParseError as SqlglotParseError
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import traverse_scope

from airlock.analyzer.parse import parse_single, statement_class
from airlock.errors import (
    DynamicColumnsError,
    ParseError,
    StarUnknownSchemaError,
    TableFunctionError,
    UnknownColumnError,
    UnknownTableError,
)
from airlock.policy.graph import ColumnFact, DatasetFacts, EnforcementSettings, PolicyGraph
from airlock.policy.rules import ActionKind, rule_applies


class Context(StrEnum):
    PROJECTION = "projection"
    PREDICATE = "predicate"  # WHERE / JOIN ON / HAVING
    GROUP_BY = "group_by"
    ORDER_BY = "order_by"


@dataclass(slots=True)
class TableRef:
    node: exp.Table
    name_written: str
    dataset: DatasetFacts | None  # original catalog facts; None when unknown
    substitute_to: DatasetFacts | None = None  # certified replacement when eligible
    substitute_note: str | None = None  # set when substitution is downgraded to a warning

    @property
    def effective(self) -> DatasetFacts | None:
        return self.substitute_to or self.dataset


@dataclass(slots=True)
class ColumnRef:
    node: exp.Column
    table: TableRef
    dataset_urn: str
    fact: ColumnFact
    context: Context
    in_aggregate: bool


@dataclass(slots=True)
class GuardedRef:
    """A column used in a predicate/aggregate whose value is *laundered* through a CTE or subquery.

    Its source is another scope, not a base table, so it is not a `ColumnRef` — but it still
    derives from one or more base columns. `base` lists those (dataset_urn, fact) pairs so the
    decision engine can guard a predicate on, or an aggregate over, a sensitive column even when
    an attacker hides it behind aliases (README edge 4, 6, 7).
    """

    context: Context
    in_aggregate: bool
    base: list[tuple[str, ColumnFact]]


@dataclass(slots=True)
class ResolvedQuery:
    expression: exp.Expression
    dialect: str
    statement_class: str
    original_sql: str
    tables: list[TableRef] = field(default_factory=list)
    columns: list[ColumnRef] = field(default_factory=list)
    guarded: list[GuardedRef] = field(default_factory=list)

    def substitutions(self) -> list[TableRef]:
        return [t for t in self.tables if t.substitute_to is not None]


def build_schema_for(
    stmt: exp.Expression, graph: PolicyGraph
) -> tuple[dict[str, Any], dict[int, TableRef]]:
    """Build a sqlglot schema keyed by how each known table is *written* in the query.

    Keying by the written form (bare `orders`, or `retail.orders`) guarantees qualify's star
    expansion and column qualification find every table the catalog knows. Returns the schema
    and a map from table-node id to its resolved `TableRef`.
    """
    cte_names = {c.alias_or_name.lower() for c in stmt.find_all(exp.CTE)}
    schema: dict[str, Any] = {}
    table_map: dict[int, TableRef] = {}
    for table in stmt.find_all(exp.Table):
        if table.name.lower() in cte_names and not table.db:
            continue  # a reference to a CTE, not a catalog table
        written = _written_name(table)
        ds = graph.dataset_by_name(written)
        ref = TableRef(node=table, name_written=written, dataset=ds)
        table_map[id(table)] = ref
        if ds is not None:
            _register_schema(schema, table, ds)
    return schema, table_map


def resolve(
    sql: str, *, dialect: str, graph: PolicyGraph, enforcement: EnforcementSettings
) -> ResolvedQuery:
    stmt = parse_single(sql, dialect)
    stmt_class = statement_class(stmt)
    if stmt_class != "select":
        # Nothing to resolve; the decision engine denies on statement class.
        return ResolvedQuery(
            expression=stmt, dialect=dialect, statement_class=stmt_class, original_sql=sql
        )

    # A COLUMNS(...) selector (DuckDB) is never expanded by qualify, so its columns are never
    # bound, classified, or masked - it would return them raw. We cannot enforce policy on it, so
    # fail closed before anything executes.
    if stmt.find(exp.Columns):
        raise DynamicColumnsError()

    # Table-valued functions in FROM (read_csv/read_text/glob/range/... ) are not catalog datasets
    # and can read files or URLs. Deny unconditionally, independent of unknown_tables, so a
    # permissive unknown_tables setting can never open arbitrary I/O through the gateway.
    for table in stmt.find_all(exp.Table):
        if isinstance(table.this, exp.Func):
            raise TableFunctionError(table.sql(dialect=dialect))

    schema, table_map = build_schema_for(stmt, graph)
    tables = list(table_map.values())

    unknown = [t for t in tables if t.dataset is None]
    if unknown and enforcement.unknown_tables == "deny":
        raise UnknownTableError(unknown[0].name_written)

    if stmt.find(exp.Star) and any(t.dataset is not None and not t.dataset.columns for t in tables):
        empty = next(t for t in tables if t.dataset is not None and not t.dataset.columns)
        raise StarUnknownSchemaError(empty.name_written)

    # In fail-closed mode (unknown_tables=deny) validate every column against the catalog schema:
    # a column the catalog does not list - qualified or not - cannot be classified, so it must be
    # denied rather than passed through raw (a warehouse whose schema drifted ahead of the catalog
    # would otherwise leak a new, untagged column). Under `allow` we infer instead.
    fail_closed = enforcement.unknown_tables == "deny"
    try:
        qualified = qualify(
            stmt,
            schema=schema,
            dialect=dialect,
            qualify_columns=True,
            expand_stars=True,
            validate_qualify_columns=fail_closed,
            infer_schema=not fail_closed,
        )
    except OptimizeError as exc:
        unknown_col = _unresolved_column(exc)
        if fail_closed and unknown_col is not None:
            raise UnknownColumnError(_only_table_name(tables), unknown_col) from exc
        raise ParseError(f"Could not resolve columns: {exc}") from exc
    except SqlglotParseError as exc:
        raise ParseError(f"Could not resolve columns: {exc}") from exc

    _decide_substitutions(qualified, table_map, graph, enforcement)

    columns, guarded = _bind_columns(qualified, table_map)
    return ResolvedQuery(
        expression=qualified,
        dialect=dialect,
        statement_class=stmt_class,
        original_sql=sql,
        tables=tables,
        columns=columns,
        guarded=guarded,
    )


def _decide_substitutions(
    qualified: exp.Expression,
    table_map: dict[int, TableRef],
    graph: PolicyGraph,
    enforcement: EnforcementSettings,
) -> None:
    if enforcement.substitution == "off":
        return
    sub_rules = [r for r in graph.rules if r.action.kind == ActionKind.SUBSTITUTE_CERTIFIED]
    if not sub_rules:
        return
    referenced = _referenced_columns_by_table(qualified, table_map)
    for ref in table_map.values():
        ds = ref.dataset
        if ds is None:
            continue
        if not any(
            rule_applies(
                r,
                tags=ds.tags,
                terms=ds.glossary_terms,
                lifecycle=ds.lifecycle,
                certification=ds.certification,
                domain=ds.domain,
            )
            for r in sub_rules
        ):
            continue
        candidates = graph.certified_substitutes(ds.urn)
        if not candidates:
            ref.substitute_note = "no certified downstream equivalent exists in the catalog"
            continue
        referenced_cols = referenced.get(id(ref.node), set())
        sub, missing = _pick_substitute(candidates, referenced_cols)
        if sub is None:
            # Every certified equivalent lacks a referenced column; report the closest one's gap.
            near, near_missing = missing
            ref.substitute_note = (
                f"certified equivalent {near.name} is missing columns {sorted(near_missing)}"
            )
            continue
        if enforcement.substitution == "rewrite":
            ref.substitute_to = sub
        else:  # warn: surface the option without redirecting
            ref.substitute_note = (
                f"certified equivalent {sub.name} available (substitution in warn mode)"
            )


_GUARDED = (Context.PREDICATE, Context.GROUP_BY, Context.ORDER_BY)


def _bind_columns(
    qualified: exp.Expression, table_map: dict[int, TableRef]
) -> tuple[list[ColumnRef], list[GuardedRef]]:
    out: list[ColumnRef] = []
    guarded: list[GuardedRef] = []
    for scope in traverse_scope(qualified):
        select = scope.expression
        if not isinstance(select, exp.Select):
            continue
        for col, context, in_agg in _iter_column_contexts(select):
            src = scope.sources.get(col.table)
            if not isinstance(src, exp.Table):
                # References a CTE/subquery output. The base value is masked/nulled at its source,
                # so the *output* is safe. But a predicate on it, or an aggregate over it, can still
                # leak — so trace it back to base facts and record a guard.
                if context in _GUARDED or in_agg:
                    base = _trace_base_facts(col.name, src, table_map)
                    if base:
                        guarded.append(GuardedRef(context=context, in_aggregate=in_agg, base=base))
                continue
            ref = table_map.get(id(src))
            if ref is None:
                continue
            effective = ref.effective
            if effective is None:
                continue
            fact = effective.column(col.name)
            if fact is None:
                continue  # uncatalogued column: under allow it passes through; deny caught upstream
            out.append(
                ColumnRef(
                    node=col,
                    table=ref,
                    dataset_urn=effective.urn,
                    fact=fact,
                    context=context,
                    in_aggregate=in_agg,
                )
            )
    return out, guarded


def _trace_base_facts(
    name: str, scope: object, table_map: dict[int, TableRef], depth: int = 0
) -> list[tuple[str, ColumnFact]]:
    """Trace an output column of `scope` back to the base (dataset_urn, ColumnFact) pairs it derives
    from, recursing through nested CTEs/subqueries and both branches of a UNION."""
    if depth > 24:
        return []
    inner_scopes = getattr(scope, "union_scopes", None) or [scope]
    results: list[tuple[str, ColumnFact]] = []
    for inner in inner_scopes:
        select = getattr(inner, "expression", None)
        if not isinstance(select, exp.Select):
            continue
        for proj in select.selects:
            if proj.alias_or_name.lower() != name.lower():
                continue
            for c in proj.find_all(exp.Column):
                src = inner.sources.get(c.table)
                if isinstance(src, exp.Table):
                    ref = table_map.get(id(src))
                    eff = ref.effective if ref is not None else None
                    fact = eff.column(c.name) if eff is not None else None
                    if eff is not None and fact is not None:
                        results.append((eff.urn, fact))
                elif src is not None:
                    results += _trace_base_facts(c.name, src, table_map, depth + 1)
    return results


def _iter_column_contexts(
    select: exp.Select,
) -> Iterator[tuple[exp.Column, Context, bool]]:
    for proj in select.expressions:
        for col in proj.find_all(exp.Column):
            yield col, Context.PROJECTION, _under_aggregate(col, proj)
    for arg, ctx in (
        ("where", Context.PREDICATE),
        ("having", Context.PREDICATE),
        ("qualify", Context.PREDICATE),  # DuckDB/Snowflake post-window filter; leaks like WHERE
        ("group", Context.GROUP_BY),
        ("order", Context.ORDER_BY),
    ):
        node = select.args.get(arg)
        if node is not None:
            for col in node.find_all(exp.Column):
                yield col, ctx, _under_aggregate(col, node)
    for join in select.args.get("joins") or []:
        on = join.args.get("on")
        if on is not None:
            for col in on.find_all(exp.Column):
                yield col, Context.PREDICATE, _under_aggregate(col, on)


def _under_aggregate(col: exp.Expression, stop: exp.Expression) -> bool:
    node = col.parent
    while node is not None and node is not stop:
        if isinstance(node, exp.AggFunc):
            return True
        node = node.parent
    return False


def _referenced_columns_by_table(
    qualified: exp.Expression, table_map: dict[int, TableRef]
) -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    for scope in traverse_scope(qualified):
        if not isinstance(scope.expression, exp.Select):
            continue
        for col in scope.expression.find_all(exp.Column):
            src = scope.sources.get(col.table)
            if isinstance(src, exp.Table) and id(src) in table_map:
                out.setdefault(id(src), set()).add(col.name.lower())
    return out


def _incompatible_columns(referenced: set[str], sub: DatasetFacts) -> set[str]:
    have = {c.name.lower() for c in sub.columns}
    return {name for name in referenced if name not in have}


def _pick_substitute(
    candidates: tuple[DatasetFacts, ...], referenced: set[str]
) -> tuple[DatasetFacts | None, tuple[DatasetFacts, set[str]]]:
    """Return (chosen equivalent, closest gap).

    The first element is the first certified equivalent whose columns cover every referenced
    column, or None if none do. The second is always the equivalent missing the fewest referenced
    columns — used to explain the downgrade when nothing fully fits. Preferring a covering
    equivalent over lineage order means a stray incompatible certified table never suppresses a
    substitution that another equivalent would satisfy.
    """
    scored = [(cand, _incompatible_columns(referenced, cand)) for cand in candidates]
    for cand, missing in scored:
        if not missing:
            return cand, (cand, missing)
    return None, min(scored, key=lambda pair: len(pair[1]))


def _register_schema(schema: dict[str, Any], table: exp.Table, ds: DatasetFacts) -> None:
    cols = {c.name: (c.data_type or "VARCHAR") for c in ds.columns}
    node: dict[str, Any] = schema
    for part in (p for p in (table.catalog, table.db) if p):
        node = node.setdefault(part, {})
    node[table.name] = cols


def _written_name(table: exp.Table) -> str:
    parts = [p for p in (table.catalog, table.db, table.name) if p]
    return ".".join(parts)


_UNRESOLVED_COL = re.compile(r"[Cc]olumn '([^']+)' could not be resolved|Unknown column: (\w+)")


def _unresolved_column(exc: OptimizeError) -> str | None:
    """The column name from qualify's unknown-column error, or None if this is a different error."""
    m = _UNRESOLVED_COL.search(str(exc))
    return (m.group(1) or m.group(2)) if m else None


def _only_table_name(tables: list[TableRef]) -> str:
    known = [t.name_written for t in tables if t.dataset is not None]
    return known[0] if len(known) == 1 else "the query"
