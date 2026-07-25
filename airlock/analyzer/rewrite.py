"""Apply a decision to the AST: mask, null, substitute, and cap the row limit.

The rewriter recomputes each column's outcome from the same `column_outcome` the decision
engine uses, so the executed SQL and the verdict envelope are guaranteed to agree. It mutates
the already-qualified AST in place — decide has already run and read what it needs — then
renders the executed SQL in the target dialect.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from sqlglot import exp

from airlock.analyzer.resolve import Context, ResolvedQuery
from airlock.engine.decide import effective_row_limit, outcome_for
from airlock.masking import mask_expression
from airlock.policy.graph import PolicyGraph, Principal


@dataclass(frozen=True, slots=True)
class RewriteResult:
    executed_sql: str  # what runs on the warehouse: carries the real masking salt as a literal
    row_limit: int
    modified: bool
    # The same SQL with the masking salt redacted. The salt must reach the warehouse (it computes the
    # hash there), but everything downstream of execution — the envelope the agent reads, the audit
    # log, the DataHub usage write-back — must not carry it, or the "secret salt" the hash strategy
    # relies on is handed straight to the party it defends against. Only executed_sql goes to the DB.
    display_sql: str
    masked_outputs: tuple[
        tuple[str, str], ...
    ] = ()  # (output column alias, strategy) for post-flight


# Placeholder that replaces the salt literal in display_sql. Fixed and obviously-not-a-secret so a
# reader can see a mask ran without learning the value that keys it.
_SALT_PLACEHOLDER = "'<masking-salt>'"


def _redact_salt(sql: str, salt: str) -> str:
    """Replace the rendered salt literal with a placeholder. The salt lands in the SQL as a single
    quoted literal with internal quotes doubled (see masking.mask_expression); rebuild that exact
    form and swap it out. A no-op when the query used no salted mask."""
    if not salt:
        return sql
    literal = "'" + salt.replace("'", "''") + "'"
    return sql.replace(literal, _SALT_PLACEHOLDER)


def existing_limit(expr: exp.Expression) -> int | None:
    limit = expr.args.get("limit")
    if isinstance(limit, exp.Limit):
        value = limit.expression
        if isinstance(value, exp.Literal) and value.is_int:
            return int(value.name)
    return None


def rewrite(
    resolved: ResolvedQuery,
    principal: Principal,
    graph: PolicyGraph,
    *,
    enforce: bool = True,
    salt: str | None = None,
) -> RewriteResult:
    """Rewrite `resolved` for execution. With enforce=False (monitor mode) only the row limit is
    injected — masks, nulls, and substitutions are observed as verdicts but not applied.

    `salt` seeds the equality-preserving hash mask; pass a deployment secret. When None it falls
    back to the (public) snapshot hash, which is fine for the demo but weaker in production.
    """
    expr = resolved.expression
    dialect = resolved.dialect
    salt = salt or graph.content_hash.split(":")[-1][:16]
    modified = False
    masked_outputs: list[tuple[str, str]] = []

    if enforce:
        for table in resolved.tables:
            if table.substitute_to is not None:
                _rename_table(table.node, table.substitute_to.name)
                modified = True

        # A correlated column is bound once per clause it is visible from, so the same AST node can
        # appear twice in `resolved.columns`. Replacing it twice would graft the mask onto a node
        # already detached from the tree, silently dropping the second rewrite.
        replaced: set[int] = set()
        for col in resolved.columns:
            if id(col.node) in replaced:
                continue
            outcome = outcome_for(col, graph)
            if outcome.kind == "mask":
                if (
                    col.context == Context.PREDICATE
                    and graph.enforcement.predicate_policy != "transform"
                ):
                    continue  # a masked predicate under deny policy denies the statement; not rewritten
                strategy = outcome.strategy or "hash"
                if col.context == Context.PROJECTION:
                    masked_outputs.append((_output_alias(col.node), strategy))
                col.node.replace(mask_expression(strategy, col.node, salt=salt))
                replaced.add(id(col.node))
                modified = True
            elif (
                outcome.kind == "deny"
                and col.context == Context.PROJECTION
                and not col.in_aggregate
            ):
                col.node.replace(exp.Null())
                replaced.add(id(col.node))
                modified = True

    limit = effective_row_limit(principal, graph.enforcement)
    query = cast(exp.Query, expr)
    current = existing_limit(expr)
    if current is None or current > limit:
        query = query.limit(limit, copy=False)

    executed_sql = query.sql(dialect=dialect)
    return RewriteResult(
        executed_sql=executed_sql,
        row_limit=limit,
        modified=modified,
        display_sql=_redact_salt(executed_sql, salt),
        masked_outputs=tuple(masked_outputs),
    )


def _output_alias(col: exp.Column) -> str:
    parent = col.parent
    if isinstance(parent, exp.Alias):
        return parent.alias
    return col.name


def _rename_table(table: exp.Table, target_name: str) -> None:
    """Point a table node at its substitute while preserving the alias so columns still resolve.

    Clears the db/catalog parts the target does not have, so substituting a schema-qualified table
    with a bare one (or vice versa) never leaves a stale prefix behind.
    """
    parts = target_name.split(".")
    table.set("this", exp.to_identifier(parts[-1]))
    table.set("db", exp.to_identifier(parts[-2]) if len(parts) > 1 else None)
    table.set("catalog", exp.to_identifier(parts[-3]) if len(parts) > 2 else None)
