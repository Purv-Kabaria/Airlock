"""Strategy registry. Each strategy turns a column reference into a masking SQL expression.

Expressions are built by templating the (already qualified) column SQL into a dialect string
and reparsing, so the result renders correctly for whatever warehouse dialect is active. The
`hash` strategy is salted-but-deterministic (equality-preserving), which is what keeps
`GROUP BY` and `COUNT(DISTINCT ...)` correct on masked keys.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import sqlglot
from sqlglot import exp

# Explicit strategy -> SQL template. `{col}` is the qualified column SQL, `{salt}` a stable salt.
# Templates avoid regex backreferences on purpose: dialects disagree on backslash escaping in
# string literals, so we stay on portable scalar functions (SUBSTR / SPLIT_PART / RIGHT / MD5).
_TEMPLATES: dict[str, str] = {
    "null": "NULL",
    "hash": "MD5('{salt}' || CAST({col} AS VARCHAR))",
    "partial_email": "SUBSTR(CAST({col} AS VARCHAR), 1, 1) || '***@' || SPLIT_PART(CAST({col} AS VARCHAR), '@', 2)",
    # The length guard is load-bearing: RIGHT(x, 4) on a value of four characters or fewer returns
    # the whole value, so without it the strategy stops masking exactly when the data is shortest.
    # Below a real phone number's length there is nothing safe to reveal, so reveal nothing.
    "partial_phone": (
        "CASE WHEN LENGTH(CAST({col} AS VARCHAR)) >= 7 "
        "THEN '***-' || RIGHT(CAST({col} AS VARCHAR), 4) ELSE '***' END"
    ),
    "generalize_date": "DATE_TRUNC('month', {col})",
    "fixed_string": "'***'",
}

_HINTS: dict[str, str] = {
    "null": "Values are nulled; the column carries no signal.",
    "hash": "Masked values preserve equality: GROUP BY / COUNT(DISTINCT ...) remain correct.",
    "partial_email": "Only the first character and domain survive; equality is not preserved.",
    "partial_phone": "Only the last four digits survive; equality is not preserved.",
    "generalize_date": "Dates are generalized to the first of the month.",
    "fixed_string": "Every value is replaced by a constant.",
}

# `auto`/`partial` defer the concrete choice to resolve_strategy, keyed on column name + type.
AUTO_ALIASES = frozenset({"auto", "partial"})


def _is_temporal(data_type: str) -> bool:
    return any(t in data_type.upper() for t in ("DATE", "TIME"))


def resolve_strategy(spec_strategy: str, *, column_name: str, data_type: str) -> str:
    """Concrete strategy name for a column. Explicit names pass through; `auto`/`partial` infer.

    An explicit strategy the column's type cannot support degrades to `hash` rather than emitting
    SQL the warehouse will reject. `hash` is at least as private as anything it replaces, so the
    degrade never weakens a policy — and one wrong strategy in airlock.yaml costs a coarser mask
    instead of failing every read of that column. The name returned here is the one the verdict
    reports, so the envelope always names the mask that actually ran.
    """
    if spec_strategy not in AUTO_ALIASES:
        if spec_strategy not in _TEMPLATES:
            raise ValueError(f"unknown masking strategy {spec_strategy!r}")
        # DATE_TRUNC does not bind against a non-temporal column. Every other template casts to
        # VARCHAR first, so this is the only strategy with a type precondition.
        if spec_strategy == "generalize_date" and not _is_temporal(data_type):
            return "hash"
        return spec_strategy
    name = column_name.lower()
    if "email" in name:
        return "partial_email"
    if "phone" in name or name.endswith("_tel"):
        return "partial_phone"
    if _is_temporal(data_type):
        return "generalize_date"
    return "hash"


def mask_expression(
    strategy: str, column: exp.Column, *, dialect: str, salt: str
) -> exp.Expression:
    """The masking expression for `column`, ready to replace it in the AST."""
    template = _TEMPLATES.get(strategy)
    if template is None:
        raise ValueError(f"unknown masking strategy {strategy!r}")
    col_sql = column.sql(dialect=dialect)
    # The salt lands inside a single-quoted SQL literal; double any quote so a salt with an
    # apostrophe cannot break out of the literal (operator-config footgun, not attacker input).
    rendered = template.format(col=col_sql, salt=salt.replace("'", "''"))
    return cast(exp.Expression, sqlglot.parse_one(rendered, dialect=dialect))


def strategy_hint(strategy: str) -> str:
    return _HINTS.get(strategy, "This column is masked before it reaches you.")


def verify_value(strategy: str, value: object) -> bool:
    """Post-flight shape check: does a returned value look like this strategy's output?

    Defense in depth (README edge 17). A masked column whose values do not match the strategy's
    shape means the mask did not apply — the response is withheld rather than risk a leak.
    """
    if value is None:
        return True
    if strategy == "null":
        return value is None
    text = str(value)
    if strategy == "hash":
        return len(text) == 32 and all(c in "0123456789abcdef" for c in text)
    if strategy == "partial_email":
        return "***" in text
    if strategy == "partial_phone":
        return text.startswith("***-") or text == "***"  # short values redact whole
    if strategy == "fixed_string":
        return text == "***"
    return True  # generalize_date and unknown strategies have no cheap shape to assert


StrategyFn = Callable[[exp.Column, str, str], exp.Expression]

# The public registry name referenced by masking.__init__; extensible via entry points later.
STRATEGIES: dict[str, str] = dict(_TEMPLATES)
