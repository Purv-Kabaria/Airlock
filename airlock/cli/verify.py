"""Prove Airlock's masking actually runs on this warehouse.

`airlock doctor` answers "can I reach the database". This answers the harder question an adopter has
before trusting the gateway with production traffic: *does the enforcement itself work here?* One set
of mask templates is rendered per sqlglot dialect, so the honest way to know a warehouse is supported
is to render each strategy into that dialect, run it, and look at what comes back.

Read-only and schema-free. Every probe masks a literal inside a scalar subquery, so nothing is
created, no table is read, and no permission beyond "may run a SELECT" is needed - which means it is
safe to point at production. A warehouse that passes here will mask correctly on real columns,
because it is the same template, the same renderer, and the same post-flight shape check the gateway
uses on every query.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlglot import exp

from airlock.masking import mask_expression, verify_value

_COLUMN = "c"
_ALIAS = "masked"


@dataclass(frozen=True, slots=True)
class Probe:
    strategy: str
    sample: exp.Expression
    expected: str | None  # None when the output is not fixed (a salted hash)
    note: str


@dataclass(frozen=True, slots=True)
class ProbeResult:
    strategy: str
    sql: str
    value: object
    ok: bool
    detail: str


def _text(value: str) -> exp.Expression:
    return exp.Literal.string(value)


# One probe per strategy that produces SQL. `null` is excluded: it renders to the literal NULL and
# exercises nothing about the warehouse. Samples are chosen so a correct mask has one right answer,
# which is what makes a wrong dialect rendering visible rather than merely plausible.
PROBES: tuple[Probe, ...] = (
    Probe("hash", _text("ada@corp.com"), None, "equality-preserving digest"),
    Probe("partial_email", _text("ada@corp.com"), "a***@corp.com", "first letter + domain"),
    Probe("partial_phone", _text("555-123-7890"), "***-7890", "last four digits"),
    Probe("partial_phone", _text("12345"), "***", "short value redacted whole"),
    Probe("fixed_string", _text("anything"), "***", "constant replacement"),
    Probe(
        "generalize_date",
        exp.cast(_text("2026-07-15"), "DATE"),
        "2026-07-01",
        "date generalized to the month",
    ),
)


def probe_statement(probe: Probe, *, dialect: str, salt: str) -> str:
    """The SELECT that masks this probe's literal, rendered in the warehouse's own dialect.

    The literal is wrapped in a subquery so the mask applies to a *column reference*, exactly as it
    does in a real query - masking a bare literal would take a different sqlglot path and prove less.
    """
    masked = mask_expression(probe.strategy, exp.column(_COLUMN), salt=salt)
    source = exp.select(exp.alias_(probe.sample, _COLUMN))
    statement = exp.select(exp.alias_(masked, _ALIAS)).from_(
        exp.Subquery(this=source, alias=exp.TableAlias(this=exp.to_identifier("airlock_probe")))
    )
    return statement.sql(dialect=dialect)


def check_value(probe: Probe, value: object) -> tuple[bool, str]:
    """Did the warehouse return what this strategy promises?

    Two gates: the post-flight shape check the gateway itself applies to every masked column, and -
    where the output is deterministic - the exact expected value. The exact check is what catches a
    dialect that renders something plausible but wrong (a substring offset that is off by one, a
    hash that comes back as bytes).
    """
    if value is None:
        return False, "returned NULL; the mask did not evaluate"
    if not verify_value(probe.strategy, value):
        return False, f"failed the shape check for {probe.strategy}: {value!r}"
    if probe.expected is None:
        return True, str(value)
    actual = str(value)
    # A date column may come back as a date or a timestamp depending on the driver; compare on the
    # prefix so `2026-07-01` and `2026-07-01T00:00:00` both pass.
    if actual.startswith(probe.expected):
        return True, actual
    return False, f"expected {probe.expected!r}, got {actual!r}"


async def run_probes(
    adapter: object, *, dialect: str, salt: str, timeout: float
) -> list[ProbeResult]:
    """Execute every probe, collecting results rather than stopping at the first failure.

    A partial failure is the interesting case - it says *which* strategy a warehouse mishandles, so
    the operator can drop that one from their rules and still use the gateway.
    """
    from airlock.errors import AirlockError

    results: list[ProbeResult] = []
    for probe in PROBES:
        sql = probe_statement(probe, dialect=dialect, salt=salt)
        try:
            result = await adapter.run(sql, timeout=timeout, row_limit=1)  # type: ignore[attr-defined]
        except AirlockError as exc:
            results.append(ProbeResult(probe.strategy, sql, None, False, str(exc).splitlines()[0]))
            continue
        value = result.rows[0].get(_ALIAS) if result.rows else None
        ok, detail = check_value(probe, value)
        results.append(ProbeResult(probe.strategy, sql, value, ok, detail))
    return results
