"""Reason codes, the Verdict, and Envelope construction.

This module owns the *only* allocation table for `AIRLOCK-NNN` codes. Never write a bare
`"AIRLOCK-123"` anywhere else — reference `ReasonCode.<NAME>`. Each code carries one
comment explaining what it means; the `TITLES` map gives the short human phrase that
leads every reason sentence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator


class ReasonCode(StrEnum):
    # -- 1xx: column-level masking and column handling --------------------------------
    MASK = "AIRLOCK-110"  # column masked because it carries a mask-classified tag/term
    MASK_ORDER_NOTE = "AIRLOCK-111"  # masked column used in ORDER BY: allowed, but meaningless
    UNION_STRICTEST = "AIRLOCK-112"  # union column adopts the strictest branch classification
    MASK_LINEAGE = (
        "AIRLOCK-113"  # untagged column masked: derives from a masked column (col lineage)
    )
    DENY_COLUMN = "AIRLOCK-120"  # column hard-denied for every principal (e.g. PII.SSN)
    DENY_AGGREGATE = "AIRLOCK-121"  # aggregate over a denied column (COUNT(ssn)) is itself denied
    DENY_LINEAGE = (
        "AIRLOCK-122"  # untagged column denied: derives from a denied column (col lineage)
    )
    PREDICATE_GUARD = (
        "AIRLOCK-130"  # masked column in WHERE/JOIN/HAVING: membership-inference guard
    )
    ROW_LIMIT = "AIRLOCK-150"  # row-limit injected / result truncated
    MONITOR = "AIRLOCK-160"  # monitor mode: verdicts observed but not enforced

    # -- 2xx: certified-table substitution --------------------------------------------
    SUBSTITUTE = "AIRLOCK-201"  # deprecated/uncertified table redirected to a certified equivalent
    SUBSTITUTE_DOWNGRADE = "AIRLOCK-202"  # substitution downgraded to a warning (schema mismatch)

    # -- 3xx: scope / domain denial ---------------------------------------------------
    SCOPE_DENY = "AIRLOCK-301"  # table lies outside the principal's permitted domains/platforms

    # -- 4xx: faults (never leak a traceback; these cross the wire) --------------------
    PARSE_ERROR = "AIRLOCK-401"  # SQL did not parse in the target dialect
    STAR_UNKNOWN_SCHEMA = "AIRLOCK-402"  # SELECT * against a table with no known schema
    UNKNOWN_TABLE = "AIRLOCK-403"  # referenced table is absent from the catalog
    STATEMENT_CLASS = (
        "AIRLOCK-404"  # DDL/DML/multi-statement/SET/SHOW disallowed for this principal
    )
    INPUT_LIMIT = "AIRLOCK-405"  # query exceeded a size/depth limit before analysis
    NOT_SQL = "AIRLOCK-406"  # input looks like natural language, not SQL
    DYNAMIC_COLUMNS = "AIRLOCK-407"  # a COLUMNS(...) dynamic selector we cannot resolve to columns
    TABLE_FUNCTION = (
        "AIRLOCK-408"  # table-valued function in FROM (read_csv, glob, ...): never governed
    )
    UNKNOWN_COLUMN = (
        "AIRLOCK-409"  # a column on a known table that the catalog schema does not list
    )
    STALE_SNAPSHOT = "AIRLOCK-410"  # policy snapshot is older than the staleness budget
    MASK_VERIFY_FAILED = "AIRLOCK-420"  # post-flight sample showed a masked column leaked its shape
    UNKNOWN_PRINCIPAL = "AIRLOCK-430"  # missing/unknown key -> anonymous deny-all principal
    OVERLOADED = "AIRLOCK-440"  # concurrency cap exceeded; retry-after
    WAREHOUSE_UNAVAILABLE = "AIRLOCK-441"  # warehouse unreachable after one retry


TITLES: dict[ReasonCode, str] = {
    ReasonCode.MASK: "column masked",
    ReasonCode.MASK_ORDER_NOTE: "ordering on a masked column is not meaningful",
    ReasonCode.UNION_STRICTEST: "union column takes the strictest classification",
    ReasonCode.MASK_LINEAGE: "column masked by inherited classification",
    ReasonCode.DENY_COLUMN: "column denied",
    ReasonCode.DENY_AGGREGATE: "aggregate over a denied column",
    ReasonCode.DENY_LINEAGE: "column denied by inherited classification",
    ReasonCode.PREDICATE_GUARD: "masked column used in a predicate",
    ReasonCode.ROW_LIMIT: "row limit applied",
    ReasonCode.MONITOR: "monitor mode: not enforced",
    ReasonCode.SUBSTITUTE: "table substituted",
    ReasonCode.SUBSTITUTE_DOWNGRADE: "substitution downgraded to a warning",
    ReasonCode.SCOPE_DENY: "table outside your scope",
    ReasonCode.PARSE_ERROR: "query did not parse",
    ReasonCode.STAR_UNKNOWN_SCHEMA: "cannot expand * without a schema",
    ReasonCode.UNKNOWN_TABLE: "table not in the catalog",
    ReasonCode.STATEMENT_CLASS: "statement type not permitted",
    ReasonCode.INPUT_LIMIT: "query too large or too deeply nested",
    ReasonCode.NOT_SQL: "input is not SQL",
    ReasonCode.DYNAMIC_COLUMNS: "dynamic column selection is not supported",
    ReasonCode.TABLE_FUNCTION: "table-valued functions are not permitted",
    ReasonCode.UNKNOWN_COLUMN: "column is not in the catalog schema",
    ReasonCode.STALE_SNAPSHOT: "policy snapshot is stale",
    ReasonCode.MASK_VERIFY_FAILED: "masking verification failed",
    ReasonCode.UNKNOWN_PRINCIPAL: "unknown principal",
    ReasonCode.OVERLOADED: "gateway at capacity",
    ReasonCode.WAREHOUSE_UNAVAILABLE: "warehouse unavailable",
}

# Codes for which a hint is mandatory: any action the reader might want to work around.
_HINT_REQUIRED = {
    ReasonCode.MASK,
    ReasonCode.MASK_LINEAGE,
    ReasonCode.DENY_COLUMN,
    ReasonCode.DENY_LINEAGE,
    ReasonCode.DENY_AGGREGATE,
    ReasonCode.PREDICATE_GUARD,
    ReasonCode.SUBSTITUTE_DOWNGRADE,
    ReasonCode.SCOPE_DENY,
    ReasonCode.STAR_UNKNOWN_SCHEMA,
    ReasonCode.UNKNOWN_TABLE,
    ReasonCode.STATEMENT_CLASS,
    ReasonCode.NOT_SQL,
    ReasonCode.DYNAMIC_COLUMNS,
    ReasonCode.TABLE_FUNCTION,
    ReasonCode.UNKNOWN_COLUMN,
    ReasonCode.UNKNOWN_PRINCIPAL,
}


VerdictAction = Literal[
    "allow",
    "mask",
    "deny_column",
    "deny_statement",
    "substitute",
    "limit",
    "note",
    "scope_deny",
]

SubjectKind = Literal["column", "table", "statement"]


@dataclass(frozen=True, slots=True)
class Subject:
    """The thing a verdict is about. Renders as `column:dim_users.email` / `table:users_raw`."""

    kind: SubjectKind
    ref: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.ref}"

    @classmethod
    def column(cls, table: str, name: str) -> Subject:
        return cls("column", f"{table}.{name}")

    @classmethod
    def table(cls, name: str) -> Subject:
        return cls("table", name)

    @classmethod
    def statement(cls, label: str = "query") -> Subject:
        return cls("statement", label)


class Verdict(BaseModel):
    """One decision about one subject. Frozen: verdicts are produced, never mutated."""

    model_config = ConfigDict(frozen=True)

    code: ReasonCode
    action: VerdictAction
    subject: str
    reason: str
    hint: str | None = None
    catalog_url: str | None = None

    @model_validator(mode="after")
    def _require_hint(self) -> Verdict:
        if self.code in _HINT_REQUIRED and not self.hint:
            raise ValueError(f"verdict {self.code} requires an actionable hint")
        return self

    @classmethod
    def make(
        cls,
        code: ReasonCode,
        action: VerdictAction,
        subject: Subject | str,
        reason: str,
        *,
        hint: str | None = None,
        catalog_url: str | None = None,
    ) -> Verdict:
        return cls(
            code=code,
            action=action,
            subject=str(subject),
            reason=reason,
            hint=hint,
            catalog_url=catalog_url,
        )


class EnvelopeStatus(StrEnum):
    EXECUTED = "executed"
    EXECUTED_WITH_MODIFICATIONS = "executed_with_modifications"
    DENIED = "denied"
    ERROR = "error"


class Envelope(BaseModel):
    """The structured MCP response: rows + every verdict + references. This is the wire shape."""

    model_config = ConfigDict(frozen=True)

    status: EnvelopeStatus
    request_id: str
    principal: str
    original_sql: str
    executed_sql: str | None = None
    rows: list[dict[str, Any]] | None = None
    columns: list[str] | None = None
    row_count: int | None = None
    truncated: bool = False
    verdicts: list[Verdict] = []
    policy_snapshot: str | None = None
    audit_ref: str | None = None

    def is_ok(self) -> bool:
        return self.status in (
            EnvelopeStatus.EXECUTED,
            EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS,
        )

    @classmethod
    def error(
        cls,
        *,
        request_id: str,
        principal: str,
        original_sql: str,
        verdict: Verdict,
        snapshot: str | None,
    ) -> Envelope:
        return cls(
            status=EnvelopeStatus.ERROR,
            request_id=request_id,
            principal=principal,
            original_sql=original_sql,
            verdicts=[verdict],
            policy_snapshot=snapshot,
        )

    @classmethod
    def denied(
        cls,
        *,
        request_id: str,
        principal: str,
        original_sql: str,
        verdicts: list[Verdict],
        snapshot: str | None,
    ) -> Envelope:
        return cls(
            status=EnvelopeStatus.DENIED,
            request_id=request_id,
            principal=principal,
            original_sql=original_sql,
            verdicts=verdicts,
            policy_snapshot=snapshot,
        )

    @classmethod
    def executed(
        cls,
        *,
        request_id: str,
        principal: str,
        original_sql: str,
        executed_sql: str,
        columns: list[str] | None,
        rows: list[dict[str, Any]] | None,
        verdicts: list[Verdict],
        snapshot: str | None,
        truncated: bool,
        modified: bool,
        audit_ref: str | None = None,
    ) -> Envelope:
        status = EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS if modified else EnvelopeStatus.EXECUTED
        return cls(
            status=status,
            request_id=request_id,
            principal=principal,
            original_sql=original_sql,
            executed_sql=executed_sql,
            columns=columns,
            rows=rows,
            row_count=len(rows) if rows is not None else None,
            truncated=truncated,
            verdicts=verdicts,
            policy_snapshot=snapshot,
            audit_ref=audit_ref,
        )
