"""Typed Airlock errors. Every error carries a ReasonCode, a human reason, and a hint.

At the MCP boundary these become `AIRLOCK-4xx` envelopes with a request_id; the traceback
goes to the log, never to the wire (README "Error message design"). Internal code raises
the narrowest of these it can name — never a bare Exception, never `except Exception: pass`.
"""

from __future__ import annotations

from airlock.engine.verdicts import ReasonCode, Subject, Verdict, VerdictAction


class AirlockError(Exception):
    """Base for everything Airlock raises across a module boundary."""

    action: VerdictAction = "deny_statement"

    def __init__(
        self,
        code: ReasonCode,
        reason: str,
        *,
        hint: str | None = None,
        subject: Subject | str | None = None,
        catalog_url: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.hint = hint
        self.subject = str(subject) if subject is not None else "statement:query"
        self.catalog_url = catalog_url

    def to_verdict(self) -> Verdict:
        return Verdict(
            code=self.code,
            action=self.action,
            subject=self.subject,
            reason=self.reason,
            hint=self.hint,
            catalog_url=self.catalog_url,
        )


class ParseError(AirlockError):
    """SQL failed to parse in the target dialect. Fail closed: never forwarded."""

    def __init__(self, reason: str, *, hint: str | None = None) -> None:
        super().__init__(
            ReasonCode.PARSE_ERROR,
            reason,
            hint=hint or "Send a single, syntactically valid SQL statement for this dialect.",
        )


class NotSqlError(AirlockError):
    def __init__(self, reason: str, *, hint: str) -> None:
        super().__init__(ReasonCode.NOT_SQL, reason, hint=hint)


class InputLimitError(AirlockError):
    def __init__(self, reason: str, *, hint: str | None = None) -> None:
        super().__init__(
            ReasonCode.INPUT_LIMIT,
            reason,
            hint=hint or "Reduce the query size or nesting depth and resend.",
        )


class UnknownTableError(AirlockError):
    def __init__(self, table: str, *, hint: str | None = None) -> None:
        super().__init__(
            ReasonCode.UNKNOWN_TABLE,
            f"Table {table} is not present in the catalog.",
            subject=Subject.table(table),
            hint=hint
            or "Call warehouse_list_tables to see the exact names you can query, then retry with one "
            "of those. If this table should exist, register it in DataHub.",
        )


class StarUnknownSchemaError(AirlockError):
    def __init__(self, table: str) -> None:
        super().__init__(
            ReasonCode.STAR_UNKNOWN_SCHEMA,
            f"Cannot expand SELECT * on {table}: its schema is unknown to the catalog.",
            subject=Subject.table(table),
            hint="Name explicit columns, or register the table's schema in DataHub.",
        )


class DynamicColumnsError(AirlockError):
    """A COLUMNS(...) dynamic selector (regex/lambda/star) that cannot be resolved to concrete
    columns. Fail closed: it would select columns Airlock never classified, so masking/denial
    could not apply (a real leak: `SELECT COLUMNS('.*') FROM t` returns every column raw)."""

    def __init__(self) -> None:
        super().__init__(
            ReasonCode.DYNAMIC_COLUMNS,
            "COLUMNS(...) dynamic column selection cannot be policy-checked and is not allowed.",
            hint="Name the explicit columns you need; Airlock masks or denies them per catalog policy.",
        )


class UnknownColumnError(AirlockError):
    """A column referenced on a catalogued table that the catalog schema does not list. Fail closed
    under unknown_tables=deny: an uncatalogued column is ungoverned, and a warehouse whose schema
    has drifted ahead of the catalog could otherwise return a new, untagged sensitive column raw."""

    def __init__(self, table: str, column: str) -> None:
        super().__init__(
            ReasonCode.UNKNOWN_COLUMN,
            f"Column {column} is not in the catalog schema for {table}; it cannot be classified.",
            subject=Subject.column(table, column),
            hint="Ingest the column into DataHub so its classification is known, or select only "
            "catalogued columns. Set unknown_tables: allow to pass uncatalogued references through.",
        )


class TableFunctionError(AirlockError):
    """A table-valued function in FROM (read_csv, read_text, glob, range, ...). These are not
    catalog datasets and can perform arbitrary I/O (file, HTTP, S3 via httpfs), so they are denied
    unconditionally - even when unknown_tables is set to allow. Airlock governs cataloged tables."""

    def __init__(self, rendered: str) -> None:
        super().__init__(
            ReasonCode.TABLE_FUNCTION,
            f"Table-valued function {rendered} is not a governed table and is not permitted.",
            subject=Subject.table(rendered),
            hint="Query a cataloged table by name. Table functions bypass catalog policy and are denied.",
        )


class StatementClassError(AirlockError):
    def __init__(self, reason: str, *, hint: str, config_key: str | None = None) -> None:
        if config_key:
            hint = f"{hint} (enable via {config_key})"
        super().__init__(ReasonCode.STATEMENT_CLASS, reason, hint=hint)


class UnknownPrincipalError(AirlockError):
    def __init__(self, reason: str, *, hint: str) -> None:
        super().__init__(ReasonCode.UNKNOWN_PRINCIPAL, reason, hint=hint)


class StaleSnapshotError(AirlockError):
    def __init__(self, reason: str, *, hint: str | None = None) -> None:
        super().__init__(
            ReasonCode.STALE_SNAPSHOT,
            reason,
            hint=hint or "Restore DataHub connectivity or set stale_policy: serve_stale_readonly.",
        )


class MaskVerifyError(AirlockError):
    action: VerdictAction = "deny_statement"

    def __init__(self, reason: str) -> None:
        super().__init__(
            ReasonCode.MASK_VERIFY_FAILED,
            reason,
            hint="This response was withheld and logged as an incident; retry the query.",
        )


class OverloadedError(AirlockError):
    def __init__(self, retry_after_ms: int) -> None:
        super().__init__(
            ReasonCode.OVERLOADED,
            "The gateway is at its concurrency cap.",
            hint=f"Retry after {retry_after_ms} ms.",
        )
        self.retry_after_ms = retry_after_ms


class WarehouseUnavailableError(AirlockError):
    def __init__(self, warehouse: str, detail: str) -> None:
        super().__init__(
            ReasonCode.WAREHOUSE_UNAVAILABLE,
            f"The {warehouse} warehouse was unreachable: {detail}.",
            hint="Verify the warehouse is up and the DSN is correct, then retry.",
        )


class ConfigError(Exception):
    """Configuration is invalid. Raised at load time with a positional, named message.

    Not an AirlockError: it never crosses the MCP wire — it stops startup before serving.
    """


class SnapshotUnavailableError(Exception):
    """`airlock serve` cannot compile a policy snapshot from DataHub. Fail fast (README §10)."""
