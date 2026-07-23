"""Parse, normalize, and fail closed on anything Airlock cannot analyze.

Every guard here maps to a row in the README edge-case table:
  * multi-statement / non-select  -> AIRLOCK-404 (edge 9, 29)
  * unparseable SQL               -> AIRLOCK-401 (edge 1)
  * natural language              -> AIRLOCK-406 (edge 27)
  * pathological size/depth       -> AIRLOCK-405 (edge 30)
Comments are dropped before analysis so nothing can hide in them (edge 28).
"""

from __future__ import annotations

import re
from typing import cast

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError as SqlglotParseError

from airlock.errors import InputLimitError, NotSqlError, ParseError, StatementClassError

MAX_SQL_BYTES = 1_000_000
MAX_NODES = 20_000
MAX_IN_LIST = 4_096

# Statements that begin with one of these keywords are SQL, not prose, even when they read like
# a bare phrase (e.g. `DROP TABLE users`). Left out of this set deliberately: SHOW/SET, so that a
# real `SHOW TABLES` (two tokens) is handled by statement-class, while `show me top customers`
# (prose) still trips the natural-language guard below.
_STATEMENT_STARTERS = frozenset(
    {
        "select",
        "with",
        "values",
        "insert",
        "update",
        "delete",
        "create",
        "drop",
        "alter",
        "truncate",
        "explain",
        "describe",
        "desc",
        "use",
        "grant",
        "revoke",
        "vacuum",
        "attach",
        "detach",
        "call",
        "pragma",
        "begin",
        "commit",
        "rollback",
        "checkpoint",
        "copy",
        "merge",
    }
)
_SQL_PUNCT = re.compile(r"[(),;*=<>]")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def looks_like_natural_language(text: str) -> bool:
    """Heuristic pre-parse check for prose sent to a SQL tool (edge 27).

    Fires only on clearly English input: a statement that starts with something other than a SQL
    keyword, contains no SELECT/FROM and none of SQL's structural punctuation, and has several
    words - e.g. `show me top customers`. Valid SQL, including DDL, is never flagged.
    """
    stripped = text.strip()
    if not stripped:
        return False
    words = _WORD.findall(stripped)
    if not words or words[0].lower() in _STATEMENT_STARTERS:
        return False
    lowered = stripped.lower()
    if "select" in lowered or "from" in lowered:
        return False
    if _SQL_PUNCT.search(stripped):
        return False
    return len(words) >= 3


def normalize(sql: str, dialect: str) -> str:
    """Strip comments and trailing punctuation; return canonical single-statement text."""
    tree = sqlglot.parse_one(sql, dialect=dialect)
    return tree.sql(dialect=dialect, comments=False)


def parse_single(sql: str, dialect: str) -> exp.Expression:
    """Parse exactly one analyzable statement or raise the right typed AirlockError."""
    if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
        raise InputLimitError(
            f"Query is {len(sql)} bytes; the limit is {MAX_SQL_BYTES}.",
            hint="Split the work into smaller queries.",
        )
    if looks_like_natural_language(sql):
        raise NotSqlError(
            "This looks like natural language, not SQL.",
            hint="warehouse_run_query takes a SQL statement, not a question. Call "
            "warehouse_list_tables to see what you can query, then send SELECT <columns> FROM <table>.",
        )

    try:
        parsed = sqlglot.parse(sql, dialect=dialect)
        statements = [
            s
            for s in parsed
            if s is not None
            and not isinstance(s, exp.Semicolon)
            and s.sql(dialect=dialect, comments=False).strip()
        ]
    except RecursionError as exc:
        raise InputLimitError("Query nesting is too deep to analyze.") from exc
    except SqlglotParseError as exc:
        raise ParseError(_first_parse_message(exc)) from exc

    if not statements:
        raise ParseError("Empty query: nothing to run.")
    if len(statements) > 1:
        raise StatementClassError(
            f"Received {len(statements)} statements; only one is allowed per call.",
            hint="Send a single statement. Multi-statement requests are rejected whole.",
        )

    stmt = cast(exp.Expression, statements[0])
    _scan_and_sanitize(stmt)
    return stmt


def _scan_and_sanitize(stmt: exp.Expression) -> None:
    """One pass over the AST that does every per-node parse-time check and mutation:

      * node-count and IN-list caps, so a pathological tree is rejected before analysis (edge 30),
      * a projectionless SELECT (`SELECT`, `SELECT FROM t`) is rejected - sqlglot parses it but it
        is not runnable SQL and the rewriter would emit `SELECT LIMIT 10000` (fail closed),
      * comments are dropped from every node so nothing can hide in them (edge 28).

    These were three separate `walk()`s; one traversal is a third of the tree-walking on the parse
    hot path, and the node-count guard still trips mid-walk, so the huge-tree protection is intact.
    """
    for node_count, node in enumerate(stmt.walk(), start=1):
        if node_count > MAX_NODES:
            raise InputLimitError(f"Query has more than {MAX_NODES} nodes.")
        if isinstance(node, exp.Select) and not node.expressions:
            raise ParseError("Query selects no columns.")
        if isinstance(node, exp.In):
            values = node.args.get("expressions") or []
            if len(values) > MAX_IN_LIST:
                raise InputLimitError(
                    f"IN list has {len(values)} items; the limit is {MAX_IN_LIST}."
                )
        if node.comments:
            node.comments = None


_SELECT_ROOTS = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery)


def statement_class(stmt: exp.Expression) -> str:
    """One of: select, insert, update, delete, ddl, explain, command."""
    if isinstance(stmt, _SELECT_ROOTS):
        return "select"
    if isinstance(stmt, exp.Insert):
        return "insert"
    if isinstance(stmt, exp.Update):
        return "update"
    if isinstance(stmt, exp.Delete):
        return "delete"
    if isinstance(stmt, (exp.Create, exp.Drop, exp.Alter, exp.TruncateTable)):
        return "ddl"
    if isinstance(stmt, exp.Command) and stmt.name.upper() == "EXPLAIN":
        return "explain"
    return "command"


def _first_parse_message(exc: SqlglotParseError) -> str:
    errors = getattr(exc, "errors", None)
    if errors:
        first = errors[0]
        desc = first.get("description", "syntax error")
        line = first.get("line")
        col = first.get("col")
        if line is not None and col is not None:
            return f"{desc} at line {line}, column {col}."
        return f"{desc}."
    return "The query did not parse."
