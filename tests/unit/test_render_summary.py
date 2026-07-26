"""The plain-language summary line under an envelope's status.

It is the first line a stranger reads, so it has to be accurate and derived only from the verdicts
the machine also reads — never a second, drifting source of truth.
"""

from __future__ import annotations

from airlock.cli.render import _summarize
from airlock.engine.verdicts import EnvelopeStatus


def test_counts_each_change_in_plain_words() -> None:
    pairs = [
        ("substitute", "table:users_raw"),
        ("mask", "column:dim_users.email"),
        ("mask", "column:dim_users.phone"),
        ("deny_column", "column:dim_users.ssn"),
        ("limit", "statement:query"),  # always-on noise: excluded from the summary
    ]
    got = _summarize(pairs, EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS)
    assert got == "1 table redirected · 2 columns masked · 1 column removed."


def test_clean_query_says_nothing_hidden() -> None:
    got = _summarize([("limit", "statement:query")], EnvelopeStatus.EXECUTED)
    assert got is not None and "Nothing hidden or removed" in got


def test_denied_names_the_blocker() -> None:
    pairs = [("deny_statement", "column:dim_users.ssn")]
    got = _summarize(pairs, EnvelopeStatus.DENIED)
    assert got is not None and "Blocked on column:dim_users.ssn" in got


def test_denied_counts_extra_blockers() -> None:
    pairs = [("scope_deny", "table:payroll"), ("deny_statement", "column:x.y")]
    got = _summarize(pairs, EnvelopeStatus.DENIED)
    assert got is not None and "+1 more" in got


def test_error_has_no_summary() -> None:
    # The single error verdict's reason is the whole message; a summary would just repeat it.
    assert _summarize([("deny_statement", "statement:query")], EnvelopeStatus.ERROR) is None
