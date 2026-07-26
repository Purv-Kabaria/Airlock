"""The plain-language summary line under an envelope's status.

It is the first line a stranger reads, so it has to be accurate and derived only from the verdicts
the machine also reads — never a second, drifting source of truth.
"""

from __future__ import annotations

from airlock.cli.render import _summarize
from airlock.engine.verdicts import EnvelopeStatus, ReasonCode


def test_counts_each_change_in_plain_words() -> None:
    pairs = [
        ("AIRLOCK-201", "substitute", "table:users_raw"),
        ("AIRLOCK-110", "mask", "column:dim_users.email"),
        ("AIRLOCK-110", "mask", "column:dim_users.phone"),
        ("AIRLOCK-120", "deny_column", "column:dim_users.ssn"),
        ("AIRLOCK-150", "limit", "statement:query"),  # always-on noise: excluded
    ]
    got = _summarize(pairs, EnvelopeStatus.EXECUTED_WITH_MODIFICATIONS)
    assert got == "1 table redirected · 2 columns masked · 1 column removed."


def test_clean_query_says_nothing_hidden() -> None:
    got = _summarize([("AIRLOCK-150", "limit", "statement:query")], EnvelopeStatus.EXECUTED)
    assert got is not None and "Nothing hidden or removed" in got


def test_denied_names_the_blocker() -> None:
    pairs = [("AIRLOCK-120", "deny_statement", "column:dim_users.ssn")]
    got = _summarize(pairs, EnvelopeStatus.DENIED)
    assert got is not None and "Blocked on column:dim_users.ssn" in got


def test_denied_counts_extra_blockers() -> None:
    pairs = [("AIRLOCK-301", "scope_deny", "table:payroll"), ("AIRLOCK-120", "deny_statement", "column:x.y")]
    got = _summarize(pairs, EnvelopeStatus.DENIED)
    assert got is not None and "+1 more" in got


def test_error_has_no_summary() -> None:
    # The single error verdict's reason is the whole message; a summary would just repeat it.
    assert _summarize([("AIRLOCK-401", "deny_statement", "statement:query")], EnvelopeStatus.ERROR) is None


def test_monitor_mode_never_claims_a_column_was_changed() -> None:
    """The one summary that could actively mislead.

    Monitor mode emits the same mask and deny verdicts enforcement does, but applies none of them -
    the rows come back raw. Reporting "1 column masked" there would tell an operator they are
    protected at the exact moment they are not.
    """
    observed = [
        ("AIRLOCK-110", "mask", "column:dim_users.email"),
        ("AIRLOCK-120", "deny_column", "column:dim_users.ssn"),
        (str(ReasonCode.MONITOR), "note", "statement:query"),
    ]
    got = _summarize(observed, EnvelopeStatus.EXECUTED)
    assert got is not None
    assert "nothing was changed" in got.lower()
    assert "unmasked" in got.lower()
    assert "masked ·" not in got and "removed" not in got
