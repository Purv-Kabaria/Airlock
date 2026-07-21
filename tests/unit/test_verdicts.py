"""The reason-code table is the public contract; keep it whole.

Every AIRLOCK-NNN a caller can receive must have a human title, or the reason sentence renders with a
blank lead. This guards against a new code being added without one.
"""

from __future__ import annotations

from airlock.engine.verdicts import TITLES, ReasonCode


def test_every_reason_code_has_a_title() -> None:
    missing = [c.value for c in ReasonCode if c not in TITLES]
    assert not missing, f"reason codes without a title: {missing}"


def test_internal_fault_is_distinct_from_parse_error() -> None:
    # An internal gateway fault must not masquerade as a parse error, or an agent wastes a turn
    # rewriting SQL that was fine.
    assert ReasonCode.INTERNAL != ReasonCode.PARSE_ERROR
    assert TITLES[ReasonCode.INTERNAL] == "internal gateway error"
