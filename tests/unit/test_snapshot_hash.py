"""The content hash must move when any decision-affecting setting changes.

The decision cache and the audit trail both key on `content_hash`; a setting that changes a decision
but not the hash would serve a stale cached plan and record the wrong snapshot for a replay.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from airlock.policy.graph import EnforcementSettings, PolicyGraph

_FIXED = datetime(2026, 1, 1, tzinfo=UTC)  # compile time is not part of the content hash


def _graph(enforcement: EnforcementSettings) -> PolicyGraph:
    return PolicyGraph.build(
        datasets={},
        lineage={},
        rules=(),
        enforcement=enforcement,
        principals={},
        compiled_at=_FIXED,
        source_url="http://localhost:9002",
    )


def test_lineage_propagation_moves_the_hash() -> None:
    on = _graph(EnforcementSettings(lineage_propagation="on"))
    off = _graph(EnforcementSettings(lineage_propagation="off"))
    assert on.content_hash != off.content_hash


def test_table_matching_moves_the_hash() -> None:
    exact = _graph(EnforcementSettings(table_matching="exact"))
    suffix = _graph(EnforcementSettings(table_matching="suffix"))
    assert exact.content_hash != suffix.content_hash


def test_every_enforcement_field_moves_the_hash() -> None:
    # Guard against a new decision-affecting setting being added to EnforcementSettings without also
    # being folded into the hash. Every field, flipped to a different valid value, must change it.
    base = EnforcementSettings()
    alt = {
        "mode": "monitor",
        "unknown_tables": "allow",
        "predicate_policy": "transform",
        "substitution": "off",
        "lineage_propagation": "off",
        "table_matching": "suffix",
        "default_row_limit": 500,
        "default_statement_timeout": 5.0,
    }
    base_hash = _graph(base).content_hash
    for field, value in alt.items():
        changed = dataclasses.replace(base, **{field: value})
        assert _graph(changed).content_hash != base_hash, f"{field} does not move the hash"
