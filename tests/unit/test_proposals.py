"""airlock propose: the grouping of suspected gaps, and the read-modify-write that keeps the audit
sink and the proposal writer from clobbering each other's structured properties on a shared dataset.
No network: the DataHub client is faked behind the two methods the writer calls."""

from __future__ import annotations

from datahub.metadata.schema_classes import (
    StructuredPropertiesClass,
    StructuredPropertyValueAssignmentClass,
)

from airlock.audit.datahub_sink import _merge_and_emit, _prop_urn
from airlock.cli.main import _proposals_from_gaps
from airlock.policy.coverage import SuspectedGap


class FakeGraph:
    """Captures the aspect emitted and serves a preset current aspect back, like DataHubGraph."""

    def __init__(self, current: StructuredPropertiesClass | None) -> None:
        self._current = current
        self.emitted: StructuredPropertiesClass | None = None

    def get_aspect(self, *, entity_urn: str, aspect_type: type) -> object | None:
        return self._current

    def emit_mcp(self, mcp: object) -> None:
        self.emitted = mcp.aspect  # type: ignore[attr-defined]


def _assignment(prop: str, *values: str | float) -> StructuredPropertyValueAssignmentClass:
    return StructuredPropertyValueAssignmentClass(propertyUrn=_prop_urn(prop), values=list(values))


def test_merge_preserves_foreign_properties_and_replaces_the_named_one() -> None:
    current = StructuredPropertiesClass(
        properties=[
            _assignment("airlock.suspectedSensitive", "customer_phone: looks like phone number"),
            _assignment("airlock.deniedAttempts", 3.0),
        ]
    )
    graph = FakeGraph(current)
    # The audit sink rewrites deniedAttempts; suspectedSensitive must survive untouched.
    _merge_and_emit(graph, "urn:li:dataset:x", [_assignment("airlock.deniedAttempts", 4.0)])

    assert graph.emitted is not None
    by_prop = {a.propertyUrn: a.values for a in graph.emitted.properties}
    assert by_prop[_prop_urn("airlock.deniedAttempts")] == [4.0]  # replaced
    assert by_prop[_prop_urn("airlock.suspectedSensitive")] == [
        "customer_phone: looks like phone number"
    ]  # preserved


def test_merge_writes_cleanly_when_the_dataset_has_no_properties_yet() -> None:
    graph = FakeGraph(None)
    _merge_and_emit(graph, "urn:li:dataset:x", [_assignment("airlock.suspectedSensitive", "a: b")])
    assert graph.emitted is not None
    assert len(graph.emitted.properties) == 1


def test_proposals_group_one_value_list_per_dataset() -> None:
    gaps = (
        SuspectedGap("orders", "urn:orders", "customer_phone", "VARCHAR", "phone number"),
        SuspectedGap("orders", "urn:orders", "backup_email", "VARCHAR", "email address"),
        SuspectedGap("leads", "urn:leads", "dob", "DATE", "date of birth"),
    )
    grouped = _proposals_from_gaps(gaps)
    assert set(grouped) == {"urn:orders", "urn:leads"}
    assert grouped["urn:orders"] == (
        "customer_phone: looks like phone number",
        "backup_email: looks like email address",
    )
    assert grouped["urn:leads"] == ("dob: looks like date of birth",)
