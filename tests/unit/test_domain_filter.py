"""Compiling only the domains you run Airlock for.

An org with thousands of datasets running the gateway for one team should not pay to compile, hold
in memory, or content-hash the rest of the company. The filter is applied server-side in the search
query, so the datasets never come back at all.

The dangerous failure here is a filter that matches nothing: it compiles an empty policy, which
denies every query. That is fail-closed, but undiagnosable from the outside, so it must raise.
"""

from __future__ import annotations

from typing import Any

import pytest

from airlock.errors import SnapshotUnavailableError
from airlock.policy.compile import _domain_filter, _list_dataset_urns

MARKETING = "urn:li:domain:594f5c3f-marketing"


class _FakeClient:
    """Answers the two GraphQL shapes compile.py sends, and records the filters it received."""

    def __init__(self, datasets: dict[str, list[str]], domains: dict[str, str]) -> None:
        self._datasets = datasets  # domain urn (or "" for unfiltered) -> dataset urns
        self._domains = domains  # display name -> urn
        self.filters_seen: list[list[dict[str, Any]]] = []

    def execute_graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        if "findDomain" in query:
            name = variables["name"]
            return {
                "search": {
                    "searchResults": [
                        {"entity": {"urn": urn, "properties": {"name": display}}}
                        for display, urn in self._domains.items()
                        # DataHub search is fuzzy, so a query returns near-matches too; the caller
                        # is responsible for the exact-name check. Model that here.
                        if name.lower() in display.lower()
                    ]
                }
            }
        self.filters_seen.append(variables["and"])
        domain = next(
            (f["values"][0] for f in variables["and"] if f["field"] == "domains"),
            "",
        )
        urns = self._datasets.get(domain, [])
        start = variables["start"]
        page = urns[start : start + variables["count"]]
        return {
            "search": {
                "start": start,
                "count": len(page),
                "total": len(urns),
                "searchResults": [{"entity": {"urn": u}} for u in page],
            }
        }


def _client() -> _FakeClient:
    return _FakeClient(
        datasets={"": ["ds:a", "ds:b", "ds:c"], MARKETING: ["ds:a", "ds:b"]},
        domains={"Marketing": MARKETING, "Marketing Analytics": "urn:li:domain:other"},
    )


def test_no_filter_compiles_the_whole_platform() -> None:
    client = _client()
    assert _list_dataset_urns(client, "urn:li:dataPlatform:duckdb") == ["ds:a", "ds:b", "ds:c"]
    # Only the platform filter is sent; nothing narrows the search by accident.
    assert [f["field"] for f in client.filters_seen[0]] == ["platform"]


def test_a_domain_filter_is_applied_server_side() -> None:
    client = _client()
    urns = _list_dataset_urns(client, "urn:li:dataPlatform:duckdb", ["Marketing"])
    assert urns == ["ds:a", "ds:b"]
    fields = [f["field"] for f in client.filters_seen[0]]
    assert fields == ["platform", "domains"], "the domain filter must reach the search query"


def test_a_domain_urn_is_passed_through_untouched() -> None:
    # DataHub often assigns a GUID rather than a readable id; an operator who has it should not
    # have to round-trip through a name lookup.
    assert _domain_filter(_client(), [MARKETING]) == [MARKETING]


def test_a_name_resolves_only_on_an_exact_match() -> None:
    # Search is fuzzy: "Marketing" also returns "Marketing Analytics". Taking both would silently
    # widen the snapshot past what the operator asked for.
    assert _domain_filter(_client(), ["Marketing"]) == [MARKETING]


def test_a_misspelled_domain_refuses_rather_than_denying_everything() -> None:
    with pytest.raises(SnapshotUnavailableError, match="not a domain in this DataHub"):
        _domain_filter(_client(), ["Marketng"])


def test_filtering_changes_the_snapshot_hash(tmp_path) -> None:
    # The filter changes which datasets exist, so it must change the content hash - otherwise the
    # decision cache could serve plans built against a wider catalog than the one now configured.
    from datetime import UTC, datetime

    from airlock.policy.graph import DatasetFacts, EnforcementSettings, PolicyGraph

    def graph(names: list[str]) -> PolicyGraph:
        return PolicyGraph.build(
            datasets={
                n: DatasetFacts(urn=n, platform="duckdb", name=n, env="PROD", columns=())
                for n in names
            },
            lineage={},
            column_lineage={},
            rules=(),
            enforcement=EnforcementSettings(),
            principals={},
            compiled_at=datetime(2026, 1, 1, tzinfo=UTC),
            source_url="http://localhost:8080",
        )

    assert graph(["a", "b", "c"]).content_hash != graph(["a", "b"]).content_hash
