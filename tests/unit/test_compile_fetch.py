"""Unit coverage for the parallelized catalog-fetch helpers in policy/compile.py.

compile_snapshot itself needs a live DataHub (integration), but the fetch/merge logic is pure given
a client, so it is faked here behind the two methods each function calls. The parallelism must not
change results or let one dataset's failure sink the snapshot.
"""

from __future__ import annotations

from types import SimpleNamespace

from airlock.policy.compile import _fetch_column_lineage, _fetch_lineage, _map_urns


def test_map_urns_preserves_order_and_handles_empty() -> None:
    assert _map_urns([], str.upper) == []
    assert _map_urns(["c", "a", "b"], str.upper) == ["C", "A", "B"]  # input order, not completion


class _LineageClient:
    """Fakes get_related_entities; raises for one urn to prove a failure is swallowed per-urn."""

    def __init__(self, edges: dict[str, list[str]], boom: str | None = None) -> None:
        self._edges = edges
        self._boom = boom

    def get_related_entities(self, *, entity_urn, relationship_types, direction):
        assert relationship_types == ["DownstreamOf"]
        if entity_urn == self._boom:
            raise RuntimeError("gms hiccup")
        return [SimpleNamespace(urn=u) for u in self._edges.get(entity_urn, [])]


def test_fetch_lineage_merges_and_skips_empties() -> None:
    client = _LineageClient({"a": ["b", "c"], "b": [], "d": ["e"]})
    result = _fetch_lineage(client, ["a", "b", "d"])
    assert result == {"a": ("b", "c"), "d": ("e",)}  # empty "b" dropped


def test_fetch_lineage_swallows_a_single_urn_failure() -> None:
    client = _LineageClient({"a": ["b"], "c": ["d"]}, boom="a")
    result = _fetch_lineage(client, ["a", "c"])
    assert result == {"c": ("d",)}  # "a" failed, snapshot still built from the rest


class _ColumnLineageClient:
    def __init__(self, aspects: dict[str, object], boom: str | None = None) -> None:
        self._aspects = aspects
        self._boom = boom

    def get_aspect(self, *, entity_urn, aspect_type):
        if entity_urn == self._boom:
            raise RuntimeError("gms hiccup")
        return self._aspects.get(entity_urn)


def _aspect(pairs: list[tuple[list[str], list[str]]]) -> object:
    fine = [SimpleNamespace(downstreams=d, upstreams=u) for d, u in pairs]
    return SimpleNamespace(fineGrainedLineages=fine)


def test_fetch_column_lineage_merges_fine_grained_edges() -> None:
    client = _ColumnLineageClient(
        {
            "t1": _aspect([(["col:t2.contact"], ["col:t1.email"])]),
            "t2": _aspect([(["col:t3.x"], ["col:t2.a", "col:t2.b"])]),
            "t3": None,  # no aspect: contributes nothing, does not error
        }
    )
    result = _fetch_column_lineage(client, ["t1", "t2", "t3"])
    assert result == {
        "col:t2.contact": ("col:t1.email",),
        "col:t3.x": ("col:t2.a", "col:t2.b"),
    }


def test_fetch_column_lineage_swallows_a_single_urn_failure() -> None:
    client = _ColumnLineageClient({"good": _aspect([(["col:d.x"], ["col:s.y"])])}, boom="bad")
    result = _fetch_column_lineage(client, ["bad", "good"])
    assert result == {"col:d.x": ("col:s.y",)}
