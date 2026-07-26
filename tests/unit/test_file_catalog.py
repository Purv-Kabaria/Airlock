"""The local catalog source: enforcement for people who have no DataHub.

The bar is that a file-sourced snapshot enforces exactly like a DataHub-sourced one - same rules,
same verdicts - and that everything DataHub uniquely provides is absent honestly rather than faked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from airlock.analyzer.resolve import resolve
from airlock.config import AirlockConfig
from airlock.engine.decide import decide
from airlock.errors import ConfigError, SnapshotUnavailableError
from airlock.policy.compile import compile_snapshot
from airlock.policy.file_catalog import load_catalog_file

CATALOG = """
datasets:
  - name: users
    certified: true
    domain: Marketing
    owners: [data-team]
    columns:
      - { name: id }
      - { name: email, tags: [PII] }
      - { name: ssn, terms: [Classification.SSN] }
  - name: users_old
    deprecated: true
    replaced_by: users
    columns:
      - { name: id }
      - { name: email, tags: [PII] }
      - { name: ssn, terms: [Classification.SSN] }
"""


def _config(tmp_path: Path, catalog: str = CATALOG) -> AirlockConfig:
    (tmp_path / "catalog.yaml").write_text(catalog, encoding="utf-8")
    return AirlockConfig.model_validate(
        {
            "catalog": {"file": str(tmp_path / "catalog.yaml")},
            "warehouse": {"kind": "sqlite", "dsn": str(tmp_path / "app.db")},
            "rules": [
                {"id": "pii", "match": {"tag": "PII"}, "action": {"mask": "auto"}},
                {"id": "ssn", "match": {"glossary_term": "Classification.SSN"}, "action": "deny"},
                {
                    "id": "dep",
                    "match": {"lifecycle": "DEPRECATED"},
                    "action": "substitute_certified",
                },
            ],
            "principals": [{"name": "agent", "key": "k"}],
            "masking": {"salt": "s"},
            "audit": {"jsonl": str(tmp_path / "a.jsonl"), "datahub_writeback": False},
        }
    )


def _verdicts(cfg: AirlockConfig, sql: str) -> list[str]:
    graph = compile_snapshot(cfg)
    resolved = resolve(sql, dialect="sqlite", graph=graph, enforcement=graph.enforcement)
    return [v.code for v in decide(resolved, graph.principal("agent"), graph)]


def test_a_file_snapshot_masks_and_denies_like_datahub_does(tmp_path) -> None:
    codes = _verdicts(_config(tmp_path), "SELECT email, ssn FROM users")
    assert "AIRLOCK-110" in codes  # email masked
    assert "AIRLOCK-120" in codes  # ssn denied


def test_replaced_by_drives_substitution(tmp_path) -> None:
    # `replaced_by` stands in for the DataHub lineage edge, so a deprecated table still redirects.
    codes = _verdicts(_config(tmp_path), "SELECT id FROM users_old")
    assert "AIRLOCK-201" in codes


def test_verdicts_carry_no_broken_catalog_link(tmp_path) -> None:
    graph = compile_snapshot(_config(tmp_path))
    resolved = resolve(
        "SELECT email FROM users", dialect="sqlite", graph=graph, enforcement=graph.enforcement
    )
    masked = [
        v for v in decide(resolved, graph.principal("agent"), graph) if v.code == "AIRLOCK-110"
    ]
    # A file path is not a URL; inventing `./catalog.yaml/dataset/urn:...` would be a broken link
    # presented to the agent as a citation.
    assert masked and masked[0].catalog_url is None


def test_exactly_one_catalog_source_is_required(tmp_path) -> None:
    base = _config(tmp_path).model_dump()
    with pytest.raises(Exception, match="no catalog source"):
        AirlockConfig.model_validate({**base, "catalog": None, "datahub": None})
    with pytest.raises(Exception, match="exactly one source"):
        AirlockConfig.model_validate({**base, "datahub": {"url": "http://localhost:8080"}})


def test_a_missing_file_says_how_to_create_one(tmp_path) -> None:
    cfg = _config(tmp_path)
    Path(cfg.catalog.file).unlink()  # type: ignore[union-attr]
    with pytest.raises(SnapshotUnavailableError, match="init --local"):
        compile_snapshot(cfg)


@pytest.mark.parametrize(
    "bad,message",
    [
        ("datasets: []", "lists no datasets"),
        ("datasets:\n  - name: a\n  - name: a\n", "listed twice"),
        ("datasets:\n  - name: a\n    replaced_by: ghost\n", "not a dataset in this file"),
        ("datasets:\n  - name: a\n    colums: []\n", "colums"),
    ],
)
def test_a_hand_written_file_fails_with_the_field_named(tmp_path, bad, message) -> None:
    # This file is typed by a human, so a typo is the likeliest failure. It must never be a traceback.
    path = tmp_path / "catalog.yaml"
    path.write_text(bad, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_catalog_file(path, "sqlite")


def test_column_lineage_is_absent_not_faked(tmp_path) -> None:
    # DataHub uniquely supplies column-level lineage. Without it, classification cannot propagate -
    # the honest outcome is an empty map, never an invented edge.
    graph = compile_snapshot(_config(tmp_path))
    users = next(d for d in graph.datasets.values() if d.name == "users")
    email = next(c for c in users.columns if c.name == "email")
    assert graph.lineage.upstream_columns(email.urn) == ()
