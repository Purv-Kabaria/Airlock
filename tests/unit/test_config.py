"""Config boundary: env-ref resolution, durations, action compilation, and named errors."""

from __future__ import annotations

import pytest

from airlock.config import load_config, parse_duration
from airlock.errors import ConfigError
from airlock.policy.rules import ActionKind

_YAML = """
datahub:
  url: {url}
  token: ${{DH_TOKEN}}
  snapshot: {{ refresh_interval: 5m, max_staleness: 24h }}
warehouse:
  kind: duckdb
  dsn: ./wh.duckdb
rules:
  - id: pii
    match: {{ tag: PII }}
    action: {{ mask: hash }}
  - id: ssn
    match: {{ glossary_term: Classification.SSN }}
    action: deny
principals:
  - name: a
    key: ${{KEY_A}}
    scopes: {{ domains: [Marketing] }}
"""


def _write(tmp_path, body: str):
    p = tmp_path / "airlock.yaml"
    p.write_text(body, encoding="utf-8")
    return p


@pytest.mark.parametrize(
    "text,seconds",
    [("5m", 300), ("24h", 86400), ("30s", 30), ("500ms", 0.5), (10, 10)],
)
def test_parse_duration(text, seconds) -> None:
    assert parse_duration(text) == seconds


def test_env_refs_resolve(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DH_TOKEN", "secret-tok")
    monkeypatch.setenv("KEY_A", "key-123")
    cfg = load_config(_write(tmp_path, _YAML.format(url="http://gms:8080")))
    assert cfg.datahub.token == "secret-tok"
    assert cfg.principal_key_map() == {"key-123": "a"}
    assert cfg.datahub.snapshot.refresh_interval == 300
    rules = {r.id: r for r in cfg.compiled_rules()}
    assert rules["pii"].action.kind is ActionKind.MASK
    assert rules["ssn"].action.kind is ActionKind.DENY


def test_missing_env_var_is_named(tmp_path) -> None:
    with pytest.raises(ConfigError, match="DH_TOKEN"):
        load_config(_write(tmp_path, _YAML.format(url="http://gms:8080")))


def test_unknown_action_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DH_TOKEN", "t")
    monkeypatch.setenv("KEY_A", "k")
    bad = _YAML.replace("action: deny", "action: masq")
    with pytest.raises(ConfigError, match="masq"):
        load_config(_write(tmp_path, bad.format(url="http://gms:8080")))


def test_unknown_mask_strategy_is_rejected_at_load(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DH_TOKEN", "t")
    monkeypatch.setenv("KEY_A", "k")
    bad = _YAML.replace("{{ mask: hash }}", "{{ mask: bogus }}")
    with pytest.raises(ConfigError, match="bogus"):
        load_config(_write(tmp_path, bad.format(url="http://gms:8080")))


def test_yaml_off_on_are_strings_not_booleans(tmp_path, monkeypatch) -> None:
    # YAML 1.1 resolves unquoted off/on/no/yes as booleans (the "Norway problem"). The README and
    # config use `substitution: off` and `lineage_propagation: on`; without the custom loader those
    # become False/True and fail Literal validation with a baffling "should be 'off'" message.
    monkeypatch.setenv("DH_TOKEN", "t")
    monkeypatch.setenv("KEY_A", "k")
    body = _YAML.format(url="http://gms:8080")
    body += "enforcement:\n  substitution: off\n  lineage_propagation: on\n"
    body += "audit:\n  datahub_writeback: no\n  datahub_usage: false\n"
    cfg = load_config(_write(tmp_path, body))
    assert cfg.enforcement.substitution == "off"
    assert cfg.enforcement.lineage_propagation == "on"
    assert cfg.audit.datahub_writeback is False  # genuine bool still coerces
    assert cfg.audit.datahub_usage is False


def test_duplicate_rule_id_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DH_TOKEN", "t")
    monkeypatch.setenv("KEY_A", "k")
    dup = _YAML.replace("  - id: ssn", "  - id: pii")  # collides with the first rule's id
    with pytest.raises(ConfigError, match="duplicate rule id"):
        load_config(_write(tmp_path, dup.format(url="http://gms:8080")))


def test_server_tuning_defaults_and_overrides(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DH_TOKEN", "t")
    monkeypatch.setenv("KEY_A", "k")
    base = _YAML.format(url="http://gms:8080")
    cfg = load_config(_write(tmp_path, base))
    assert (cfg.server.max_concurrency, cfg.server.connection_pool) == (64, 8)  # defaults
    tuned = base + "server: { max_concurrency: 128, connection_pool: 16 }\n"
    cfg2 = load_config(_write(tmp_path, tuned))
    assert (cfg2.server.max_concurrency, cfg2.server.connection_pool) == (128, 16)


def test_invalid_server_tuning_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DH_TOKEN", "t")
    monkeypatch.setenv("KEY_A", "k")
    bad = _YAML.format(url="http://gms:8080") + "server: { max_concurrency: 0 }\n"  # must be >= 1
    with pytest.raises(ConfigError, match="max_concurrency"):
        load_config(_write(tmp_path, bad))


def test_warehouse_kind_without_an_adapter_is_rejected_at_config_load(
    tmp_path, monkeypatch
) -> None:
    """Config must not accept a warehouse kind exec/ cannot build. Accepting one moves the failure
    from config load to first query, and the README used to advertise a kind that did not exist."""
    monkeypatch.setenv("DH_TOKEN", "t")
    monkeypatch.setenv("KEY_A", "k")
    # redshift is a real sqlglot dialect but has no adapter in exec/, so config must reject it.
    bad = _YAML.format(url="http://gms:8080").replace("kind: duckdb", "kind: redshift")
    with pytest.raises(ConfigError, match="kind"):
        load_config(_write(tmp_path, bad))


# A valid DSN for each configurable kind, so make_adapter can construct without a live connection.
_DSN_FOR_KIND = {
    "duckdb": ":memory:",
    "postgres": "postgresql://localhost/db",
    "snowflake": "snowflake://u:p@acct/db/schema?warehouse=W&role=R",
    "bigquery": "bigquery://project/dataset",
}


def test_every_configurable_warehouse_kind_has_an_adapter() -> None:
    """Pins the config Literal to what make_adapter can actually construct, so adding a kind
    without its adapter fails here rather than in front of a user."""
    from typing import get_args

    from airlock.config import WarehouseConfig
    from airlock.exec.base import make_adapter

    kinds = get_args(WarehouseConfig.model_fields["kind"].annotation)
    assert set(kinds) == set(_DSN_FOR_KIND), "add a DSN for a new kind so this test can build it"
    for kind in kinds:
        adapter = make_adapter(WarehouseConfig(kind=kind, dsn=_DSN_FOR_KIND[kind]))
        assert adapter.kind == kind
