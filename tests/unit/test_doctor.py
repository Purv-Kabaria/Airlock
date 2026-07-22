"""airlock doctor: it must diagnose the same environment every other command runs in, report the
whole checklist, and never block on a call it already knows will fail.

No network: the probe functions are monkeypatched except where the point of the test is that config
loads for real.
"""

from __future__ import annotations

import airlock.config
from airlock.cli import doctor
from airlock.cli.doctor import Check

_CONFIG = """
datahub:
  url: ${DOCTOR_TEST_URL}
  token: ${DOCTOR_TEST_TOKEN}
warehouse:
  kind: duckdb
  dsn: ./doctor-test.duckdb
rules:
  - id: pii
    match: { tag: PII }
    action: { mask: auto }
principals:
  - name: a
    key: k
audit:
  jsonl: ./doctor-test.jsonl
"""


def _stub_probes(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "_docker", lambda _c: Check("docker", "pass", "ok"))
    monkeypatch.setattr(doctor, "_warehouse", lambda _c: Check("warehouse", "pass", "ok"))
    monkeypatch.setattr(doctor, "_mask_salt", lambda _c: Check("mask-salt", "pass", "ok"))


def test_snapshot_compile_is_skipped_when_datahub_is_unreachable(tmp_path, monkeypatch) -> None:
    # The trap: the cheap ping fails in seconds, so doctor must not then attempt a full snapshot
    # compile and make the operator wait out the client timeout.
    cfg_path = tmp_path / "airlock.yaml"
    cfg_path.write_text("unused", encoding="utf-8")
    monkeypatch.setattr(airlock.config, "load_config", lambda _p: object())
    _stub_probes(monkeypatch)
    monkeypatch.setattr(doctor, "_datahub", lambda _c: Check("datahub", "fail", "unreachable"))

    called = False

    def _boom(_c: object) -> Check:  # a real compile would hang against a dead GMS
        nonlocal called
        called = True
        return Check("snapshot", "pass", "compiled")

    monkeypatch.setattr(doctor, "_snapshot", _boom)

    assert doctor.run_doctor(cfg_path) is False
    assert called is False


def test_doctor_resolves_config_the_way_other_commands_do(tmp_path, monkeypatch) -> None:
    """The regression that matters most: doctor used to load config without the `.env` autoload
    every other command performs, so it failed configs that `check` and `serve` load happily -- and
    it is the first command the README tells you to run."""
    (tmp_path / "airlock.yaml").write_text(_CONFIG, encoding="utf-8")
    (tmp_path / ".env").write_text(
        "DOCTOR_TEST_URL=http://datahub.test:8080\nDOCTOR_TEST_TOKEN=t\n", encoding="utf-8"
    )
    monkeypatch.delenv("DOCTOR_TEST_URL", raising=False)
    monkeypatch.delenv("DOCTOR_TEST_TOKEN", raising=False)
    _stub_probes(monkeypatch)
    monkeypatch.setattr(doctor, "_datahub", lambda _c: Check("datahub", "pass", "ok"))
    monkeypatch.setattr(doctor, "_snapshot", lambda _c: Check("snapshot", "pass", "ok"))

    checks = doctor._collect(tmp_path / "airlock.yaml")
    config = next(c for c in checks if c.name == "config")
    assert config.status == "pass", config.detail


def test_every_check_is_reported_even_when_config_fails(tmp_path) -> None:
    # A checklist that stops at the first failure makes the operator re-run to discover the next
    # one. Downstream checks are skipped, never dropped.
    checks = doctor._collect(tmp_path / "missing.yaml")
    names = [c.name for c in checks]
    assert names == ["python", "config", "docker", "datahub", "warehouse", "snapshot", "mask-salt"]
    assert next(c for c in checks if c.name == "config").status == "fail"
    assert all(c.status == "skip" for c in checks if c.name in {"datahub", "warehouse", "snapshot"})


def test_failures_name_a_fix(tmp_path) -> None:
    # No dead ends: a red row the operator cannot act on is worse than no row.
    checks = doctor._collect(tmp_path / "missing.yaml")
    assert all(c.fix for c in checks if c.status == "fail")


def test_docker_is_not_required_when_datahub_is_remote(monkeypatch) -> None:
    # Docker only hosts the demo stack. Failing doctor over it on a production install teaches
    # operators to ignore a red row, which costs more than the check is worth.
    class _Cfg:
        class datahub:  # stands in for the nested config model
            url = "https://datahub.corp.example"

    assert doctor._docker(_Cfg()).status == "skip"


def test_json_report_agrees_with_the_table(tmp_path) -> None:
    checks = doctor._collect(tmp_path / "missing.yaml")
    payload = doctor._payload(checks)
    assert payload["ok"] is False
    assert [c["check"] for c in payload["checks"]] == [c.name for c in checks]
