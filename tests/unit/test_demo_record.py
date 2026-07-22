"""The rehearsal gate in demo/record.py must not report a false green.

`--rehearse` is what stands between a broken beat and a wasted recording session, so the check
itself needs to be trustworthy: a beat whose verdicts changed has to fail, and a stack that answers
with nothing must not read as success.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "demo" / "record.py"


@pytest.fixture
def record():
    spec = importlib.util.spec_from_file_location("demo_record", _PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.VERIFY = True
    module._FAILED_BEATS.clear()
    return module


def _stub(monkeypatch, record, stdout: str, stderr: str = "") -> None:
    def fake_run(*_a, **kwargs):
        if kwargs.get("capture_output"):
            return subprocess.CompletedProcess([], 0, stdout=stdout, stderr=stderr)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(record.subprocess, "run", fake_run)


def _envelope(*codes: str) -> str:
    return json.dumps({"verdicts": [{"code": c} for c in codes]})


def test_beat_passes_when_the_promised_codes_come_back(monkeypatch, record) -> None:
    _stub(monkeypatch, record, _envelope("AIRLOCK-110", "AIRLOCK-120"))
    record.run_airlock(["check", "q"], expect=("AIRLOCK-110", "AIRLOCK-120"), beat="cold open")
    assert record._FAILED_BEATS == []


def test_beat_fails_when_a_promised_code_stops_firing(monkeypatch, record) -> None:
    # The regression this catches: enforcement changes, the narration does not, and the video
    # claims something the gateway no longer does.
    _stub(monkeypatch, record, _envelope("AIRLOCK-110"))
    record.run_airlock(["check", "q"], expect=("AIRLOCK-110", "AIRLOCK-120"), beat="cold open")
    assert len(record._FAILED_BEATS) == 1
    assert "AIRLOCK-120" in record._FAILED_BEATS[0]


def test_beat_fails_when_a_forbidden_code_appears(monkeypatch, record) -> None:
    # The clean-query beat exists to show the gateway is invisible until policy says otherwise.
    # If it starts masking, the beat no longer makes that point.
    _stub(monkeypatch, record, _envelope("AIRLOCK-110"))
    record.run_airlock(["check", "q"], forbid=("AIRLOCK-110",), beat="clean query")
    assert len(record._FAILED_BEATS) == 1


def test_an_empty_or_broken_response_is_a_failure_not_a_pass(monkeypatch, record) -> None:
    _stub(monkeypatch, record, "", stderr="connection refused")
    record.run_airlock(["check", "q"], expect=("AIRLOCK-110",), beat="cold open")
    assert len(record._FAILED_BEATS) == 1
    assert "connection refused" in record._FAILED_BEATS[0]


def test_preflight_surfaces_each_failing_doctor_check(monkeypatch, record) -> None:
    report = {
        "ok": False,
        "checks": [
            {"check": "python", "status": "pass", "detail": "3.11", "fix": None},
            {"check": "datahub", "status": "fail", "detail": "unreachable", "fix": "run up.py"},
        ],
    }
    _stub(monkeypatch, record, json.dumps(report))
    problems = record.preflight()
    assert problems == ["datahub - run up.py"]


def test_preflight_reports_rather_than_raises_when_doctor_cannot_run(monkeypatch, record) -> None:
    _stub(monkeypatch, record, "not json", stderr="boom")
    assert record.preflight() and "boom" in record.preflight()[0]
