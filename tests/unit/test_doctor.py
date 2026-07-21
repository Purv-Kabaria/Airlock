"""airlock doctor: a diagnostic must fail fast and never hang on a check it already knows will fail.

The trap this pins: when DataHub is unreachable, the cheap ping fails in seconds, so doctor must not
then attempt a full snapshot compile (which waits out the client timeout). No network: the check
functions are monkeypatched.
"""

from __future__ import annotations

from pathlib import Path

import airlock.config
from airlock.cli import doctor
from airlock.cli.doctor import Check


def test_snapshot_compile_is_skipped_when_datahub_is_unreachable(tmp_path, monkeypatch) -> None:
    cfg_path = tmp_path / "airlock.yaml"
    cfg_path.write_text("unused", encoding="utf-8")

    monkeypatch.setattr(airlock.config, "load_config", lambda _p: object())
    monkeypatch.setattr(doctor, "_docker", lambda: Check("docker", True, "ok"))
    monkeypatch.setattr(doctor, "_warehouse", lambda _c: Check("warehouse", True, "ok"))
    monkeypatch.setattr(doctor, "_datahub", lambda _c: Check("datahub", False, "unreachable"))
    monkeypatch.setattr(doctor, "_mask_salt", lambda _c: Check("mask-salt", True, "ok"))

    called = False

    def _boom(_c: object) -> Check:  # a real compile would hang against a dead GMS
        nonlocal called
        called = True
        return Check("snapshot", True, "compiled")

    monkeypatch.setattr(doctor, "_snapshot", _boom)

    ok = doctor.run_doctor(Path(cfg_path))
    assert ok is False
    assert called is False  # the slow compile was never attempted
