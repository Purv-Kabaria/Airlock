"""demo/up.py is the judge's first command; it must fail in sentences, not tracebacks.

CLAUDE.md treats one unhandled traceback on the judge path as a P0. These pin the two places up.py
could produce one, and the success message that has to hand back a command that actually runs.
"""

from __future__ import annotations

import importlib.util
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "demo" / "up.py"


@pytest.fixture
def up():
    spec = importlib.util.spec_from_file_location("demo_up", _PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_failing_seed_step_reports_instead_of_raising(up) -> None:
    # subprocess.run(check=True) here would surface a CalledProcessError traceback as the first
    # thing a judge sees after cloning.
    assert up._run([sys.executable, "-c", "raise SystemExit(3)"]) is False


def test_a_missing_binary_reports_instead_of_raising(up) -> None:
    assert up._run(["definitely-not-a-real-binary-xyz"]) is False


def test_a_successful_step_reports_success(up) -> None:
    assert up._run([sys.executable, "-c", "pass"]) is True


def test_next_step_command_is_runnable_on_this_machine(up) -> None:
    """up.py may bootstrap a .venv and re-launch through it, leaving `airlock` off the caller's
    PATH. Printing `airlock check ...` then hands them command-not-found at the moment setup
    succeeded, so the message has to name an invocation that works here."""
    display = up._airlock_display()
    assert display
    proc = subprocess.run(
        [*shlex.split(display, posix=False), "--version"], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert "airlock" in proc.stdout.lower()


def test_paths_with_spaces_are_quoted(up) -> None:
    assert up._quote(r"C:\Program Files\python.exe") == r'"C:\Program Files\python.exe"'
    assert up._quote("/usr/bin/python") == "/usr/bin/python"


def test_gms_port_moves_off_a_taken_default(up, monkeypatch) -> None:
    # The exact failure that started this: something already owns 8080, so DataHub must not try to
    # bind there. A free port is chosen and the URL updated.
    def fake_free(port: int) -> bool:
        return port != 8080  # 8080 taken, everything else free

    monkeypatch.setattr(up, "_port_is_free", fake_free)
    monkeypatch.setattr(up, "_gms_healthy", lambda _url: False)
    assert up._resolve_gms_url("http://localhost:8080") == "http://localhost:18080"


def test_free_default_port_is_kept(up, monkeypatch) -> None:
    monkeypatch.setattr(up, "_port_is_free", lambda _p: True)
    monkeypatch.setattr(up, "_gms_healthy", lambda _url: False)
    assert up._resolve_gms_url("http://localhost:18080") == "http://localhost:18080"


def test_an_already_healthy_gms_is_never_moved(up, monkeypatch) -> None:
    # Idempotency: a re-run against a DataHub already up on its port must not relocate it just
    # because the port now reads busy (it is busy because DataHub is on it).
    monkeypatch.setattr(up, "_gms_healthy", lambda _url: True)
    monkeypatch.setattr(up, "_port_is_free", lambda _p: False)
    assert up._resolve_gms_url("http://localhost:8080") == "http://localhost:8080"


def test_port_helpers(up) -> None:
    assert up._port_of("http://localhost:18080") == 18080
    assert up._port_of("http://localhost") == 8080  # default when absent
    assert up._with_port("http://localhost:8080", 9002) == "http://localhost:9002"


def test_persist_env_replaces_only_its_key(up, tmp_path, monkeypatch) -> None:
    env = tmp_path / ".env"
    env.write_text("DATAHUB_GMS_URL=http://localhost:8080\nOTHER=keep\n", encoding="utf-8")
    monkeypatch.setattr(up, "DEMO", tmp_path)
    up._persist_env("DATAHUB_GMS_URL", "http://localhost:18080")
    written = env.read_text(encoding="utf-8")
    assert "DATAHUB_GMS_URL=http://localhost:18080" in written
    assert "OTHER=keep" in written
    assert written.count("DATAHUB_GMS_URL=") == 1  # replaced, not appended


def test_persist_env_seeds_a_missing_file_from_the_example(up, tmp_path, monkeypatch) -> None:
    # The bug this pins: a demo/.env holding only the URL shadows the token for every loader that
    # reads .env and stops. A newly-written .env must carry the full set.
    (tmp_path / ".env.example").write_text(
        "DATAHUB_GMS_URL=http://localhost:8080\nDATAHUB_GMS_TOKEN=demo\nAIRLOCK_KEY_GROWTH=g\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(up, "DEMO", tmp_path)
    up._persist_env("DATAHUB_GMS_URL", "http://localhost:18080")
    written = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "DATAHUB_GMS_TOKEN=demo" in written  # carried over from the example
    assert "AIRLOCK_KEY_GROWTH=g" in written
    assert "DATAHUB_GMS_URL=http://localhost:18080" in written
    assert written.count("DATAHUB_GMS_URL=") == 1


def test_gms_health_rejects_a_non_datahub_service(up, monkeypatch) -> None:
    # SigNoz (or any service) answering 200 with HTML on the port must not read as a healthy GMS,
    # or up.py skips the boot and seeds into the wrong service.
    class _Resp:
        status = 200

        def __init__(self, body: bytes) -> None:
            self._body = body

        def read(self, _n: int = -1) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *_a: object) -> None:
            return None

    monkeypatch.setattr(up.urllib.request, "urlopen", lambda *_a, **_k: _Resp(b"<!doctype html>"))
    assert up._gms_healthy("http://localhost:8080") is False

    monkeypatch.setattr(
        up.urllib.request, "urlopen", lambda *_a, **_k: _Resp(b'{"versions":{"acryl":"1"}}')
    )
    assert up._gms_healthy("http://localhost:8080") is True
