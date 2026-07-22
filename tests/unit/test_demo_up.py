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
