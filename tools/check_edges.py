"""Fail CI if any row of the README edge-case table lacks a `test_edge_NN_*` test.

The edge table is the test plan (CLAUDE.md §7). This parses the table to learn the row numbers,
scans the test tree for `def test_edge_NN_`, and reports any gaps. Run: `python tools/check_edges.py`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
TESTS = ROOT / "tests"

_ROW = re.compile(r"^\|\s*(\d+)\s*\|", re.MULTILINE)
_TEST = re.compile(r"def\s+test_edge_(\d+)_")


def edge_numbers() -> set[int]:
    text = README.read_text(encoding="utf-8")
    start = text.index("## Edge cases")
    section = text[start : text.index("\n## ", start + 1)]
    return {int(m.group(1)) for m in _ROW.finditer(section)}


def tested_numbers() -> set[int]:
    covered: set[int] = set()
    for path in TESTS.rglob("test_*.py"):
        covered |= {int(m.group(1)) for m in _TEST.finditer(path.read_text(encoding="utf-8"))}
    return covered


def main() -> int:
    required = edge_numbers()
    covered = tested_numbers()
    missing = sorted(required - covered)
    if missing:
        print(f"missing edge-case tests for rows: {missing}", file=sys.stderr)
        print(
            "add a `def test_edge_NN_<slug>` for each. See tests/unit/test_edges.py.",
            file=sys.stderr,
        )
        return 1
    print(f"edge coverage ok: {len(required)} rows, all have tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
