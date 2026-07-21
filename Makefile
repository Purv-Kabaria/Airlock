# Dev convenience targets. Judges never need make: the judge path is `python demo/up.py`.
# Every target wraps a cross-platform command, so Windows users can run the python calls directly.
#
# Two lanes: `make ci` is fast and needs nothing (lint, types, unit tests, edge coverage). The
# `bench`, `eval`, `judge`, and `examples` targets run against the REAL stack and need `make up`
# first (a live DataHub + DuckDB); `make integration` runs them together.

.PHONY: install test unit lint fmt typecheck edges examples bench judge eval load up reset all ci integration

install:
	uv sync --extra dev

test unit:
	uv run pytest tests/unit -q

lint:
	uv run ruff check airlock tools tests demo
	uv run ruff format --check airlock tools tests demo

fmt:
	uv run ruff format airlock tools tests demo
	uv run ruff check airlock tools tests demo --fix

typecheck:
	uv run mypy airlock

edges:
	uv run python tools/check_edges.py

# The targets below run against the live stack; `make up` first.
examples:
	uv run python tools/gen_examples.py

bench:
	uv run python tools/bench.py

judge:
	uv run python tools/judge.py

eval:
	uv run python tools/eval.py

load:
	uv run python tools/load.py

up:
	python demo/up.py

reset:
	python demo/reset.py

# Fast lane: no external services. This is what the CI unit matrix runs on every commit.
ci: lint typecheck unit edges

# Real-stack lane: needs `make up`. Compiles the snapshot from live DataHub, like production.
integration: bench eval judge load examples

all: ci
