# Contributing to Airlock

Start with the [development guide](docs/development.md): the architecture in code terms, the request
lifecycle, and how to add a warehouse adapter, a masking strategy, or a reason code. For running
Airlock rather than changing it, see the [operations runbook](docs/operations.md) and the
[reason-code reference](docs/reason-codes.md).

## Setup
```
uv sync --extra dev
uv run pytest tests/unit -q
```

## Before you push
`make ci` must be green: ruff (lint + format), `mypy --strict`, the unit suite, edge-case
coverage (`tools/check_edges.py`), the decision benchmark, and the hostile-user gauntlet.

- **Conventional commits** (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`), imperative mood.
- **Small PRs**, one concern each. New behavior ships with tests; user-visible behavior updates
  the README in the same PR (they must never drift).
- **Nomenclature is fixed** — see the ubiquitous-language table in `CLAUDE.md`. `Principal`, not
  user; `Verdict`, not result; `PolicyGraph`, not cache.
- **The edge-case table in the README is the test plan.** Every row has a `test_edge_NN_<slug>`;
  when someone finds a new way to break Airlock, it becomes a gauntlet case in the same PR as the
  fix.
- **No mocks in the product.** Fakes live only under `tests/unit/`, behind the real protocols.

## Architecture decisions
Anything that pins or reverses a rule in `CLAUDE.md` gets a one-page ADR in `docs/adr/`.

## License
By contributing you agree your contributions are licensed under Apache 2.0.
