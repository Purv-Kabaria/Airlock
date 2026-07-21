# ADR 0001 — Policy is compiled from the catalog; facts and rules are split

## Context
Access decisions for agents must derive from governed, versioned facts, not from a config file
someone forgot to update. Two ways to model this: keep everything in DataHub, or split facts
(what is PII, what is deprecated) from rules (what happens to PII).

## Decision
Facts live in DataHub and are compiled into a content-addressed `PolicyGraph`; rules, principals,
and enforcement live in `airlock.yaml` under code review. The decision function is pure over
`(ResolvedQuery, Principal, PolicyGraph)`, and `policy/compile.py` is the only reader of DataHub.
There is no code path that decides without a compiled snapshot — `serve` fails fast if it cannot
compile one.

## Consequences
- Classification changes deploy instantly (next snapshot); enforcement changes get a human
  approver. Two different change-management speeds, matched to who owns each.
- Decisions are replayable bit-for-bit from `(sql, principal, snapshot_hash)`, which makes the
  decision cache safe to key on and any past decision auditable.
- DataHub is a hard runtime dependency, by design. A "standalone mode" would be a policy engine
  with made-up facts — the exact thing Airlock exists to replace — so it is out of scope.
