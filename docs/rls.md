# Row-level security (roadmap, not shipped)

Airlock v1 enforces at table, column, and statement granularity. Row-level filtering is future
work; this note records the intended design so the scope boundary is explicit (README "Security
model & honest limitations").

## Intent
Bind row predicates to catalog attributes the same way column policy binds to tags:

- A catalog attribute (a structured property or a tag with a value, e.g. `rls.tenantColumn`)
  names the column that scopes rows, and the principal's scope supplies the allowed values.
- At rewrite time, Airlock injects a `WHERE` predicate (`tenant_id IN (...principal tenants...)`)
  the same way it injects the row limit, and records an `AIRLOCK-1xx` verdict explaining it.

## Why it is not in v1
Correct row-level rewriting interacts with joins, aggregates, and set operations in ways that
need their own property-test suite (a predicate injected into the wrong scope is a silent leak).
That work is sequenced after the table/column enforcement path is battle-tested, so v1 ships the
guarantees it can prove rather than a row-level feature it cannot yet prove safe.
