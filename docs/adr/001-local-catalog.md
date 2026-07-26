# 001 — A local catalog file, for deployments with no DataHub

## Context

CLAUDE.md §10 and the README FAQ both stated the rule plainly: DataHub is a hard dependency, and
`serve` refuses to start without a compiled snapshot from a live instance. That rule exists for a
good reason. It stops the project drifting into the thing it was built to replace — a policy engine
running on facts somebody typed once and never maintained — and it is why "remove DataHub and Airlock
cannot start" is a true statement rather than a marketing one.

It also excluded an entire class of user. A solo developer, or a two-person team, shipping a
text-to-SQL agent against a Postgres or SQLite database has the exact problem Airlock solves and will
not install a multi-container metadata platform to get protection for one database. For them
"DataHub first" reads as "not for you". That is a real cost, paid by the people with the least
capacity to absorb it.

The distinction that resolves it is that §10's actual target is **fabrication**, not file storage.
The forbidden thing is Airlock inventing classifications — guessing from column names, shipping
fixture data that makes a demo look like it works. A catalog file written and reviewed by a person is
not a fabrication. It is the same act as applying a tag in the DataHub UI, recorded somewhere
cheaper.

## Decision

`airlock.yaml` takes **exactly one** catalog source:

```yaml
datahub: { url: ... }          # the intended source
# or
catalog: { file: ./catalog.yaml }   # a reviewed local file
```

Config validation rejects both and rejects neither, so a decision can always name where its facts
came from.

Three constraints keep the original rule intact:

1. **Airlock still never guesses.** Enforcement reads only what the file declares. `airlock init
   --local` may *propose* entries from the warehouse schema, but a proposal is inert until a human
   confirms it — the same relationship `airlock propose` has with DataHub today.
2. **What DataHub uniquely provides is absent, not simulated.** No column-level lineage means
   classification does not propagate to derived columns; `column_lineage` is empty rather than
   invented. Ownership is whatever the file lists, so denials may not be able to name a team. There
   is no write-back: `require_datahub()` raises a named error naming the missing capability.
3. **Nothing pretends to be a link.** `source_url` is a path, so verdicts carry no `catalog_url` —
   emitting `./catalog.yaml/dataset/urn:li:...` would be a broken link presented as a citation.

## Consequences

**Good.** Airlock installs and protects a database in about a minute with no Docker. The value
proposition survives contact with the smallest team, and the growth path is real: the same
`airlock.yaml`, same rules, same verdicts — swap `catalog:` for `datahub:` when a catalog arrives.
Testing improves too, because a file-sourced snapshot needs no live GMS.

**Bad.** Two supported sources is more surface: every path touching `config.datahub` now goes through
`require_datahub()` or the `snapshot` property. The local file can rot, exactly like the
hand-maintained config §10 warns about — mitigated only by `coverage` reporting what the policy
cannot see, not prevented.

**The claim that changes.** "Airlock cannot start without DataHub" is no longer true and has been
removed from the README. What remains true, and is the stronger claim: *Airlock enforces only what a
human declared, and never guesses.* DataHub is still the recommended source, and the only one that
supplies lineage, ownership, and a catalog a whole company shares.
