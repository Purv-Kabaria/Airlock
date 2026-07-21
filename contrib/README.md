# contrib

Code intended for upstream contribution, kept dependency-isolated from `airlock/` so it can be
filed against the target project without dragging Airlock along.

## `datahub_action/` — push-based snapshot refresh

A [DataHub Actions](https://docs.datahub.com/docs/actions/) plugin that pokes Airlock's `/refresh`
endpoint when a dataset's classification changes (tag, glossary term, deprecation, domain). It
turns Airlock's poll into a push, so enforcement updates within seconds of a catalog change
instead of on the next `refresh_interval`.

Run it against a DataHub instance with the Actions framework installed:

```
datahub actions -c contrib/datahub_action/action.yaml
```

We intend to propose this as a reusable Action upstream.

## `datahub_audit_skill/` — the missing `datahub-audit` skill

A skill for [`datahub-project/datahub-skills`](https://github.com/datahub-project/datahub-skills).
The registry routes users to `/datahub-audit` from seven places across five files — including the
"Not This Skill" boundary in `datahub-search` and the canonical `-C skill=datahub-audit` example in
the shared CLI reference — but the skill was never written. This is it.

It reports catalog coverage (ownership, documentation, classification, domains, lineage,
deprecation hygiene) and the unclassified columns whose names suggest they need review. Read-only;
fixes route to `/datahub-enrich`.

`PR.md` is the pull request body. The directory mirrors the upstream layout, so it drops into
`skills/datahub-audit/` unchanged; `catalog-audit.command.md` belongs at `commands/catalog-audit.md`.

The classified-versus-governed distinction it insists on is the same one `airlock coverage`
enforces: a column carrying a tag no rule acts on is catalog metadata, not protection.
