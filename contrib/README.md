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
