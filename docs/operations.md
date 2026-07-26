# Operating Airlock

The day-2 guide for running Airlock in production — not the demo. It assumes you already
have Airlock installed, a live DataHub it can read, and a warehouse it can reach. For what
Airlock *is* and how to stand up the demo, read `README.md` first; this document does not
repeat the architecture, the security model, or the performance budgets, only extends them
for operators.

Airlock fails closed and requires a live DataHub to start. Internalize both before you page
yourself over an outage: a gateway that will not serve is usually a gateway doing its job.

## 1. Deployment topologies

Airlock serves MCP over one of two transports. The choice is about how many agents share a
process, and it decides where identity comes from.

| | `stdio` | `http` |
|---|---|---|
| Process model | one process per agent; the client launches it | one process, many agents concurrently |
| Principal source | fixed at startup (`--principal` or `--key-env`) | per request, from the `X-Airlock-Key` header |
| Identity boundary | the OS process | the request |
| Health endpoints | separate listener on `--health-port` | `/healthz`, `/readyz` on the MCP `--port` |
| Use when | a harness (Claude Code, Cursor, Claude Desktop) spawns Airlock as a local subprocess for one agent | a shared gateway fronts many agents over the network |

Start commands:

```
# stdio — the process IS the identity; principal pinned at startup
airlock serve --transport stdio --principal growth-agent
airlock serve --transport stdio --key-env AIRLOCK_KEY_GROWTH   # resolve principal from a key

# http — one process, per-request auth
airlock serve --transport http --host 0.0.0.0 --port 8080
```

`--principal` and `--key-env` are refused over http and the command exits 2:

```
--principal/--key-env are stdio-only. Over http each request authenticates itself:
send the agent's key as the X-Airlock-Key header. Re-run without the flag.
```

This is deliberate. Honoring a startup principal on a shared process would hand every
agent that connected the same scope — the over-permissioned credential Airlock exists to
remove. Over http, every call carries its own key and is resolved on its own; a missing or
unrecognized key resolves to the anonymous deny-all principal, never to some other agent's
scope.

`serve` flags: `--config/-c` (default `airlock.yaml`), `--principal`, `--key-env`,
`--transport` (`stdio`|`http`, default `stdio`), `--host` (default `127.0.0.1`),
`--port` (default `8080`, the MCP port over http), `--health-port` (default `8088`, the
stdio health listener). Bind `--host 0.0.0.0` only behind a network boundary you trust; the
`X-Airlock-Key` header is the only thing standing between a caller and a principal's scope.

## 2. Configuration reference

One file, checked into Git. Secrets are only ever `${ENV}` references, resolved at load;
a missing variable is a named `ConfigError`, not a `KeyError`. Durations accept `5m`, `24h`,
`30s`, `500ms`, or a bare number of seconds. Unknown keys are rejected (`extra="forbid"`).

Every field, its type, default, and effect. Defaults are the code's defaults; note that
`airlock init` writes a template with a shorter `refresh_interval` (`30s`) than the code
default.

### datahub

| Key | Type | Default | Effect |
|---|---|---|---|
| `datahub.url` | str | — (required) | GMS base URL. |
| `datahub.token` | str \| null | `null` | Bearer token for GMS. Use an env ref. |
| `datahub.domains` | list | `[]` | Compile only these DataHub domains (names or urns). Empty compiles every dataset on the platform. Applied server-side in the search query, so filtered datasets are never fetched. A name that matches no domain refuses to compile rather than silently producing an empty deny-everything policy. |
| `datahub.snapshot.refresh_interval` | duration | `300s` | Background recompile cadence. |
| `datahub.snapshot.max_staleness` | duration | `86400s` (24h) | Age past which `stale_policy` applies. |
| `datahub.snapshot.stale_policy` | `fail_closed` \| `serve_stale_readonly` | `fail_closed` | What a stale snapshot does. **`serve_stale_readonly` relaxes safety** (see §6). |

### warehouse

| Key | Type | Default | Effect |
|---|---|---|---|
| `warehouse.kind` | `duckdb`\|`postgres`\|`snowflake`\|`bigquery`\|`sqlite`\|`dbapi` | — (required) | Adapter + default sqlglot dialect. |
| `warehouse.dsn` | str | — (required) | Connection string. Use an env ref. |
| `warehouse.driver` | str \| null | `null` | DB-API module (e.g. `pymysql`). Required when `kind: dbapi`. |
| `warehouse.dialect` | str \| null | `null` | sqlglot dialect. Inferred from `kind` for named kinds; required for `dbapi`. |
| `warehouse.connect_args` | map | `{}` | Passed to the driver's `connect()`; values may be env refs. |
| `warehouse.defaults.row_limit` | int | `10000` | Row cap injected into every query. |
| `warehouse.defaults.statement_timeout` | duration | `30s` | Per-statement timeout. |

### enforcement

| Key | Type | Default | Effect |
|---|---|---|---|
| `enforcement.mode` | `enforce` \| `monitor` | `enforce` | **`monitor` observes but does not apply verdicts** (§5). |
| `enforcement.unknown_tables` | `deny` \| `allow` | `deny` | A table absent from the catalog. **`allow` relaxes safety.** |
| `enforcement.statement_classes` | list[str] | `[select]` | Statement types any principal may run. Broadening it grants more than reads. |
| `enforcement.predicate_policy` | `deny` \| `transform` | `deny` | Masked column used in `WHERE`/`JOIN`. **`transform` relaxes the membership-inference guard.** |
| `enforcement.substitution` | `rewrite` \| `warn` \| `off` | `rewrite` | Deprecated-table redirect. **`warn`/`off` stop rewriting.** |
| `enforcement.lineage_propagation` | `on` \| `off` | `on` | Propagate classifications along column lineage. **`off` can serve a derived PII column in the clear.** |
| `enforcement.table_matching` | `exact` \| `suffix` | `exact` | Name-to-dataset resolution. **`suffix` resolves over-qualified names the catalog didn't store — a small relaxation.** |

### principals

`principals` defaults to `[]`. Each entry: `name` (str), `key` (str, an env ref),
`scopes` (`domains`: list, `platforms`: list — a null list means unconstrained on that axis),
and `overrides` (`row_limit`: int, `statement_timeout`: duration, `statement_classes`: list —
each null means inherit the enforcement default). Duplicate names or duplicate key *values*
are a `ConfigError` at load.

### audit, masking, server

| Key | Type | Default | Effect |
|---|---|---|---|
| `audit.jsonl` | path | `./audit/decisions.jsonl` | Local append-only decision log (§7). |
| `audit.datahub_writeback` | bool | `true` | Structured properties + ledger back to DataHub. |
| `audit.datahub_usage` | bool | `true` | `datasetUsageStatistics` write-back. **Carries executed query text — turn off where query text must not leave the gateway.** |
| `audit.otel.enabled` | bool | `false` | Emit OTel metrics (§5). |
| `audit.otel.endpoint` | str \| null | `null` | OTLP endpoint. |
| `masking.salt` | str \| null | `null` | Secret for the deterministic `hash` strategy (§3). **Unset is a warning, not an error.** |
| `server.max_concurrency` | int ≥ 1 | `64` | Concurrent decisions before queueing (§9). |
| `server.burst` | int ≥ 0 | `200` | Extra queued above the cap before `AIRLOCK-440`. |
| `server.connection_pool` | int ≥ 1 | `8` | Warehouse connections. |
| `server.decision_cache` | int ≥ 1 | `2048` | Memoized decision plans. |
| `server.writeback_queue` | int ≥ 1 | `512` | Bounded remote-audit backlog before the remote copy is dropped. |

**Fail-closed defaults, bolded above, are the ones to protect.** Every setting that relaxes
safety is opt-in and named. Validate any change with `airlock policy lint` before it ships;
misconfiguration produces a named, positional error, not a traceback.

## 3. Secrets and key management

Keys and tokens are **env references only** (`${AIRLOCK_KEY_GROWTH}`). The yaml is checked
into Git; secrets are not. A referenced variable that is unset fails config load with the
variable named. `airlock init` writes the template this way and never puts a value on disk.

**Principal keys** map a secret to a named principal. Over http they are matched in constant
time (`hmac.compare_digest` against every configured key) so timing does not reveal which
principal a guessed key is near.

**Rotate a principal key:**
1. Set the new secret in the env var the principal's `key: ${...}` references.
2. Restart `serve` (a new snapshot picks up the new key map; there is no hot key reload).
3. Update the agent's harness config with the new key.
4. During cutover, an old key resolves to the anonymous deny-all principal — every query is
   denied with `AIRLOCK-430`, not silently served. Coordinate the two updates.

**The masking salt is a deployment secret.** The `hash` strategy is deterministic so joins
and `GROUP BY` on masked keys still work; that determinism is exactly why the salt matters.
Without a secret salt, an attacker who knows the public policy can brute-force low-cardinality
hashed values (there are only so many US states). Set `masking.salt` to a real secret in
every non-demo deployment. When it is unset, Airlock derives a salt from the snapshot hash and
`airlock doctor` warns — a warning, deliberately, so the demo runs, but treat it as a blocker
for production.

## 4. Health and readiness for orchestrators

Two endpoints, two questions.

| Endpoint | Answers | Wire it to |
|---|---|---|
| `/healthz` | Is the process alive? Always `200 ok` while serving. | liveness probe / process restart |
| `/readyz` | Can this gateway decide *right now*? `200 ready` or `503 not ready`. | readiness probe / load-balancer routing |

`/readyz` is `ready` only when a valid policy snapshot is loaded. Under
`stale_policy: fail_closed` it also flips to `503` once the loaded snapshot ages past
`max_staleness` — the gateway is up but refusing to decide on stale policy, and an
orchestrator should stop routing to it. Under `serve_stale_readonly` a loaded snapshot stays
`ready` even when stale, because that mode's contract is to keep serving.

A failing `/readyz` means one of: the first snapshot has not compiled yet (cold start),
DataHub has been unreachable long enough to blow the staleness budget under `fail_closed`, or
no snapshot could ever be built. It is not a liveness problem; do not restart the process on a
`/readyz` failure — that discards a possibly-fine cached snapshot and makes the outage worse.
Check DataHub and run `airlock doctor`.

Where the endpoints live differs by transport (§1): over http they are custom routes on the
MCP `--port`; over stdio a small stdlib HTTP listener serves them on `--host:--health-port`.

**Graceful shutdown.** On `SIGINT`/`SIGTERM` (or `Ctrl+C`), Airlock cancels the refresh loop,
drains the queued remote audit writes within a deadline (5s; a timeout logs
`audit.drain_timeout pending=N` and proceeds), closes the warehouse adapter, and closes every
sink. The local JSONL log is written on the request path, so it is already durable — the drain
only concerns the best-effort DataHub/OTel backlog. Give the container a stop grace period of
at least the drain deadline so write-back is not truncated.

## 5. Monitoring

Three surfaces, in increasing distance from the request:

- **`airlock tail`** follows the local decision log live, colorized, as queries arrive. This
  is the operator's real-time view. `airlock explain <request_id>` replays one past decision
  from the same log (`--json` for the raw record).
- **`airlock usage`** reads back the per-dataset / per-column / per-principal read activity
  Airlock wrote to DataHub as `datasetUsageStatistics`. It reads the timeseries store directly
  (GMS caches the GraphQL aggregation for minutes), so a fresh write is visible. `--json` for
  scripts.
- **OTel** (`audit.otel.enabled: true`): a histogram `airlock.decision.latency_ms` and
  counters `airlock.verdicts` / `airlock.denials`, tagged by principal. Off by default; if the
  SDK is absent or export fails it degrades to a no-op with one `otel.disabled` warning, never
  a failed request.

**Structured log events** (structlog; `serve` can emit JSON). The ones worth alerting on:

| Event | Level | Fields | Means |
|---|---|---|---|
| `decision.made` | info | `request_id`, `principal`, `status`, `verdicts`, `latency_ms` | Every decision. Your throughput and latency signal. |
| `snapshot.compiled` | info | `datasets`, `rules`, `principals`, `hash` | A fresh snapshot installed. Dataset/rule counts dropping unexpectedly is a catalog problem. |
| `snapshot.refresh_failed` | warn | `detail` | A background refresh failed; the pinned snapshot keeps serving and the next tick retries. A steady stream means DataHub is down — watch the staleness budget. |
| `snapshot.stale_bootstrap` | warn | `compiled_at` | Started from a persisted snapshot because DataHub was unreachable *and* `serve_stale_readonly` is set. |
| `audit.writeback_dropped` | warn | `request_id`, `total_dropped` | The remote-audit queue is full; DataHub write-back is falling behind. Local log is unaffected. |
| `auth.unknown_key` / `auth.missing_key` | warn | — | A caller presented a bad/no key and got the anonymous deny-all principal. Bursts mean a misconfigured client. |

## 6. Staleness and DataHub outages

Airlock's behavior depends on *when* DataHub becomes unreachable relative to a request.

| When | Behavior |
|---|---|
| **At startup** | Fail fast. `serve` refuses to start with `SnapshotUnavailableError` and exits 2 — there is no code path that decides without a snapshot. Exception: if a snapshot was previously persisted *and* `stale_policy: serve_stale_readonly`, it boots from that cache and logs `snapshot.stale_bootstrap`. |
| **Mid-session, within budget** | No request impact. Each request is served from the snapshot pinned at ingress; the background refresh loop retries every `refresh_interval` and logs `snapshot.refresh_failed` each time it fails. |
| **Mid-session, past `max_staleness`** | `stale_policy` decides. `fail_closed` (default): every query is refused with `AIRLOCK-410` and `/readyz` returns `503`. `serve_stale_readonly`: queries are served from the last-known snapshot, each envelope carries an `AIRLOCK-410` *note* verdict ("Serving a stale policy snapshot; DataHub is unreachable"), and `/readyz` stays `ready`. |

`AIRLOCK-410` (`STALE_SNAPSHOT`) is therefore both the hard deny under `fail_closed` and the
soft warning note under `serve_stale_readonly` — same code, the envelope status tells them
apart. Choosing `serve_stale_readonly` is a decision to keep serving possibly-outdated policy
during a DataHub outage; make it deliberately and document it, because a column reclassified
as PII during the outage will not be masked until DataHub recovers and the snapshot refreshes.

## 7. The audit log

`audit.jsonl` is an append-only JSONL file: one line per decision, written under a lock off
the event loop, before the response is returned. Writes are line-atomic — a kill can truncate
at a line boundary but never corrupt a record. It is the durable source of truth; DataHub
write-back is best-effort on top of it.

**Airlock does not rotate this file.** It grows unbounded, one line per query, forever. That
is your responsibility. Two options:

- Point `audit.jsonl` at a path your existing log pipeline already rotates.
- Rotate it externally with `copytruncate`, so Airlock's held file handle keeps appending to
  the same inode after truncation:

  ```
  /var/log/airlock/decisions.jsonl {
      daily
      rotate 30
      compress
      copytruncate
      missingok
      notifempty
  }
  ```

Do not `mv` the file out from under a running gateway without `copytruncate` (or a restart) —
the process keeps writing to the moved inode and the new file stays empty. Retention is a
compliance decision; these records are your record of what every agent read.

## 8. Troubleshooting

`airlock doctor` is the first thing to run. It resolves config exactly as `serve` does, always
prints the whole checklist (python, config, docker, datahub, warehouse, snapshot, mask-salt),
never stops at the first failure, and prints the fixing command for every red row. `--json`
for CI. A warning (e.g. unset mask salt) does not fail doctor; a `fail` exits non-zero.

| Symptom | Likely cause | Do this |
|---|---|---|
| `serve` exits 2, "refused to start" | DataHub unreachable at startup; no snapshot to compile | `airlock doctor` → fix the `datahub` row; `airlock refresh` for the full compile error |
| `/readyz` never becomes ready | First snapshot not compiled, or stale past budget under `fail_closed` | `airlock doctor`; check `snapshot.refresh_failed` in the logs; confirm DataHub is up — do **not** restart the process |
| Every query denied with `AIRLOCK-430` | Wrong/missing key → resolved to anonymous deny-all principal | Check the agent's `X-Airlock-Key` (http) or `--principal`/`--key-env` (stdio); watch for `auth.unknown_key` / `auth.missing_key` |
| Every query denied with `AIRLOCK-410` | Snapshot past `max_staleness` under `fail_closed` | Restore DataHub connectivity; or set `serve_stale_readonly` if serving stale is acceptable |
| Queries fail with `AIRLOCK-441` | Warehouse unreachable after one retry | `airlock doctor` → `warehouse` row; check `warehouse.dsn` and the driver; watch `warehouse.retry` logs |
| `datahub` FAIL: "another service holds this port" | Port collision — reachable, but not DataHub | Point `datahub.url` at DataHub's real port, or free the port; `python demo/up.py` picks a free GMS port |
| Config error naming a `${VAR}` | Env ref not set | Export the variable, or copy `.env.example` to `.env`; re-run doctor |
| `AIRLOCK-440` under load | Concurrency cap + burst exceeded | See §9 |
| `audit.writeback_dropped` climbing | Remote-audit queue full; DataHub write-back behind | Raise `server.writeback_queue`, or accept the drop — the local log stays complete |
| Unexpected table denied (`AIRLOCK-403`) | Over-qualified name vs `table_matching: exact` | Confirm the catalog name; consider `table_matching: suffix` if ingestion drops the prefix |

## 9. Scaling and capacity

The `server` block bounds one process. Understand the queue before you raise the numbers.

| Knob | Default | Governs |
|---|---|---|
| `max_concurrency` | 64 | Decisions executing at once; beyond this, requests queue. |
| `burst` | 200 | Extra requests allowed to queue above the cap. |
| `connection_pool` | 8 | Warehouse connections shared across all in-flight queries. |
| `decision_cache` | 2048 | Memoized plans keyed on `(sql, principal, snapshot_hash)`. A snapshot change changes the hash, so a policy update invalidates stale entries automatically. |
| `writeback_queue` | 512 | Bounded remote-audit backlog. Over it, the remote copy is dropped (counted, logged); the local JSONL stays authoritative. |

The in-flight ceiling is `max_concurrency + burst`. A request arriving above it is rejected
immediately with **`AIRLOCK-440`** ("gateway at its concurrency cap") and a retry-after hint —
a clean, typed rejection, not a hang or a dropped connection. If you see `AIRLOCK-440` under
normal load, the bottleneck is usually the warehouse: raise `connection_pool` (and the
warehouse's own connection limit) before you raise `max_concurrency`, because more concurrent
decisions without more connections just moves the queue.

**Single-instance assumption.** The DataHub write-back keeps a per-dataset `deniedAttempts`
counter that it maintains read-modify-write, serialized within one process by a lock and a
single drain worker. Running **multiple gateway instances against the same DataHub datasets
races that counter** — two instances can read the same value and both write value+1, losing an
increment. The structured properties (`lastAgentAccess`, `lastPolicySnapshot`) and the usage
timeseries are self-healing (last write wins, re-emitted in full), but the denial count is not.
If you must scale horizontally, either accept that `deniedAttempts` under-counts, or disable
`datahub_writeback` on all but one instance and let that one carry the ledger. Each instance's
local `audit.jsonl` remains complete and correct regardless.
