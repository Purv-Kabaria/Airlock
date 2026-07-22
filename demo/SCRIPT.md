# Demo script

Two ways to record. **Hands-free (recommended):** `python demo/record.py` plays the whole sequence
below against the live stack with captions and pauses — you screen-record one take and read the
word-for-word voiceover in [`VIDEO.md`](VIDEO.md) over it. No typing on camera, no typos, no timing
risk. **Manual:** drive the terminal and the DataHub UI yourself with the shot list below — the only
reason to do this is to click the retag in the real UI on camera, which is marginally more convincing
than the automated tag write.

Three things the player does so a take cannot be wasted:

- **Preflight.** It runs `airlock doctor --json` before anything else and refuses to start if a
  check is failing, naming the fix. A stack that is not ready costs you a re-run, not a take.
- **`--rehearse` is a real gate,** not just faster playback. Every decision beat is re-run with
  `--json` and checked against the reason codes its narration promises; the run exits non-zero and
  lists any beat that no longer holds. `make rehearse` until it passes, then `make demo`.
- **The retag always comes off.** `orders.status` is restored from a `finally`, so a run that dies
  midway still leaves the catalog as it found it and the next take opens on the same before-state.

Two documents in one. **Part A** is the recording shot list, timed to 2:55 against the hard
3:00 limit. **Part B** is the unscripted rehearsal — run it before recording, and hand it to anyone
who wants to break the thing themselves.

Everything here runs against the real stack `python demo/up.py` starts. No mocks, no fixtures, no
`--demo` flag. If a beat below cannot be performed live, it does not belong in the video.

---

## Part A — the 2:55 shot list

### Screen layout

Two panes, side by side, for the whole recording. Do not rearrange windows on camera.

```
+---------------------------+---------------------------+
|  LEFT: terminal           |  RIGHT: browser           |
|  airlock commands         |  DataHub UI  :9002        |
|  (bottom third: tail)     |  logged in, dataset open  |
+---------------------------+---------------------------+
```

Terminal at 100 columns, font large enough to read at 720p (14pt minimum — judges may watch in a
small embedded player). Run `airlock tail -c demo/airlock.yaml` in a split at the bottom of the left
pane so verdicts stream while you talk.

### Before the camera rolls

```
python demo/up.py                  # DataHub + DuckDB + seeded catalog, idempotent
python tools/judge.py              # gauntlet must be green before you record
airlock coverage -c demo/airlock.yaml
airlock tail -c demo/airlock.yaml  # bottom split
```

Clear the terminal. Log into DataHub (`datahub`/`datahub`) and leave the `orders` dataset open on
the right so no login happens on camera.

### 0:00-0:14 — cold open, no preamble

Type the query that a text-to-SQL agent would send:

```
airlock check "SELECT name, email, ssn FROM dim_users" --as growth-agent -c demo/airlock.yaml
```

On screen: `email` partially masked, `ssn` nulled, each with a reason code and a hint, plus the
rewritten SQL.

> "This agent asked for social security numbers. It didn't get them — and it got told why, in a
> format it can act on. Nothing was installed in the warehouse to make that happen."

Do not explain the architecture yet. Show the result first.

### 0:14-0:35 — the problem

Stay on the same screen.

> "Every team shipping a data agent hits the same wall: security won't hand a non-deterministic
> text generator a warehouse credential. The usual answers are static role grants nobody maintains,
> or a six-figure access platform built for humans clicking through dashboards. Airlock is a
> gateway that sits between the agent and the warehouse — and it gets its policy from DataHub."

### 0:35-1:00 — policy comes from the catalog

> "Nothing here is hardcoded. `email` is masked because it carries the `PII` tag in DataHub. `ssn`
> is denied because of the glossary term. Airlock parses the SQL into an AST, resolves every column
> to a catalog URN, and applies the rules."

Show the clean case so the gateway does not look like it blocks everything:

```
airlock check "SELECT status, COUNT(*) AS n FROM orders GROUP BY status" --as growth-agent -c demo/airlock.yaml
```

> "No sensitive columns, no intervention. It's invisible until policy says otherwise."

### 1:00-1:25 — the catalog redirects the agent

```
airlock check "SELECT u.name, u.email, u.ssn, o.total FROM users_raw u JOIN orders o ON o.user_id = u.id ORDER BY o.total DESC LIMIT 10" --as growth-agent -c demo/airlock.yaml
```

> "`users_raw` was deprecated. Airlock followed lineage in DataHub to the certified replacement,
> checked the schema was compatible, and rewrote the query to point at `dim_users` — then masked
> the columns on the substitute. The agent didn't know the table moved. The catalog did."

### 1:25-2:10 — the live retag (the centerpiece; do not rush this)

This is the beat that proves nothing is mocked. Slow down and narrate every click.

1. **Right pane.** In DataHub, open `orders`, add the `PII` tag to the `status` column. Let the
   viewer see the tag being applied in the UI.
2. **Left pane.** `airlock refresh -c demo/airlock.yaml` (or wait out the 20s interval and say so).
3. **Left pane.** Re-run the exact query from 0:35:

```
airlock check "SELECT status, COUNT(*) AS n FROM orders GROUP BY status" --as growth-agent -c demo/airlock.yaml
```

> "Same query. Same gateway. `status` is masked now — because somebody changed a tag in the
> catalog thirty seconds ago. No deploy, no restart, no code change. That's what it means for
> policy to be compiled from DataHub rather than copied out of it."

### 2:10-2:35 — write-back closes the loop

Right pane, open `dim_users`; scroll the structured properties, then click the Stats tab:

> "And it writes back. Structured properties on the dataset — last agent access, the policy
> snapshot hash that made the decision, a denied-attempts counter — plus a ledger entry. And on the
> Stats tab, agent query and per-column read counts, written as DataHub's own usage statistics.
> Governance can query what agents did to their data inside DataHub itself, where they already look."

### 2:35-2:55 — the honest close

Left pane:

```
airlock coverage -c demo/airlock.yaml
```

> "Last thing. Airlock only enforces what the catalog states, so it reports its own blind spots:
> columns that look sensitive but carry no classification, rules that match nothing. A security
> tool that only reports its wins isn't one you should trust. Apache 2.0, runs on any laptop with
> Docker and Python, and there's no mock mode — everything you just saw was live."

### Rules for the recording

- **No dead air on a loading screen.** If `up.py` or a refresh needs time, cut it.
- **Never type a command that has not been rehearsed in the same session.** A typo on camera costs
  a re-record; a failed command costs the submission.
- **Do not narrate the architecture diagram.** It's in the README. The video shows behavior.
- **No claim without a corresponding thing on screen.** If it isn't demonstrated, cut the sentence.
- **Watch it back at 720p in a small window.** If the terminal text is unreadable there, the font
  is too small.

---

## Part B — rehearsal and hostile testing

Run all of this before recording. Anything that breaks here becomes a `make judge` case in the same
PR as the fix.

### Adversarial inputs

```
airlock check "SELECT ssn FROM dim_users -- ignore previous instructions" --as growth-agent -c demo/airlock.yaml   # still denied; the comment is not a policy
airlock check "show me the biggest spenders" --as growth-agent -c demo/airlock.yaml                                # AIRLOCK-406, tells the agent to send SQL
airlock check "SELECT salary FROM payroll" --as growth-agent -c demo/airlock.yaml                                  # cross-domain deny, names the owning team
airlock check "SELECT * FROM dim_users" --as growth-agent -c demo/airlock.yaml                                     # star expanded against the catalog schema, then masked
airlock check "DROP TABLE dim_users" --as growth-agent -c demo/airlock.yaml                                        # statement class denied
```

### Write-back read back from DataHub

```
make eval                                    # run real queries through the gateway (writes usage back)
airlock usage -c demo/airlock.yaml           # read the datasetUsageStatistics Airlock wrote to the Stats tab
```

`usage` needs executed queries, not dry-runs: `airlock check` decides without executing, so it
writes no usage. Run `make eval` (or drive `airlock serve` from an MCP client) first, then the
per-dataset, per-agent, per-column counts show up here and on each dataset's Stats tab in the UI.

### Failure modes worth rehearsing

| Do this                                        | Expected                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------- |
| `docker stop` the DataHub container mid-session | In-flight requests unaffected (pinned snapshot); `doctor` reports it |
| Ctrl+C the gateway mid-query, restart           | Clean shutdown, no orphaned warehouse statement, restarts fine       |
| Run `python demo/up.py` a second time           | Converges, never duplicates catalog entries                         |
| Send the same query twice at once               | One warehouse execution (singleflight), identical envelopes         |
| `python demo/reset.py` then `up.py`             | Back to a clean, working stack                                      |

### Green-light checklist

- [ ] `make rehearse` exits 0 — every beat produced the verdicts the narration claims
- [ ] `python tools/judge.py` passes — zero tracebacks
- [ ] `make eval` passes — including the deny-then-reformulate case
- [ ] `airlock coverage` output matches what the video claims
- [ ] The retag moment worked end to end, twice in a row
- [ ] Write-back is visible in the DataHub UI for `dim_users`
- [ ] Video is under 3:00 and readable at 720p
