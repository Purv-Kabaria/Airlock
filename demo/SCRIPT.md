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

Two documents in one. **Part A** is the recording shot list, timed to 2:50 against the hard
3:00 limit. **Part B** is the unscripted rehearsal — run it before recording, and hand it to anyone
who wants to break the thing themselves.

Everything here runs against the real stack `python demo/up.py` starts. No mocks, no fixtures, no
`--demo` flag. If a beat below cannot be performed live, it does not belong in the video.

---

## Part A — the 2:50 shot list

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

### The beats

Narration lives in [`VIDEO.md`](VIDEO.md) — word for word, timed. Do not keep a second copy here;
two scripts drift and the video ends up claiming something the terminal does not show. This is the
shot list: what to run, where to look, and what the beat has to buy you.

Every command below takes `-c demo/airlock.yaml`, omitted for width.

| Time | Run / show | Look at | What the viewer takes away |
|---|---|---|---|
| 0:06 | The warehouse read directly, no gateway (`record.py` does this) | Raw `name`, `email`, `ssn` rows | This is what a database login sees. That is the problem. |
| 0:26 | `airlock check "SELECT name, email, phone, ssn FROM dim_users" --as growth-agent` | The verdict table, then `executed_sql` | Same question, but email hidden, SSN gone, each with a reason and a next step. |
| 0:52 | **Right pane:** DataHub, `dim_users` Schema tab | The `PII` chips on email/phone, the SSN term on ssn | The rules live in the catalog, not in Airlock. |
| 0:52 | `airlock check "SELECT status, COUNT(*) AS n FROM orders GROUP BY status" --as growth-agent` | No verdicts at all | Nothing marked private here, so nothing happens. It stays out of the way. |
| 1:10 | **Tag change.** Mark `orders.status` as `PII` (UI click, or `record.py` writes it) → `airlock refresh` → same query | The snapshot hash changes, then `AIRLOCK-110` on `status` | A note changed in DataHub; the answer changed. Nothing was redeployed. |
| 1:45 | Two real queries run, then the DataHub properties panel | `airlock.lastAgentAccess`, `lastPolicySnapshot`, `deniedAttempts` | It writes back. The data team sees it where they already work. |
| 2:03 | `airlock check "SELECT u.name, u.email, u.ssn, o.total FROM users_raw u JOIN orders o ON o.user_id = u.id ORDER BY o.total DESC LIMIT 10" --as growth-agent` | `AIRLOCK-201`, then `FROM dim_users` in `executed_sql` | A retired table, quietly redirected to its replacement. |
| 2:14 | `airlock check "SELECT user_id, contact, signup_month FROM user_report" --as growth-agent` | `AIRLOCK-113` and the column it names | An unlabelled column protected because of where it came from. |
| 2:25 | `airlock check "SELECT name FROM dim_users WHERE ssn = '111-22-3333'" --as growth-agent` | `denied`, and the hint under it | Refused, but told what to ask instead. |
| 2:36 | `airlock coverage` | `customer_phone` under suspected gaps | It reports its own blind spots rather than pretending. |

### Manual vs hands-free

`python demo/record.py` performs all of the above, in order, with captions. The retag beat writes
the tag through the same `editableSchemaMetadata` aspect the DataHub UI writes, so the enforcement
change is identical either way.

The one thing the manual path buys you is **clicking the tag in the DataHub UI on camera**, in the
right-hand pane. That is marginally more convincing than a tag written by the script, because the
viewer sees a human do it in a product they recognise. If you take the manual path, do it only for
that beat and let `record.py` carry the rest — every command you type live is a chance to typo on
camera.

### The one beat that is not a dry run

Everything except write-back uses `airlock check`, which decides without executing. The write-back
beat runs two real queries through the gateway — one allowed, one denied — because `check` writes
nothing back, and a properties panel populated by an earlier session is exactly the kind of thing a
judge is right to distrust. Those two queries are why `lastAgentAccess` reads seconds old and why
`deniedAttempts` moves while the camera is on it.

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
python demo/record.py --rehearse             # its write-back beat executes real queries, sinks attached
airlock usage -c demo/airlock.yaml           # read the datasetUsageStatistics Airlock wrote to the Stats tab
```

Write-back needs two things at once, and it is easy to have only one. The queries must be
**executed** — `airlock check` decides without running anything, so it writes nothing — and the
gateway must be built **with its sinks attached**. `make eval` satisfies the first but not the
second: it constructs its gateway with an empty sink list on purpose, so a conformance run never
mutates the catalog it is asserting against. It is not a way to populate the Stats tab.

What does write back: `airlock serve` driven from an MCP client, and the write-back beat in
`demo/record.py`, which goes through `Gateway.build` exactly as `serve` does. Run either, then the
per-dataset, per-agent, per-column counts appear here and on each dataset's Stats tab in the UI.

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
- [ ] Every sentence in `VIDEO.md` points at something on screen when it is said. Read it once
      against a playback with the sound off; anything you cannot point to gets cut.
- [ ] `airlock coverage` output matches what the video claims
- [ ] The retag moment worked end to end, twice in a row
- [ ] `airlock.lastAgentAccess` on `dim_users` is from *this* session, not an earlier one
- [ ] Video is under 3:00 and readable at 720p
