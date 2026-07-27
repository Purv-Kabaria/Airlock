# Recording the demo video

Everything needed to record the submission video, in one file: what to set up, what is on screen,
what to say, and the checks that stop a take being wasted. There is deliberately no second script —
two of them drift, and then the voice claims something the screen does not show.

```
Limit:        3:00 hard. Judges may stop watching at three minutes.
Must show:    the project functioning — footage of the real thing running.
Hosting:      public YouTube, Vimeo, or Youku.
Restrictions: no copyrighted music, no third-party trademarks.
Target:       2:50, so a slow read still fits.
```

## Two rules that decide everything

**Judges may never run the code.** The rules say judges are not required to test the project and may
score from the video, the description, and the images alone. This video is not a supplement to the
repo — for some judges it *is* the project.

**Every sentence must be true on screen as it is said.** One claim the screen doesn't back makes a
judge discount the rest, and there is no way to earn it back inside three minutes. Nothing here is
mocked: real DataHub, real warehouse, real queries.

## What the viewer must walk away believing

| # | The belief | The beat that earns it |
|---|---|---|
| 1 | This problem is real and it blocks projects | The pain |
| 2 | The fix works, and it's not in the way | Same query, governed |
| 3 | **The rules come from DataHub, live** | The tag change |
| 4 | It writes back — the loop closes in DataHub | Write-back |
| 5 | It does more than hide columns | The three fast beats |
| 6 | These people are honest | The close |

Beat 3 wins the sponsor criterion. Nobody is convinced by hearing "we use DataHub" — they are
convinced by watching a tag change in DataHub and the answer change because of it.

---

# 1. Set up

## The stack

```bash
python demo/up.py            # DataHub + DuckDB + seeded catalog. Idempotent; safe to re-run.
make rehearse                # MUST exit 0. See "The gate" below.
python tools/judge.py        # hostile-input gauntlet, must be green
```

`up.py` now waits until the catalog is actually queryable before printing "Ready", so the command it
prints will work the moment you paste it. If DataHub was already running it skips the boot.

## The screen

Two panes, side by side, for the whole recording. Do not rearrange windows on camera.

```
+---------------------------+---------------------------+
|  LEFT: terminal           |  RIGHT: browser           |
|  demo/record.py runs here |  DataHub UI  :9002        |
|                           |  logged in, dataset open  |
+---------------------------+---------------------------+
```

- Terminal at **100 columns**, font **16pt minimum**, dark theme, nothing else visible.
- Log into DataHub (`datahub` / `datahub`) **before** you start, and leave the `orders` dataset open,
  so no login and no navigation happens on camera.
- Watch the result back **at 720p in a small window**. That is how a judge sees it. If the text is
  hard to read there, raise the font and shoot again.

## The gate

```bash
make rehearse
```

This is not a dry run for your benefit — it is a verification. It replays every beat, re-runs each
decision with `--json`, and asserts the reason codes the narration promises actually came back. It
exits non-zero and names any beat that no longer holds. It also prints the projected length of the
take beside the length of the narration, and warns if they drift more than twenty seconds apart or
either crosses 3:00.

Run it until it exits 0. Then run `python demo/record.py` and record that.

---

# 2. The flow

`python demo/record.py` plays every beat hands-free, with captions and pauses sized for a voiceover.
Nothing is typed on camera. You read the words below over it.

Timings are where each beat lands in a take of about 2:50.

| Time | Beat | On screen | What the viewer must notice |
|---|---|---|---|
| 0:00 | Title | One line of text | What this is |
| 0:06 | The pain | The raw table, read straight from the database | The agent can see everything, including SSNs |
| 0:26 | The fix | The same question through Airlock | Email hidden, SSN gone, and a reason for each |
| 0:52 | Where rules come from | **Right pane:** DataHub, the tags on the columns | Nothing is hardcoded |
| 1:10 | **The tag change** | DataHub → refresh → same query | A tag changed; the answer changed |
| 1:45 | Write-back | **Right pane:** the dataset's Properties tab | DataHub now shows who touched the data |
| 2:03 | Three more things | Redirect, inherited, self-correction | It does more than hide columns |
| 2:36 | Close | Blind-spot report | Honest about limits; all of it was live |

**The one beat that is not a dry run.** Every beat except write-back uses `airlock check`, which
decides without executing. The write-back beat runs two real queries through the gateway — one
allowed, one denied — because `check` writes nothing back, and a Properties tab populated by an
earlier session is exactly what a judge is right to distrust. Those two queries are why
`lastAgentAccess` reads seconds old and `deniedAttempts` moves while the camera is on it.

**Manual vs hands-free.** `record.py` writes the retag through the same `editableSchemaMetadata`
aspect the DataHub UI writes, so enforcement changes identically either way. The only thing doing it
by hand buys you is *clicking the tag in the DataHub UI on camera*, which is marginally more
convincing because the viewer watches a human do it in a product they recognise. If you take that
path, do it **only** for that beat and let `record.py` carry the rest — every command typed live is a
chance to typo on camera.

---

# 3. The words

Read at a steady pace. Slow down where marked. Bracketed lines are directions, not spoken.

### Title — 0:00–0:06

> This is Airlock. It lets a company point an AI assistant at their database without handing over
> everyone's private data.

### The pain — 0:06–0:26

*[On screen: the customer table, read straight from the database with no gateway in the way.]*

> Companies want to ask their database questions in plain English. An AI agent can do that — but to
> read the data, it needs a database login.
>
> And a login sees everything. Names, emails, social security numbers. All of it, to a program that
> decides what to do on its own.
>
> So the security team says no, and the project stops there. That's where most of these ideas die.

### The fix — 0:26–0:52

*[On screen: the same query, through Airlock. Verdict table, then the SQL that actually ran.]*

> Airlock sits in the middle. Same question, same agent.
>
> But look at what comes back. The email is covered up. The social security number is gone —
> replaced with nothing.
>
> And the agent is told *why*, line by line: what was changed, and what to do instead. Not an error
> message for a person to read. Instructions a program can follow.

### Where the rules come from — 0:52–1:10

*[On screen: DataHub. The `PII` tag on email, the SSN label on ssn.]*

> Here's the part that matters. None of those rules are written in Airlock.
>
> This is DataHub — the catalog where this company already keeps notes about its data. Someone
> marked this column as private, and this one as a social security number. Airlock just reads that
> and does what it says.

### The tag change — 1:10–1:45 *(slow down here)*

*[On screen: the `status` query running clean → a tag is added in DataHub → refresh → the same query
again, now hidden.]*

> So watch what happens when the notes change.
>
> Right now, this column is public. The query runs, nothing is hidden.
>
> Now someone on the data team marks that column private in DataHub. That's it — no new code,
> nothing restarted, nobody redeployed anything.
>
> *[pause for the re-run]*
>
> Same query. Same system. Now it's hidden. The rule changed because the catalog changed, about
> thirty seconds ago.

### Write-back — 1:45–2:03

*[On screen: real queries run, then the DataHub dataset page.]*

> It also writes back. These two queries just ran for real.
>
> And here they are inside DataHub: which agent touched this table, when, and how many times it was
> turned down. The data team sees it in the tool they already use.

### Three more things — 2:03–2:36

*[On screen: three fast beats, one after another.]*

> Three more, quickly.
>
> This table was retired. Airlock followed the trail in DataHub to its replacement and quietly sent
> the question there instead. The agent never knew.
>
> This column has no label at all — but DataHub says it was copied from an email address, so Airlock
> protects it anyway. That's the leak nobody remembers to close.
>
> And when a question is refused, the answer doesn't just say no. It says what to ask instead — so
> the agent can fix its own next question.

### Close — 2:36–2:50

*[On screen: `airlock coverage`.]*

> Last thing: Airlock only protects what the catalog knows about, so it tells you where it's blind
> instead of pretending it isn't.
>
> Free and open source. Runs on any laptop. And everything you just saw was real.

---

# 4. How to say it

- **Don't read the codes out loud.** `AIRLOCK-110` is on screen. Saying "A-I-R-L-O-C-K one one zero"
  burns four seconds and tells the viewer nothing. Say what it *means*.
- **The tag change is the video.** If you rush anything, don't rush that. Let the "before" result sit
  for a full second before you say someone marks the column.
- **Never apologise on camera.** No "as you can see", no "sorry, this takes a second". Where a beat
  needs time, the script already budgeted the silence.
- **Record the audio separately if you can.** Reading live over the terminal tempts you to speed up
  when output is slow.
- **Say "hidden", not "masked". "Rules", not "policy". "The catalog", not "the metadata plane."**
  The words you picked up building this are yours, not the viewer's.

## Things not to say

Each is either unprovable on screen or a bigger claim than the demo supports. A judge who catches one
stops trusting the rest.

| Don't say | Why | Say instead |
|---|---|---|
| "Works with any database" | You showed one | "The demo runs on DuckDB" — the README lists the rest |
| "Production ready" | Nothing on screen shows that | "Free and open source, runs on any laptop" |
| "Impossible to bypass" | An agent holding a real database password goes around it | "Every question the agent asks goes through this" |
| "Faster than X" | No measurement on screen | Cut it |
| "AI-powered" | It is deliberately *not* — that is the selling point | "It decides the same way every time" |
| Anything about the roadmap | The video is for what exists today | Cut it |

---

# 5. The optional extra clip: the agent fixes itself

Keep this **out of the main take**. It calls a live language model — the one moving part that can
hang or wander mid-recording. Record it separately and cut it in, or link it.

`python demo/agent_reformulation.py` connects a real AI agent to Airlock and asks it to look up
someone by social security number. Airlock refuses. The agent reads the refusal and asks a different
question that works. Set one of these and it picks the provider itself:

| Variable | For |
|---|---|
| `ANTHROPIC_API_KEY` | Claude |
| `OPENAI_API_KEY` | OpenAI |
| `AIRLOCK_AGENT_BASE_URL` | Any OpenAI-compatible server (Together, Groq, local Ollama or vLLM) |
| `AIRLOCK_AGENT_MODEL` | Override the default model |

With none set it exits with a named error and changes nothing, so a missing key cannot surprise you
mid-take.

**Use a model that can hold a multi-step tool workflow** — roughly 7B and up, or any hosted model.
Smaller ones guess column names instead of calling `warehouse_describe_table` first, which produces a
real run of an agent flailing: true, and useless on camera.

> This is a real AI agent, connected the same way a coding assistant would be. It asks for someone
> by social security number. Turned down. It reads the reason, understands what it's allowed to ask
> for, and rewrites its own question. Nobody told it the rule — the system did, in words a program
> can act on.

**The fallback is already committed:** [`examples/agent_session.md`](../examples/agent_session.md) is
the same loop captured turn by turn over MCP. If the live call misbehaves mid-take, put that on
screen instead. Both are real runs; that one cannot fail on camera.

---

# 6. Before you publish

- [ ] `make rehearse` exits 0 — every beat produced the verdicts the narration claims
- [ ] `python tools/judge.py` passes — zero tracebacks
- [ ] `make eval` passes — including the deny-then-reformulate case
- [ ] Every sentence points at something on screen when it is said. Watch it once with the sound off;
      anything you cannot point to gets cut.
- [ ] `airlock coverage` output matches what the close claims
- [ ] The tag change worked end to end, twice in a row
- [ ] `airlock.lastAgentAccess` on `dim_users` is from *this* session, not an earlier one
- [ ] Under 3:00 and readable at 720p in a small window

## If something breaks while you are testing

| Do this | Expected |
|---|---|
| `docker stop` the DataHub container mid-session | In-flight requests unaffected (pinned snapshot); `doctor` reports it |
| Ctrl+C the gateway mid-query, restart | Clean shutdown, no orphaned statement, restarts fine |
| Run `python demo/up.py` a second time | Converges, never duplicates catalog entries |
| Send the same query twice at once | One warehouse execution (coalesced), identical envelopes |
| `python demo/reset.py` then `up.py` | Back to a clean, working stack |
| Broker won't restart after a machine reboot | Restart Zookeeper first, then the broker — a stale registration blocks it |

Anything that breaks here becomes a `make judge` case in the same change as the fix.
