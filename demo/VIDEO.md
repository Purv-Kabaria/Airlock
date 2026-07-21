# Voiceover — read this over `python demo/record.py`

Word-for-word narration for the submission video, timed to the self-running demo. Two ways to use
it: read it aloud while `demo/record.py` plays, or paste it into a text-to-speech engine and lay the
audio over the screen capture. Every number and column name below is what appears on screen — if you
edit the demo, edit this.

**Recording checklist**
1. `python demo/up.py` — wait for the stack to be healthy.
2. `python demo/record.py --rehearse` — confirm every beat renders and the retag flips `status`.
3. Terminal at 100 columns, 16pt+, dark theme. Full screen. Nothing else on camera.
4. Start the screen recorder, run `python demo/record.py`, read the lines below. Total ≈ 2:45.
5. Watch it back at 720p in a small window. If text is unreadable there, raise the font and re-shoot.

---

### Title card (0:00–0:06)
> "This is Airlock — a governance gateway that sits between an AI agent and your SQL warehouse."

### Cold open (0:06–0:35)
> "A text-to-SQL agent sends this query. It asks for name, email, and social security number. Watch
> what comes back. The email is masked — first letter and domain only. The SSN is gone, replaced
> with NULL. And each change carries a stable reason code and a hint the agent can act on. Nothing
> was installed in the warehouse to do this. Airlock parsed the SQL, resolved every column to its
> DataHub catalog entry, and rewrote the query in flight."

### Clean query (0:35–0:55)
> "Here's a query with no sensitive columns — just a count by status. Airlock does nothing. It runs
> untouched. The gateway is invisible until the catalog says otherwise. It isn't a wall; it's a
> filter that only acts on what governance has actually classified."

### Substitution (0:55–1:25)
> "Now something only a catalog-aware gateway can do. This query hits `users_raw` — a table that was
> deprecated. Airlock followed the lineage in DataHub to its certified replacement, `dim_users`,
> checked that it has every column the query needs, and rewrote the query to point at it — then
> masked the email and nulled the SSN on the replacement. The agent never knew the table moved. The
> catalog did."

### The live retag (1:25–2:10) — the centerpiece
> "This is the part that proves nothing here is hardcoded. Same status query as before — right now
> `status` runs clean. Watch: a data steward tags `status` as PII in DataHub. No deploy. No restart.
> Airlock recompiles its policy from the catalog — see the snapshot hash change — and the very next
> run of the exact same query masks `status`. A tag changed in the catalog thirty seconds ago, and
> enforcement changed with it. That is what it means for policy to be compiled from DataHub, not
> copied out of it."

### Write-back (2:10–2:35)
> "And it writes back. Every decision updates the dataset in DataHub — the last agent to touch it,
> the exact policy snapshot that made the call, a running count of denied attempts. Your governance
> team can see what agents did to their data inside the catalog they already use."

### It finds and fixes its blind spots (2:30–2:55)
> "One last thing. Airlock only enforces what the catalog states, so it reports its own blind spots —
> here, a `customer_phone` column nobody classified. And it doesn't just report it: `airlock propose`
> writes that finding back to DataHub, so a steward sees the gateway's suggestion in the catalog and
> can tag it. The gateway improves the graph it enforces from. Apache 2.0, runs on any laptop with
> Docker and Python, no mock mode — everything you just saw was live."
