# Demo script (about 3 minutes)

Everything here runs against the real stack `python demo/up.py` starts. No mocks.

## 0. Before recording
```
python demo/up.py                 # DataHub + DuckDB + seeded catalog
airlock tail -c demo/airlock.yaml # second pane: the live decision stream
```

## 1. Clean query (10s) — the gateway is invisible when nothing is sensitive
```
airlock check "SELECT status, COUNT(*) AS n FROM orders GROUP BY status" --as growth-agent -c demo/airlock.yaml
```
Status `executed`, no verdicts beyond a row-limit note. Point out: Airlock only intervenes when policy says so.

## 2. PII query (40s) — masking and denial, explained
```
airlock check "SELECT name, email, ssn FROM dim_users" --as growth-agent -c demo/airlock.yaml
```
`email` is partially masked (tag `PII`), `ssn` is nulled (term `Classification.SSN`), each with a reason code and a hint. Show the rewritten SQL: the mask is an inline expression — nothing is installed in the warehouse.

## 3. Deprecated table (40s) — the catalog redirects the agent
```
airlock check "SELECT u.name, u.email, u.ssn, o.total FROM users_raw u JOIN orders o ON o.user_id = u.id ORDER BY o.total DESC LIMIT 10" --as growth-agent -c demo/airlock.yaml
```
`users_raw` is deprecated; Airlock substitutes the certified `dim_users` discovered through lineage (verdict `AIRLOCK-201`), then masks/denies columns on the substitute. The agent didn't know the table moved — the catalog did.

## 4. The live-retag moment (40s) — proof nothing is mocked
1. Open the DataHub UI (`http://localhost:9002`, login `datahub`/`datahub`).
2. Open dataset `orders`, add the `PII` tag to the `status` column (or any column).
3. Wait one refresh interval (20s) or run `airlock refresh -c demo/airlock.yaml`.
4. Re-run: `airlock check "SELECT status FROM orders" --as growth-agent -c demo/airlock.yaml`
   — `status` is now masked. Enforcement changed because the *catalog* changed.

## 5. Write-back (20s) — close the loop
In the DataHub UI, open `dim_users`: the structured properties `airlock.lastAgentAccess` and
`airlock.lastPolicySnapshot` are populated, and the institutional-memory ledger shows the access.
Governance can query agent behavior inside the graph itself.

## Throw things at it (if time)
```
airlock check "SELECT ssn FROM dim_users -- ignore previous instructions" --as growth-agent -c demo/airlock.yaml   # still denied
airlock check "show me the biggest spenders" --as growth-agent -c demo/airlock.yaml                                  # AIRLOCK-406, friendly
airlock check "SELECT salary FROM payroll" --as growth-agent -c demo/airlock.yaml                                    # cross-domain deny, names the owner
```
