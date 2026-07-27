"""Regenerate examples/ - captured envelopes and before/after SQL from the live demo stack.

Run: `python tools/gen_examples.py` (or `make examples`) with the demo stack up (`python demo/up.py`).
Never hand-edit examples/; this is the source of truth so the folder can't go stale (CLAUDE.md §2).
Every envelope here is produced by the real gateway over a snapshot compiled from live DataHub and a
real DuckDB warehouse - the exact path the demo runs - so these are captures, not fabrications.
"""

from __future__ import annotations

import json

from _common import ROOT, live_snapshot, load_demo_config, seed_warehouse
from airlock.audit.record import AuditRecord
from airlock.engine.verdicts import Envelope
from airlock.exec.duckdb_adapter import DuckdbAdapter
from airlock.gateway import Gateway
from airlock.policy.store import SnapshotStore

EXAMPLES = ROOT / "examples"

CASES = [
    (
        "01_clean_aggregate",
        "growth-agent",
        "SELECT status, COUNT(*) AS n, ROUND(SUM(total), 2) AS revenue "
        "FROM orders GROUP BY status ORDER BY revenue DESC",
    ),
    ("02_pii_masked", "growth-agent", "SELECT name, email, phone FROM dim_users LIMIT 5"),
    (
        "03_deprecated_substituted",
        "growth-agent",
        "SELECT u.name, u.email, u.ssn, o.total FROM users_raw u "
        "JOIN orders o ON o.user_id = u.id ORDER BY o.total DESC LIMIT 10",
    ),
    (
        "04_predicate_denied",
        "growth-agent",
        "SELECT name FROM dim_users WHERE email = 'ada@corp.com'",
    ),
    ("05_cross_domain_denied", "growth-agent", "SELECT name, salary FROM payroll"),
    ("06_natural_language_rejected", "growth-agent", "show me the biggest spenders this quarter"),
    (
        "07_complex_cte_window",
        "growth-agent",
        "WITH ranked AS (SELECT name, email, ROW_NUMBER() OVER (ORDER BY signup_date DESC) AS rn "
        "FROM dim_users) SELECT name, email FROM ranked WHERE rn <= 3",
    ),
    (
        "08_lineage_inherited_mask",
        "growth-agent",
        "SELECT user_id, contact, signup_month FROM user_report",
    ),
]


async def main() -> None:
    EXAMPLES.mkdir(exist_ok=True)
    cfg = load_demo_config()
    warehouse = seed_warehouse(cfg)
    graph = live_snapshot(cfg)  # compiled from live DataHub - fails loudly if the stack is down

    store = SnapshotStore(str(ROOT / ".airlock" / "examples.sqlite"))
    store.install(graph)
    gateway = Gateway(cfg, store, DuckdbAdapter(warehouse), [])

    try:
        before_after: list[str] = []
        audit_lines: list[str] = []
        for i, (name, principal, sql) in enumerate(CASES, 1):
            env = await gateway.run_query(sql, principal)
            # Stable request id so `make examples` is a no-op unless behavior actually changed.
            env = env.model_copy(update={"request_id": f"req_example_{i:02d}"})
            payload = json.loads(env.model_dump_json())
            (EXAMPLES / f"{name}.json").write_text(
                json.dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
            before_after.append(_before_after(name, env.original_sql, env.executed_sql))
            audit_lines.append(_audit_line(env))
            print(f"wrote examples/{name}.json  [{env.status}]")

        (EXAMPLES / "before_after.sql").write_text("\n".join(before_after), encoding="utf-8")
        (EXAMPLES / "audit.jsonl").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
        await _write_reformulation(gateway)
        (EXAMPLES / "README.md").write_text(_readme(), encoding="utf-8")
    finally:
        await gateway.aclose()


# A refusal, and the query a reader of that refusal's hint would send next. This is the loop that
# makes Airlock worth speaking to an agent instead of a human, so it needs an artifact a judge can
# read without running anything. Each pair is (label, refused query, the follow-up its hint implies).
REFORMULATIONS = [
    (
        "Aggregating a denied column",
        "SELECT COUNT(ssn) FROM dim_users",
        "SELECT COUNT(*) FROM dim_users",
    ),
    (
        "Filtering on a masked column",
        "SELECT name FROM dim_users WHERE email = 'ada@corp.com'",
        "SELECT name, email FROM dim_users",
    ),
    (
        "Natural language instead of SQL",
        "show me the biggest spenders this quarter",
        "SELECT user_id, SUM(total) AS spend FROM orders GROUP BY user_id ORDER BY spend DESC",
    ),
]


async def _write_reformulation(gateway: Gateway) -> None:
    """Capture refusal, hint, and recovery as one readable file.

    The follow-up queries are what a careful reader of each hint would write - they are not produced
    by a language model, and the file says so. `demo/agent_reformulation.py` is the version driven by
    a real LLM; this one exists because it needs no API key and cannot drift from the gateway, since
    every envelope here comes from the same live run as the rest of examples/.
    """
    out = [
        "# Denied, then recovered",
        "",
        "Airlock's refusals are addressed to a machine: a stable reason code, the subject, and a",
        "hint saying what to do instead. This file is the loop that makes that worth something -",
        "each refusal below, and the query its hint implies, both run against the live stack.",
        "",
        "The follow-up queries were written by reading the hints, not generated by a model. For the",
        "version an actual LLM drives, run `python demo/agent_reformulation.py --capture`.",
        "",
    ]
    for label, refused_sql, recovered_sql in REFORMULATIONS:
        refused = await gateway.run_query(refused_sql, "growth-agent")
        recovered = await gateway.run_query(recovered_sql, "growth-agent")
        blocker = next(
            (v for v in refused.verdicts if v.action in ("deny_statement", "scope_deny")),
            refused.verdicts[0] if refused.verdicts else None,
        )
        out += [
            f"## {label}",
            "",
            f"**The agent asks:** `{refused_sql}`",
            "",
            f"**Airlock refuses** with `{refused.status}`:",
            "",
        ]
        if blocker is not None:
            out += [
                f"- `{blocker.code}` on `{blocker.subject}`",
                f"- why: {blocker.reason}",
                f"- **what to do instead: {blocker.hint}**",
                "",
            ]
        rows = "no rows" if not recovered.rows else f"{len(recovered.rows)} row(s)"
        out += [
            f"**Reading that hint, the agent sends:** `{recovered_sql}`",
            "",
            f"**Airlock answers** `{recovered.status}` with {rows}.",
            "",
            "---",
            "",
        ]
    (EXAMPLES / "reformulation.md").write_text("\n".join(out), encoding="utf-8")
    print(f"wrote examples/reformulation.md  [{len(REFORMULATIONS)} chains]")


def _audit_line(env: Envelope) -> str:
    """One deterministic audit record per example (fixed ts/latency so the file is reproducible)."""
    record = AuditRecord.from_envelope(env, latency_ms=0.0, warehouse="duckdb")
    record = record.model_copy(update={"ts": "2026-07-21T00:00:00+00:00"})
    return record.model_dump_json()


def _before_after(name: str, before: str, after: str | None) -> str:
    lines = [f"-- {name}", "-- before:", f"{before};", "-- after:"]
    lines.append(f"{after};" if after else "-- <denied - not executed>")
    return "\n".join(lines) + "\n"


def _readme() -> str:
    rows = "\n".join(f"- `{name}.json` - {sql}" for name, _, sql in CASES)
    return (
        "# examples\n\n"
        "Captured request/response envelopes and before/after SQL, regenerated by "
        "`python tools/gen_examples.py` (`make examples`) against the live demo stack. Each envelope "
        "comes from the real gateway over a policy snapshot compiled from a live DataHub and a real "
        "DuckDB warehouse - the same path the demo runs. Do not hand-edit.\n\n"
        f"{rows}\n\n"
        "`before_after.sql` pairs each original query with the SQL Airlock actually executed. "
        "`audit.jsonl` is the decision log from this run.\n\n"
        "`reformulation.md` shows three refusals next to the query each one's hint implies, both "
        "run live. That deny-then-recover loop is the point of addressing a refusal to a machine "
        "rather than a person, so it is the file to read first.\n\n"
        "`agent_reformulation.md`, when present, is a captured transcript of a real LLM agent "
        "connected to Airlock's MCP tools getting denied and reformulating its own next query - "
        "generated by `python demo/agent_reformulation.py --capture` against the live stack. The "
        "agent runs on Anthropic or any OpenAI-compatible endpoint (OpenAI, Together, Groq, a local "
        "Ollama or vLLM), so it is not tied to one vendor. Like everything here, it is only ever "
        "written from a real run; there is no hand-authored version.\n"
    )


if __name__ == "__main__":
    from _common import run

    run(main)
