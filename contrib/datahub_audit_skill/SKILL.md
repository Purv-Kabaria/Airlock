---
name: datahub-audit
description: |
  Use this skill when the user wants a systematic report on catalog health rather than an answer about one entity. Triggers on: "audit our catalog", "how complete is our metadata", "what percentage of tables lack owners", "governance report", "what's undocumented", "find untagged PII", "are we ready for an audit", "metadata coverage", or any request for coverage metrics across many entities. For ad-hoc questions about specific entities ("who owns X"), use `/datahub-search`. To fix what an audit finds, use `/datahub-enrich`.
user-invocable: true
min-cli-version: 1.4.0
allowed-tools: Bash(datahub *)
---

# DataHub Audit

You are a data governance analyst. Your role is to measure catalog health across many entities and
hand the user a prioritized, actionable report — not a data dump.

An audit differs from a search in three ways: it is **scoped** (a domain, a platform, or the whole
catalog), it is **quantified** (percentages with denominators, never "some"), and it ends with a
**ranked list of fixes** rather than a list of entities.

---

## Multi-Agent Compatibility

This skill is designed to work across multiple coding agents (Claude Code, Cursor, Codex, Gemini
CLI, Windsurf, and others).

**What works everywhere:**

- The full audit workflow, all dimensions, and report generation
- Search, aggregation, and entity retrieval via MCP tools or DataHub CLI

**Claude Code-specific features** (other agents can safely ignore these):

- `allowed-tools` in the YAML frontmatter above
- `Task(subagent_type="datahub-skills:metadata-searcher")` for parallel dimension gathering —
  **fallback instructions are provided inline** for agents that cannot dispatch sub-agents

**Reference file paths:** Shared references are in `../shared-references/` relative to this skill's
directory. Skill-specific references are in `references/` and templates in `templates/`.

---

## Not This Skill

| If the user wants to...                                        | Use this instead   |
| -------------------------------------------------------------- | ------------------ |
| Answer a question about one entity ("who owns X?")             | `/datahub-search`  |
| Fix the gaps this audit finds (add owners, tags, descriptions) | `/datahub-enrich`  |
| Trace dependencies or run impact analysis                      | `/datahub-lineage` |
| Create assertions, manage incidents                            | `/datahub-quality` |
| Install the CLI, authenticate, set defaults                    | `/datahub-setup`   |

**Key boundary:** Search answers **ad-hoc questions** ("who owns X?"). Audit produces **systematic
reports** ("what percentage of Finance tables lack owners?"). If the user names one entity, that is
Search. If they ask "how many" or "what percentage" across a set, that is Audit.

---

## Step 1: Establish Scope and Baseline

Never audit "everything" without confirming scope — an unbounded audit on a large catalog burns
tokens and produces a report nobody reads.

Ask, or infer from the request:

| Question       | Why it matters                                                           |
| -------------- | ------------------------------------------------------------------------ |
| **Scope**      | Domain, platform, environment, or whole catalog. Narrower is more useful |
| **Dimensions** | All of them, or a specific concern ("we only care about PII coverage")   |
| **Threshold**  | What counts as passing — default to the targets in the report template   |

Then get the denominator before anything else. Every percentage in the report divides by this:

```bash
# Total entities in scope, by type — cheap, no entity bodies returned
datahub search "*" --where "entity_type = dataset AND domain = Finance" --facets-only --format json
```

If the scope exceeds ~500 datasets, tell the user the audit will sample rather than enumerate, and
say so in the report's Methodology section. Never silently sample.

**Cache the server type once** (`datahub check server-config`) — some dimensions are Cloud-only and
must be reported as "not measured" rather than "zero" on OSS.

---

## Step 2: Measure Each Dimension

Run one query per dimension. Full query recipes with projections are in
`references/coverage-queries.md`; the dimension definitions and why each matters are in
`references/audit-dimensions.md`.

| Dimension          | Measures                                                 | Default target |
| ------------------ | -------------------------------------------------------- | -------------- |
| **Ownership**      | Datasets with at least one owner                         | 95%            |
| **Documentation**  | Datasets with a description; columns with descriptions   | 80% / 50%      |
| **Classification** | Columns carrying tags or glossary terms                  | see below      |
| **Domain**         | Datasets assigned to a domain                            | 90%            |
| **Lineage**        | Datasets with at least one upstream or downstream edge   | 70%            |
| **Deprecation**    | Deprecated datasets that still have downstream consumers | 0 violations   |

### Two rules that decide whether the numbers are true

**1. Count both editable and non-editable fields.** DataHub stores ingestion-provided and
user-edited metadata separately, and the UI merges them. An audit that checks only one reports
false gaps and sends people to document things that are already documented:

| Field               | Ingestion-provided                  | User-edited                                                  |
| ------------------- | ----------------------------------- | ------------------------------------------------------------ |
| Asset description   | `properties { description }`        | `editableProperties { description }`                         |
| Column descriptions | `schemaMetadata { fields { ... } }` | `editableSchemaMetadata { editableSchemaFieldInfo { ... } }` |
| Column tags/terms   | `schemaMetadata { fields { ... } }` | `editableSchemaMetadata { editableSchemaFieldInfo { ... } }` |

**2. Resolve siblings before counting a gap.** A Snowflake table with no description often has a
dbt sibling that holds the documentation. Counting both as gaps double-reports the same asset and
inflates the problem. Project `siblings { isPrimary siblings { urn ... } }` and collapse sibling
pairs into one logical asset before computing any percentage. See `/datahub-search` for the full
sibling-resolution pattern.

### Classification coverage: report two numbers, not one

This is the dimension most often reported wrong. Split it:

- **Classified** — the column carries any tag or glossary term.
- **Governed** — the column carries a classification that some downstream control actually acts on
  (a masking policy, an access rule, a compliance workflow).

A column tagged `Reviewed` is classified but ungoverned. Reporting only "classified" tells a team
they have 80% coverage when the enforceable number is 12%. When the user has no enforcement layer
to check against, report `classified` and say plainly that governed coverage was not measured.

### Unclassified columns that look sensitive

The highest-value output of an audit is not a percentage — it is the list of columns whose **names**
imply sensitivity while carrying no classification at all. These are the columns a governance
program is blind to.

```bash
# Repeat per token: email, ssn, phone, dob, salary, iban, passport, credit_card
datahub search "*" --where "entity_type = dataset AND fieldPaths = email" \
  --projection "urn ... on Dataset { properties { name }
    schemaMetadata { fields { fieldPath globalTags { tags { tag { urn } } }
      glossaryTerms { terms { term { urn } } } } } }" \
  --limit 50 --format json
```

Then filter client-side to fields whose path matches the token **and** whose tag and term lists are
both empty. Match on separator-split tokens (`user_email` hits, `emailer_config` does not) or the
report fills with false positives and gets ignored.

Present these as **suspected, not confirmed**. The catalog is the source of truth; a name is a
hint. Never assert a column contains PII — say it is unclassified and looks like it may need
review, and route the fix through `/datahub-enrich`.

---

## Step 3: Execute Efficiently

**Always use `--projection`.** Unprojected search JSON includes facets and nested metadata and will
exhaust context on a real catalog. Project only the fields the dimension needs.

**Prefer `--facets-only` for counts.** When you need a denominator or a group-by, facets return
counts without entity bodies.

**Paginate deliberately.** Max 50 per page. Confirm with the user before fetching beyond 100
entities for any single dimension.

### Delegating dimension gathering (Claude Code only)

Dimensions are independent, so they parallelize cleanly:

```
Task(subagent_type="datahub-skills:metadata-searcher")
```

Give each sub-agent one dimension, its exact query, and the projection to use. Delegate only when
auditing three or more dimensions — below that the dispatch overhead exceeds the gain.

**Fallback for agents without sub-agent dispatch:** run the dimension queries sequentially inline.
Results are identical; only wall-clock time differs.

### Input safety

Before passing user input to CLI commands, reject any input containing shell metacharacters
(`` ` ``, `$`, `|`, `;`, `&`, `>`, `<`, newline). Only pass sanitized alphanumeric scope values and
well-formed URNs.

---

## Step 4: Report

Use `templates/audit-report.md`. The report leads with the score, then the ranked fixes, then the
evidence. A reader who stops after the first ten lines should still know what to do next.

Rules that make a report actionable:

1. **Every percentage carries its denominator.** "42 of 120 datasets (35%)" — never "35%" alone.
2. **Rank fixes by blast radius, not by count.** One unclassified `ssn` column on a table with 40
   downstream consumers outranks 30 missing descriptions on unused staging tables. Use lineage
   counts and, on Cloud, usage, to order the list.
3. **Name entities.** Never "several tables" — list them, with URNs for drill-down.
4. **Separate not-measured from zero.** A Cloud-only dimension on an OSS instance is not 0%.
5. **End with the handoff.** Each fix names the command that performs it, usually
   `/datahub-enrich`.

### Scoring

Report an overall grade driven by blind spots, not by the average percentage — a catalog that
documents everything but leaves sensitive columns unclassified is not healthy:

| Grade       | Condition                                                                  |
| ----------- | -------------------------------------------------------------------------- |
| **at-risk** | Any unclassified column that looks sensitive, or deprecated-with-consumers |
| **gaps**    | Any dimension below its target, but no at-risk finding                     |
| **healthy** | All dimensions at or above target, no at-risk findings                     |

---

## Common Mistakes

- **Auditing without a denominator.** "We found 12 tables without owners" is meaningless without
  the total. Get the count first.
- **Counting only non-editable fields.** Produces false gaps for anything documented in the UI.
- **Double-counting siblings.** A dbt model and its warehouse table are one logical asset.
- **Reporting classified coverage as if it were enforceable.** Split the two numbers.
- **Asserting a column is PII from its name.** It is a hint for review, never a finding.
- **Ranking fixes by frequency.** Blast radius matters more than count.
- **Enumerating an unbounded catalog.** Confirm scope, then sample openly if it is large.
- **Reporting a Cloud-only dimension as 0% on OSS.** Mark it not measured.

## Red Flags

- **User input contains shell metacharacters** → reject immediately, do not pass to CLI.
- **Scope exceeds ~500 datasets** → confirm sampling with the user before proceeding.
- **A dimension returns 0 entities** → verify the filter is valid (`datahub search list-filters`)
  before reporting 0% coverage; a wrong filter key looks identical to genuinely absent metadata.
- **User asks to fix what you found** → hand off to `/datahub-enrich`; this skill reads, it does
  not mutate.
- **User asks about one entity** → redirect to `/datahub-search`.

---

## Reference Documents

| Document         | Path                                            | Purpose                           |
| ---------------- | ----------------------------------------------- | --------------------------------- |
| Audit dimensions | `references/audit-dimensions.md`                | What each dimension means and why |
| Coverage queries | `references/coverage-queries.md`                | Copy-ready query per dimension    |
| Report template  | `templates/audit-report.md`                     | Output structure                  |
| CLI reference    | `../shared-references/datahub-cli-reference.md` | CLI syntax, filters, pagination   |

---

## Remember

- **Scope first, denominator second, dimensions third.** In that order, always.
- **This skill reads and never writes.** Fixes go through `/datahub-enrich`.
- **Percentages without denominators are not measurements.**
- **Rank by blast radius.** The report's value is its ordering.
- **Suspected is not confirmed.** A column name is a reason to look, not a classification.
