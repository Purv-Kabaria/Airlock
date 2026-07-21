# PR: `feat: add datahub-audit skill for catalog coverage reporting`

Target: [`datahub-project/datahub-skills`](https://github.com/datahub-project/datahub-skills)

Branch: `feat/datahub-audit-skill`

---

## Why this PR exists

The registry already points users at `/datahub-audit` in seven places, but the skill does not
exist. Anyone following the guidance hits a dead end:

| File                                            | Reference                                                     |
| ----------------------------------------------- | ------------------------------------------------------------- |
| `skills/datahub-search/SKILL.md`                | "Not This Skill" boundary, next-steps prompt, and a red flag  |
| `skills/datahub-enrich/SKILL.md`                | "Generate quality reports or audits" -> `/datahub-audit`      |
| `skills/datahub-lineage/SKILL.md`               | "Want to run an impact audit? Use `/datahub-audit`"           |
| `skills/datahub-setup/SKILL.md`                 | Listed as an available skill                                  |
| `skills/shared-references/datahub-cli-reference.md` | Uses `datahub -C skill=datahub-audit` as the canonical example |

`datahub-search` draws the boundary explicitly — "Search answers ad-hoc questions. Audit generates
systematic reports" — and then routes systematic reports to a skill that was never shipped. This PR
ships it, using that same boundary as the spec.

## What it adds

- `skills/datahub-audit/` — SKILL.md, two references, a report template, three evaluations, README
- `commands/catalog-audit.md` — the slash command, matching the existing `catalog-*` pattern
- README registration in all four places (skill list, install list, feature matrix, command table,
  directory tree)

## Design notes

Three decisions are worth reviewer attention, because each one is a way audits are commonly wrong:

**Both field variants are counted.** DataHub stores ingestion-provided and user-edited metadata
separately and the UI merges them. An audit checking only `properties { description }` reports
false gaps for everything documented in the UI. The skill projects both and counts either as
coverage — the same rule `datahub-search` already documents for coverage questions.

**Siblings are collapsed before any percentage.** A dbt model and its warehouse table are one
logical asset. Counting both double-reports the gap and inflates the problem.

**Classification is reported as two numbers, not one.** "Classified" (carries any tag or term) and
"governed" (carries a classification some control acts on) diverge sharply in practice — tagging
every column `Reviewed` yields 100% classified and zero protection. Where there is no enforcement
layer to compare against, the skill reports governed as *not measured* rather than implying the
classified number is enforceable. `not measured` is consistently distinguished from `0%`,
including for Cloud-only dimensions on OSS instances.

The highest-value output is not a percentage but the list of **unclassified columns whose names
suggest they need review**. These are presented as suspected, never asserted — the catalog is the
source of truth and a column name is a hint. Matching is on separator-split tokens so
`emailer_config` is not reported for the `email` token; substring matching produces enough false
positives to make the report ignorable.

## Validation

- `prettier --write` and `markdownlint-cli2`: clean
- All three evaluation files parse and follow the existing schema
- Only CLI syntax already documented in `shared-references/datahub-cli-reference.md` and
  `datahub-search/SKILL.md` is used — no invented flags
- Read-only: the skill never mutates metadata and routes every fix to `/datahub-enrich`

## Provenance

Written while building [Airlock](https://github.com/Purv-Kabaria/Airlock), a governance gateway
that compiles enforcement policy from DataHub. The classified-versus-governed distinction came
directly from that work: a gateway that treats "tagged" as "protected" gives a team confidence it
has not earned. The skill is generic to DataHub and mentions no vendor.
