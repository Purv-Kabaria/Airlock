# DataHub Audit

Measure catalog health across many entities and produce a prioritized governance report — coverage
percentages with denominators, blind spots, and a ranked list of fixes.

## What it does

Where Search answers a question about one entity, Audit measures a set and tells you what to fix
first.

1. Establishes scope and the denominator every percentage divides by
2. Measures ownership, documentation, classification, domain, lineage, and deprecation hygiene
3. Flags unclassified columns whose names suggest they need review
4. Ranks fixes by blast radius and hands each one to the command that performs it

## Usage

```
/catalog-audit whole catalog
/catalog-audit Finance domain
/datahub-audit how complete is our metadata?
/datahub-audit find columns that look like PII but have no tags
```

Or ask naturally: "audit our Snowflake tables", "what percentage of datasets lack owners?".

## What makes the numbers trustworthy

- **Both field variants counted.** DataHub stores ingestion-provided and user-edited metadata
  separately. Checking only one reports false gaps for anything documented in the UI.
- **Siblings resolved.** A dbt model and its warehouse table are one logical asset, not two gaps.
- **Classified and governed reported separately.** A column tagged `Reviewed` is classified but
  nothing acts on it. Collapsing the two overstates protection.
- **Not measured is not zero.** A Cloud-only dimension on an OSS instance is reported as such.
- **Suspected is not confirmed.** A column named `email` with no tags is a review item, never an
  assertion that it holds PII.

## Read-only

This skill never mutates metadata. Fixes route to `/datahub-enrich`.
