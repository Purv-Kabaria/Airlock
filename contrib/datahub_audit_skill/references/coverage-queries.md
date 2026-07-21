# Coverage Queries

Copy-ready queries per dimension. Verified against DataHub CLI v1.4.0. Replace `<SCOPE>` with the
scope clause you established in Step 1, for example `AND domain = Finance` or `AND platform =
snowflake`, or drop it entirely for a whole-catalog audit.

MCP equivalents follow the mapping in `../shared-references/datahub-cli-reference.md` — when MCP
tools are available, prefer them and pass the same filters.

---

## Denominator

Get this before any dimension. Every percentage divides by it.

```bash
datahub search "*" --where "entity_type = dataset <SCOPE>" --facets-only --format json
```

`--facets-only` returns counts without entity bodies, so this stays cheap on a large catalog.

---

## Ownership

```bash
# Datasets missing owners
datahub search "*" --where "entity_type = dataset AND owners IS NULL <SCOPE>" \
  --projection "urn ... on Dataset { properties { name } platform { name } }" \
  --limit 50 --format json
```

If `owners IS NULL` is rejected by the server, fall back to projecting ownership and filtering
client-side:

```bash
datahub search "*" --where "entity_type = dataset <SCOPE>" \
  --projection "urn ... on Dataset { properties { name } ownership { owners { owner type } } }" \
  --limit 50 --format json
```

---

## Documentation

Project both variants — an asset documented in the UI only populates `editableProperties`.

```bash
# Dataset-level descriptions
datahub search "*" --where "entity_type = dataset <SCOPE>" \
  --projection "urn ... on Dataset { properties { name description }
    editableProperties { description }
    siblings { isPrimary siblings { urn ... on Dataset { properties { description } } } } }" \
  --limit 50 --format json
```

```bash
# Column-level descriptions
datahub search "*" --where "entity_type = dataset <SCOPE>" \
  --projection "urn ... on Dataset { properties { name }
    schemaMetadata { fields { fieldPath description } }
    editableSchemaMetadata { editableSchemaFieldInfo { fieldPath description } } }" \
  --limit 50 --format json
```

Count a column as documented if **either** variant has a non-empty description. Merge sibling pairs
into one logical asset before computing the percentage.

---

## Classification

```bash
# Column tags and terms, both variants
datahub search "*" --where "entity_type = dataset <SCOPE>" \
  --projection "urn ... on Dataset { properties { name }
    schemaMetadata { fields { fieldPath
      globalTags { tags { tag { urn } } }
      glossaryTerms { terms { term { urn } } } } }
    editableSchemaMetadata { editableSchemaFieldInfo { fieldPath
      globalTags { tags { tag { urn } } }
      glossaryTerms { terms { term { urn } } } } } }" \
  --limit 50 --format json
```

**Classified** = the column has at least one tag or term in either variant.

**Governed** = that tag or term appears in the set of classifications the organization's controls
act on. Ask the user for that set; if they cannot name one, report governed as not measured.

### Suspected-sensitive, unclassified

Run once per token. Tokens worth checking: `email`, `ssn`, `phone`, `dob`, `birthdate`, `salary`,
`iban`, `passport`, `credit_card`, `account_number`, `latitude`, `longitude`.

```bash
datahub search "*" --where "entity_type = dataset AND fieldPaths = email <SCOPE>" \
  --projection "urn ... on Dataset { properties { name }
    schemaMetadata { fields { fieldPath
      globalTags { tags { tag { urn } } }
      glossaryTerms { terms { term { urn } } } } } }" \
  --limit 50 --format json
```

Filter client-side to fields where the split tokens of `fieldPath` contain the token **and** both
tag and term lists are empty. Split on `_`, `-`, `.`, and case boundaries — substring matching
reports `emailer_config` and destroys trust in the report.

---

## Domain

```bash
datahub search "*" --where "entity_type = dataset <SCOPE>" \
  --projection "urn ... on Dataset { properties { name } domain { domain { urn } } platform { name } }" \
  --limit 50 --format json
```

Group unassigned results by platform before reporting — clusters usually trace to one ingestion
recipe.

---

## Lineage

Facets give the shape cheaply; per-entity checks confirm the edges.

```bash
datahub lineage --urn "<URN>" --direction upstream
datahub lineage --urn "<URN>" --direction downstream
```

A dataset counts as covered with an edge in either direction. For a scoped audit, sample rather
than walking every dataset — say so in Methodology.

---

## Deprecation hygiene

```bash
# Deprecated datasets in scope
datahub search "*" --where "entity_type = dataset AND deprecated = true <SCOPE>" \
  --projection "urn ... on Dataset { properties { name } deprecation { deprecated note } }" \
  --limit 50 --format json
```

For each hit, count downstream consumers with `datahub lineage --urn "<URN>" --direction
downstream`. Any deprecated dataset with one or more consumers is a finding. Rank by consumer count.

---

## Structured properties

```bash
# 1. Discover which properties exist
datahub search "*" --where "entity_type = structuredProperty" --format json --limit 50

# 2. Inspect one for allowed values
datahub get --urn "urn:li:structuredProperty:<qualifiedName>"

# 3. Measure coverage
datahub search "*" \
  --where "entity_type = dataset AND structuredProperties.<qualifiedName> IS NULL <SCOPE>" \
  --projection "urn ... on Dataset { properties { name } }" --limit 50 --format json
```

Never guess a qualified name — resolve it in step 1 or the filter silently matches nothing, which
is indistinguishable from genuinely absent metadata.

---

## Validating a filter before trusting a zero

A wrong filter key returns zero results and looks exactly like absent metadata. When a dimension
reports 0, confirm the key exists before writing it into the report:

```bash
datahub search list-filters
datahub search "*" --where "<your filter>" --dry-run
```
