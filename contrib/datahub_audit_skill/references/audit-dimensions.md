# Audit Dimensions

What each dimension measures, why it matters, and how to judge the result. Targets are defaults —
a team with a stated policy uses theirs instead.

---

## Ownership

**Measures:** datasets with at least one owner in the `ownership` aspect.

**Target:** 95%.

**Why:** an unowned dataset has nobody to ask when it breaks, nobody to approve access, and nobody
accountable for its classification. Ownership is the dimension every other governance workflow
depends on, which is why the bar is higher than for documentation.

**Judging:** distinguish _technical_ owners from _business_ owners. A dataset with only a technical
owner still has no one who can answer "should this agent see this column?". Report the split when
the catalog populates owner types.

---

## Documentation

**Measures:** datasets with a non-empty description; separately, columns with descriptions.

**Target:** 80% of datasets, 50% of columns.

**Why:** column descriptions are what let a person — or an agent — pick the right field without
reading the pipeline. The column target is deliberately lower than the dataset target: wide tables
have many mechanical columns (`_loaded_at`, surrogate keys) where a description adds nothing.

**Judging:** check the editable and non-editable variants of both fields, and resolve siblings
first. A dbt model frequently holds the documentation for its warehouse sibling. Descriptions that
restate the column name (`user_id` → "the user id") pass an automated check and fail a human one;
if you sample any, say so rather than implying the number is quality-adjusted.

---

## Classification

**Measures:** two numbers.

- **Classified** — columns carrying any tag or glossary term.
- **Governed** — columns carrying a classification some control actually acts on.

**Target:** no fixed percentage. The meaningful target is zero unclassified columns that look
sensitive.

**Why:** a percentage here is easy to game and easy to misread. Tagging every column `Reviewed`
produces 100% classified coverage and zero protection. What matters is whether the columns that
carry risk are classified with terms the organization's controls recognize.

**Judging:** report both numbers with their denominators, and lead with the suspected-gap list
rather than the percentage. If there is no enforcement layer to compare against, report `classified`
and state that `governed` was not measured — do not present one as the other.

---

## Domain

**Measures:** datasets assigned to a domain.

**Target:** 90%.

**Why:** domains are how most access policies, ownership routing, and cost attribution are scoped.
An unassigned dataset falls outside every domain-scoped rule, which usually means it is either
invisible to policy or caught by a catch-all.

**Judging:** unassigned datasets concentrated in one platform normally indicate an ingestion recipe
that never set a domain, not 200 individual oversights. Report the cluster, not the instances.

---

## Lineage

**Measures:** datasets with at least one upstream or downstream edge.

**Target:** 70%.

**Why:** lineage is what makes impact analysis and deprecation safety possible. Without it, nobody
can answer "what breaks if I change this."

**Judging:** true source tables legitimately have no upstream, and true leaf marts legitimately have
no downstream — neither is a gap. Count a dataset as covered if it has an edge in **either**
direction. A dataset isolated in both directions is either genuinely orphaned or missing a
connector, and the two are worth separating when the platform makes it obvious.

---

## Deprecation hygiene

**Measures:** datasets marked deprecated that still have downstream consumers.

**Target:** zero.

**Why:** a deprecated table with live consumers is a migration that stalled. It is the one dimension
where any non-zero count is a finding rather than a percentage, because each instance is a concrete
scheduled breakage.

**Judging:** rank by downstream count. Include the certified or recommended replacement when the
catalog records one — the fix is a redirect, and naming the target makes it actionable.

---

## Structured properties

**Measures:** coverage of whichever structured properties the organization has defined (data tier,
retention class, compliance scope).

**Target:** set by the property's owner; no universal default.

**Why:** structured properties are where most organizations encode their own governance model, so
coverage here maps directly to their internal policy rather than to a generic best practice.

**Judging:** resolve the property's qualified name first — filter fields cannot be guessed. Check
`allowedValues` before reporting a value as invalid. Audit only properties that actually exist in
the instance; a property nobody defined is not a gap.
