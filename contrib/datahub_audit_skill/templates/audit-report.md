# Catalog Audit — <scope>

**Grade:** <healthy | gaps | at-risk>
**Scope:** <domain / platform / whole catalog> · <N> datasets · <M> columns
**Run:** <date> · DataHub <cloud | oss>

---

## Do these first

Ranked by blast radius, not by count.

| #   | Fix                                            | Affects              | Command            |
| --- | ---------------------------------------------- | -------------------- | ------------------ |
| 1   | Classify `<dataset>.<column>` (looks like SSN) | 40 downstream assets | `/datahub-enrich`  |
| 2   | Assign owners to <N> Finance datasets          | <N> datasets         | `/datahub-enrich`  |
| 3   | Retire `<deprecated_table>` — 6 live consumers | 6 pipelines          | `/datahub-lineage` |

---

## Coverage

| Dimension          | Covered    | Percent | Target | Status       |
| ------------------ | ---------- | ------- | ------ | ------------ |
| Ownership          | 114 / 120  | 95%     | 95%    | pass         |
| Dataset docs       | 88 / 120   | 73%     | 80%    | below        |
| Column docs        | 402 / 980  | 41%     | 50%    | below        |
| Classified columns | 118 / 980  | 12%     | —      | see below    |
| Governed columns   | —          | —       | —      | not measured |
| Domain assignment  | 110 / 120  | 92%     | 90%    | pass         |
| Lineage            | 79 / 120   | 66%     | 70%    | below        |
| Deprecation        | 2 findings | —       | 0      | fail         |

Every figure carries its denominator. `not measured` is not zero — it means the dimension could not
be evaluated on this instance and why is stated in Methodology.

---

## Unclassified columns that look sensitive

Suspected from column names, not confirmed. The catalog is the source of truth; treat each row as a
column to review, not as a finding.

| Column                          | Type    | Looks like    | Downstream |
| ------------------------------- | ------- | ------------- | ---------- |
| `analytics.users.email_address` | VARCHAR | email address | 40         |
| `raw.staging_hr.salary`         | DECIMAL | compensation  | 3          |

---

## Findings by dimension

### <Dimension>

<One sentence on what the number means for this catalog.>

| Entity   | Gap        | URN                    |
| -------- | ---------- | ---------------------- |
| `<name>` | `<detail>` | `urn:li:dataset:(...)` |

<Repeat per dimension that is below target. Omit dimensions that pass — a report nobody finishes
reading is a report that changes nothing.>

---

## Methodology

**Scope:** <exact filter used>
**Queries executed:** <count>
**Sampled:** <yes/no — if yes, sample size and how entities were selected>
**Siblings:** resolved — dbt/warehouse pairs counted as one logical asset
**Fields:** both editable and non-editable variants counted as coverage
**Not measured:** <dimension> — <reason, e.g. requires DataHub Cloud>

**Limitations:** <what this audit could not see>
