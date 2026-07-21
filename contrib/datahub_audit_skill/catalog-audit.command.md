---
name: catalog-audit
description: Audit catalog metadata coverage and produce a prioritized governance report
argument-hint: "[scope, e.g. a domain, platform, or 'whole catalog']"
---

# DataHub Audit

Use the Skill tool to invoke the full `datahub-audit` skill:

```
Skill tool:
  skill: "datahub-skills:datahub-audit"
```

**User's request:** $ARGUMENTS

This skill measures catalog health across many entities and produces a ranked report:

1. **Coverage:** ownership, documentation, classification, domain, lineage, deprecation hygiene
2. **Blind spots:** unclassified columns whose names suggest they need review
3. **Fixes:** ranked by blast radius, each pointing at the command that performs it

If no arguments provided, ask which scope to audit — a domain, a platform, or the whole catalog.
