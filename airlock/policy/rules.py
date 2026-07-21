"""The rule model and the classification matcher.

A `Rule` binds a `Match` over catalog classifications (tags, glossary terms, lifecycle,
certification, domain) to an `ActionSpec` (mask / deny / substitute / allow). The matcher
takes *classification primitives*, not fact objects, so it has no dependency on the graph
and is trivially testable. Precedence (edge case #19) is resolved by `winning_action`:

    deny > mask > allow  ; among equals, the more specific match wins ; then rule id.

A genuine tie (same rank, same specificity, conflicting action) is a lint error surfaced by
`airlock policy lint`, never a runtime coin-flip — `winning_action` stays deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class ActionKind(StrEnum):
    DENY = "deny"
    MASK = "mask"
    SUBSTITUTE_CERTIFIED = "substitute_certified"
    ALLOW = "allow"


class _Rank(IntEnum):
    # Lower wins. Substitution is table-level and never competes with column actions here.
    DENY = 0
    MASK = 1
    ALLOW = 2
    SUBSTITUTE = 3


_RANK = {
    ActionKind.DENY: _Rank.DENY,
    ActionKind.MASK: _Rank.MASK,
    ActionKind.ALLOW: _Rank.ALLOW,
    ActionKind.SUBSTITUTE_CERTIFIED: _Rank.SUBSTITUTE,
}

# "auto" defers strategy choice to masking.resolve_strategy, keyed on the column's data type.
AUTO_STRATEGY = "auto"


@dataclass(frozen=True, slots=True)
class ActionSpec:
    kind: ActionKind
    strategy: str = AUTO_STRATEGY  # only meaningful when kind is MASK


@dataclass(frozen=True, slots=True)
class Match:
    """A rule matches a subject when every field set here is satisfied by the subject."""

    tag: str | None = None
    glossary_term: str | None = None
    lifecycle: str | None = None
    certification: str | None = None
    domain: str | None = None

    def specificity(self) -> int:
        return sum(
            1
            for v in (self.tag, self.glossary_term, self.lifecycle, self.certification, self.domain)
            if v is not None
        )


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    match: Match
    action: ActionSpec
    _specificity: int = field(default=0, compare=False)

    @classmethod
    def make(cls, rule_id: str, match: Match, action: ActionSpec) -> Rule:
        return cls(id=rule_id, match=match, action=action, _specificity=match.specificity())


def rule_applies(
    rule: Rule,
    *,
    tags: frozenset[str],
    terms: frozenset[str],
    lifecycle: str | None,
    certification: str | None,
    domain: str | None,
) -> bool:
    m = rule.match
    if m.tag is not None and m.tag not in tags:
        return False
    if m.glossary_term is not None and m.glossary_term not in terms:
        return False
    if m.lifecycle is not None and m.lifecycle != lifecycle:
        return False
    if m.certification is not None and m.certification != certification:
        return False
    if m.domain is not None and m.domain != domain:
        return False
    # A match with no conditions never applies to anything: rules must bind to a classification.
    return m.specificity() > 0


def matching_rules(
    rules: tuple[Rule, ...],
    *,
    tags: frozenset[str] = frozenset(),
    terms: frozenset[str] = frozenset(),
    lifecycle: str | None = None,
    certification: str | None = None,
    domain: str | None = None,
) -> list[Rule]:
    return [
        r
        for r in rules
        if rule_applies(
            r,
            tags=tags,
            terms=terms,
            lifecycle=lifecycle,
            certification=certification,
            domain=domain,
        )
    ]


def winning_action(candidates: list[Rule]) -> Rule | None:
    """Deterministic precedence winner among candidate rules; None if the list is empty."""
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda r: (_RANK[r.action.kind], -r._specificity, r.id),
    )


def tie_conflicts(candidates: list[Rule]) -> list[tuple[Rule, Rule]]:
    """Pairs of rules that tie on rank and specificity but prescribe different actions.

    Used by `airlock policy lint` to reject ambiguous policy before it can surprise anyone.
    """
    conflicts: list[tuple[Rule, Rule]] = []
    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            a, b = candidates[i], candidates[j]
            same_rank = _RANK[a.action.kind] == _RANK[b.action.kind]
            same_spec = a._specificity == b._specificity
            differ = a.action != b.action
            if same_rank and same_spec and differ:
                conflicts.append((a, b))
    return conflicts
