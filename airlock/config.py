"""airlock.yaml: the pydantic boundary and its compilation to runtime policy types.

Config is validated here, once, at load. Everything downstream trusts the result. Secrets
never live in the file — values like `${DATAHUB_GMS_TOKEN}` are env references resolved at
load time; a missing variable is a named `ConfigError`, not a `KeyError` three layers deep.
Durations accept `5m` / `24h` / `30s` / `500ms` / a bare number of seconds.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from airlock.errors import ConfigError
from airlock.policy.graph import EnforcementSettings, Principal, Scope
from airlock.policy.rules import ActionKind, ActionSpec, Match, Rule

_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)\}")
_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$")
_DURATION_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def parse_duration(value: str | int | float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    m = _DURATION.match(value)
    if not m:
        raise ValueError(f"invalid duration {value!r}; use forms like 5m, 24h, 30s, 500ms")
    magnitude, unit = m.groups()
    return float(magnitude) * _DURATION_UNITS[unit or "s"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SnapshotConfig(_Strict):
    refresh_interval: float = Field(default=300.0)
    max_staleness: float = Field(default=86400.0)
    stale_policy: Literal["fail_closed", "serve_stale_readonly"] = "fail_closed"

    @field_validator("refresh_interval", "max_staleness", mode="before")
    @classmethod
    def _dur(cls, v: Any) -> float:
        return parse_duration(v)


class DatahubConfig(_Strict):
    url: str
    token: str | None = None
    snapshot: SnapshotConfig = SnapshotConfig()


class WarehouseDefaults(_Strict):
    row_limit: int = 10000
    statement_timeout: float = 30.0

    @field_validator("statement_timeout", mode="before")
    @classmethod
    def _dur(cls, v: Any) -> float:
        return parse_duration(v)


class WarehouseConfig(_Strict):
    kind: Literal["duckdb", "postgres", "snowflake"]
    dsn: str
    defaults: WarehouseDefaults = WarehouseDefaults()


class EnforcementConfig(_Strict):
    mode: Literal["enforce", "monitor"] = "enforce"
    unknown_tables: Literal["deny", "allow"] = "deny"
    statement_classes: list[str] = ["select"]
    predicate_policy: Literal["deny", "transform"] = "deny"
    substitution: Literal["rewrite", "warn", "off"] = "rewrite"
    table_matching: Literal["exact", "suffix"] = "exact"

    def compile(self, defaults: WarehouseDefaults) -> EnforcementSettings:
        return EnforcementSettings(
            mode=self.mode,
            unknown_tables=self.unknown_tables,
            statement_classes=frozenset(s.lower() for s in self.statement_classes),
            predicate_policy=self.predicate_policy,
            substitution=self.substitution,
            table_matching=self.table_matching,
            default_row_limit=defaults.row_limit,
            default_statement_timeout=defaults.statement_timeout,
        )


class MatchConfig(_Strict):
    tag: str | None = None
    glossary_term: str | None = None
    lifecycle: str | None = None
    certification: str | None = None
    domain: str | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> MatchConfig:
        if not any((self.tag, self.glossary_term, self.lifecycle, self.certification, self.domain)):
            raise ValueError("a rule match must bind to at least one classification")
        return self


class RuleConfig(_Strict):
    id: str
    match: MatchConfig
    action: str | dict[str, str]

    @model_validator(mode="after")
    def _check_action(self) -> RuleConfig:
        _compile_action(self.id, self.action)  # raises ValueError on a bad action, surfaced at load
        return self

    def compile(self) -> Rule:
        match = Match(
            tag=self.match.tag,
            glossary_term=self.match.glossary_term,
            lifecycle=self.match.lifecycle,
            certification=self.match.certification,
            domain=self.match.domain,
        )
        return Rule.make(self.id, match, _compile_action(self.id, self.action))


def _compile_action(rule_id: str, action: str | dict[str, str]) -> ActionSpec:
    if isinstance(action, str):
        try:
            kind = ActionKind(action)
        except ValueError as exc:
            raise ValueError(
                f"action: unknown action {action!r} - expected deny, allow, "
                "substitute_certified, or {mask: <strategy>}"
            ) from exc
        if kind is ActionKind.MASK:
            raise ValueError("action: mask requires a strategy, e.g. {mask: hash}")
        return ActionSpec(kind=kind)
    if set(action) != {"mask"}:
        raise ValueError(f"action: unknown action {action!r} - did you mean {{mask: ...}}?")
    strategy = action["mask"]
    if strategy not in _VALID_MASK_STRATEGIES:
        raise ValueError(
            f"action.mask: unknown strategy {strategy!r} - expected one of "
            f"{sorted(_VALID_MASK_STRATEGIES)}"
        )
    return ActionSpec(kind=ActionKind.MASK, strategy=strategy)


def _valid_mask_strategies() -> frozenset[str]:
    from airlock.masking.strategies import AUTO_ALIASES, STRATEGIES

    return AUTO_ALIASES | frozenset(STRATEGIES)


_VALID_MASK_STRATEGIES = _valid_mask_strategies()


class ScopeConfig(_Strict):
    domains: list[str] | None = None
    platforms: list[str] | None = None


class OverridesConfig(_Strict):
    row_limit: int | None = None
    statement_timeout: float | None = None
    statement_classes: list[str] | None = None

    @field_validator("statement_timeout", mode="before")
    @classmethod
    def _dur(cls, v: Any) -> float | None:
        return None if v is None else parse_duration(v)


class PrincipalConfig(_Strict):
    name: str
    key: str
    scopes: ScopeConfig = ScopeConfig()
    overrides: OverridesConfig = OverridesConfig()

    def compile(self, default_classes: frozenset[str]) -> Principal:
        classes = (
            frozenset(s.lower() for s in self.overrides.statement_classes)
            if self.overrides.statement_classes is not None
            else default_classes
        )
        return Principal(
            name=self.name,
            scope=Scope(
                domains=frozenset(self.scopes.domains) if self.scopes.domains is not None else None,
                platforms=(
                    frozenset(self.scopes.platforms) if self.scopes.platforms is not None else None
                ),
            ),
            statement_classes=classes,
            row_limit=self.overrides.row_limit,
            statement_timeout=self.overrides.statement_timeout,
        )


class OtelConfig(_Strict):
    enabled: bool = False
    endpoint: str | None = None


class AuditConfig(_Strict):
    jsonl: Path = Path("./audit/decisions.jsonl")
    datahub_writeback: bool = True
    otel: OtelConfig = OtelConfig()


class MaskingConfig(_Strict):
    # A secret salt for the equality-preserving `hash` strategy. Set it (via an env ref) in any
    # deployment: without a secret, an attacker who knows the public policy could brute-force
    # low-cardinality hashed values. When unset, Airlock derives a salt from the snapshot hash and
    # `airlock doctor` warns.
    salt: str | None = None


class ServerConfig(_Strict):
    """Concurrency and caching knobs. Defaults hold the budgets in README "Performance & concurrency"
    (50 sustained, 200 burst); raise them for heavier warehouses."""

    max_concurrency: int = Field(default=64, ge=1)  # concurrent decisions before queueing
    burst: int = Field(default=200, ge=0)  # extra queued above the cap before AIRLOCK-440
    connection_pool: int = Field(default=8, ge=1)  # warehouse connections
    decision_cache: int = Field(default=2048, ge=1)  # memoized decision plans
    writeback_queue: int = Field(default=512, ge=1)  # bounded remote-audit backlog before dropping


class AirlockConfig(_Strict):
    datahub: DatahubConfig
    warehouse: WarehouseConfig
    enforcement: EnforcementConfig = EnforcementConfig()
    rules: list[RuleConfig]
    principals: list[PrincipalConfig] = []
    audit: AuditConfig = AuditConfig()
    masking: MaskingConfig = MaskingConfig()
    server: ServerConfig = ServerConfig()

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> AirlockConfig:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"rules: duplicate rule id {rule.id!r} - ids must be unique")
            seen.add(rule.id)
        return self

    def enforcement_settings(self) -> EnforcementSettings:
        return self.enforcement.compile(self.warehouse.defaults)

    def compiled_rules(self) -> tuple[Rule, ...]:
        return tuple(r.compile() for r in self.rules)

    def compiled_principals(self) -> dict[str, Principal]:
        default_classes = frozenset(s.lower() for s in self.enforcement.statement_classes)
        out: dict[str, Principal] = {}
        for p in self.principals:
            if p.name in out:
                raise ConfigError(f"principals: duplicate principal name {p.name!r}")
            out[p.name] = p.compile(default_classes)
        return out

    def principal_key_map(self) -> dict[str, str]:
        """Secret key value -> principal name, for MCP auth. Built from resolved env refs."""
        mapping: dict[str, str] = {}
        for p in self.principals:
            if p.key in mapping:
                raise ConfigError(f"principals: key for {p.name!r} collides with another principal")
            mapping[p.key] = p.name
        return mapping


def _resolve_env(node: Any, *, path: str = "") -> Any:
    if isinstance(node, str):

        def repl(m: re.Match[str]) -> str:
            var = m.group(1)
            val = os.environ.get(var)
            if val is None:
                raise ConfigError(f"{path or 'config'}: environment variable ${{{var}}} is not set")
            return val

        return _ENV_REF.sub(repl, node)
    if isinstance(node, dict):
        return {k: _resolve_env(v, path=f"{path}.{k}" if path else k) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve_env(v, path=f"{path}[{i}]") for i, v in enumerate(node)]
    return node


def load_config(path: str | Path) -> AirlockConfig:
    """Load, env-resolve, and validate airlock.yaml. Raises ConfigError on any problem."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p}")
    with p.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    resolved = _resolve_env(raw)
    try:
        return AirlockConfig.model_validate(resolved)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from exc


def _format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err["loc"])
        lines.append(f"{loc}: {err['msg']}")
    return "invalid airlock.yaml:\n  " + "\n  ".join(lines)
