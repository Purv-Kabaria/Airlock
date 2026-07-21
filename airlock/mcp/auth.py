"""Resolve the principal a served process acts as.

Airlock maps a per-agent key to a named principal. A serve process is launched for one agent, so
the principal is fixed at startup from `--principal <name>` or an `AIRLOCK_PRINCIPAL_KEY` env ref.
An unrecognized key resolves to the anonymous (deny-all) principal rather than failing closed at
startup, so a misconfigured client gets actionable AIRLOCK-430 verdicts instead of a dead server.
"""

from __future__ import annotations

import hmac

from airlock.config import AirlockConfig
from airlock.errors import ConfigError
from airlock.logging import get_logger

log = get_logger("airlock.mcp.auth")

ANONYMOUS = "anonymous"


def resolve_principal_name(config: AirlockConfig, *, principal: str | None, key: str | None) -> str:
    if principal:
        known = {p.name for p in config.principals}
        if principal not in known:
            raise ConfigError(
                f"principal {principal!r} is not defined in airlock.yaml; "
                f"known principals: {sorted(known) or '[none]'}"
            )
        return principal
    if key:
        name = _match_key(config, key)
        if name is None:
            log.warning("auth.unknown_key")
            return ANONYMOUS
        return name
    return ANONYMOUS


def _match_key(config: AirlockConfig, key: str) -> str | None:
    """Constant-time key match: compare against every configured key so timing does not reveal
    which principal (if any) a guessed key is close to."""
    matched: str | None = None
    for candidate, name in config.principal_key_map().items():
        if hmac.compare_digest(candidate, key):
            matched = name
    return matched
