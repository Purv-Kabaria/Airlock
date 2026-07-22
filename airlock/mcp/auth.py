"""Resolve the principal a request acts as.

Airlock maps a per-agent key to a named principal. Where that identity comes from depends on the
transport, because the transports differ in how many agents one process serves:

  * **stdio** - the client launches the process, so one process serves exactly one agent. The
    process boundary *is* the identity boundary, and the principal is fixed at startup from
    `--principal <name>` or an `AIRLOCK_PRINCIPAL_KEY` env ref.
  * **http** - one process serves many clients concurrently, so identity must come from the
    request. Every call carries `X-Airlock-Key` and is resolved on its own; a startup principal
    would hand every connecting agent the same scope, which is the over-permissioned credential
    Airlock exists to remove.

An unrecognized key resolves to the anonymous (deny-all) principal rather than failing closed at
startup, so a misconfigured client gets actionable AIRLOCK-430 verdicts instead of a dead server.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping

from airlock.config import AirlockConfig
from airlock.errors import ConfigError
from airlock.logging import get_logger

log = get_logger("airlock.mcp.auth")

ANONYMOUS = "anonymous"
PRINCIPAL_HEADER = "x-airlock-key"


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


def principal_from_headers(config: AirlockConfig, headers: Mapping[str, str]) -> str:
    """The principal for one HTTP request, from its `X-Airlock-Key` header.

    A missing or unrecognized key is the anonymous deny-all principal, never the process's startup
    identity: on a shared HTTP gateway that fallback would silently grant one agent's scope to
    every other agent that connected.
    """
    key = headers.get(PRINCIPAL_HEADER)
    if not key:
        log.warning("auth.missing_key")
        return ANONYMOUS
    return resolve_principal_name(config, principal=None, key=key)


def _match_key(config: AirlockConfig, key: str) -> str | None:
    """Constant-time key match: compare against every configured key so timing does not reveal
    which principal (if any) a guessed key is close to."""
    matched: str | None = None
    for candidate, name in config.principal_key_map().items():
        if hmac.compare_digest(candidate, key):
            matched = name
    return matched
