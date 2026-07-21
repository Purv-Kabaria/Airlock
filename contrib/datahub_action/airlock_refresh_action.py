"""A DataHub Action that pushes a snapshot-refresh to Airlock on classification change.

Proposed for upstream (the DataHub Actions framework). Today Airlock polls DataHub every
`refresh_interval`; this Action makes it push: when a tag, glossary term, deprecation, or domain
changes on a dataset, it pokes Airlock's `/refresh` endpoint so enforcement updates within
seconds instead of on the next poll. Kept dependency-isolated here so it can be filed upstream
without pulling in Airlock.

Register it in an actions recipe (see action.yaml) and run with:
    datahub actions -c contrib/datahub_action/action.yaml
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Change categories worth a refresh; other events (e.g. description edits) are ignored.
_RELEVANT = {"TAG", "GLOSSARY_TERM", "DOMAIN", "DEPRECATION"}


class AirlockRefreshAction:
    """Implements the DataHub Actions `Action` interface (create / act / close)."""

    def __init__(self, refresh_url: str, token: str | None = None, timeout: float = 5.0) -> None:
        self._url = refresh_url.rstrip("/") + "/refresh"
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._timeout = timeout

    @classmethod
    def create(cls, config: dict[str, Any], ctx: Any) -> AirlockRefreshAction:
        return cls(
            refresh_url=config["airlock_url"],
            token=config.get("token"),
            timeout=config.get("timeout", 5.0),
        )

    def act(self, event: Any) -> None:
        category = _category(event)
        if category not in _RELEVANT:
            return
        urn = _entity_urn(event)
        try:
            httpx.post(
                self._url,
                headers=self._headers,
                json={"reason": category, "urn": urn},
                timeout=self._timeout,
            )
            logger.info("airlock.refresh_pushed category=%s urn=%s", category, urn)
        except httpx.HTTPError as exc:
            logger.warning("airlock.refresh_failed category=%s detail=%s", category, exc)

    def close(self) -> None:
        return None


def _category(event: Any) -> str:
    payload = getattr(event, "as_json", None)
    data = json.loads(payload()) if callable(payload) else getattr(event, "__dict__", {})
    return str(data.get("category", "")).upper()


def _entity_urn(event: Any) -> str:
    return str(getattr(event, "entityUrn", "") or getattr(event, "entity_urn", ""))
