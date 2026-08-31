"""Общий двухэтапный подбор для сайта и Telegram-бота."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable


@dataclass(slots=True)
class SelectionResult:
    proxy: dict | None
    response_ms: int | None
    checked_unreachable: set[str]
    checked_unknown: set[str] | None = None


async def select_first_reachable(
    primary: Iterable[dict],
    fallback: Iterable[dict],
    check: Callable[[str, int], Awaitable[int | None]],
    *,
    skip_ids: set[str] | None = None,
    batch_size: int = 10,
    threshold_ms: int | None = None,
    allow_fallback: bool = False,
) -> SelectionResult:
    """Legacy diagnostic helper. Production selection uses saved protocol evidence.

    No location-dependent latency cutoff and no silent filter expansion.
    """
    skipped = set(skip_ids or ())
    unreachable: set[str] = set()
    unknown: set[str] = set()

    async def _search(pool: Iterable[dict]) -> tuple[dict, int] | None:
        candidates = [p for p in pool if p.get("id") not in skipped]
        for start in range(0, len(candidates), batch_size):
            batch = candidates[start : start + batch_size]
            results = await asyncio.gather(
                *[check(str(p["server"]), int(p["port"])) for p in batch],
                return_exceptions=True,
            )
            for proxy, response in zip(batch, results):
                if isinstance(response, int) and not isinstance(response, bool) and response >= 0:
                    return proxy, response
            for proxy, response in zip(batch, results):
                proxy_id = str(proxy.get("id", ""))
                if proxy_id:
                    skipped.add(proxy_id)
                    (unknown if isinstance(response, BaseException) else unreachable).add(proxy_id)
        return None

    found = await _search(primary)
    if found is None and allow_fallback:
        found = await _search(fallback)
    if found is None:
        return SelectionResult(None, None, unreachable, unknown)
    return SelectionResult(found[0], found[1], unreachable, unknown)
