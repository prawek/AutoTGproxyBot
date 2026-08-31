"""Independent discovery and bounded authenticated MTProto measurements.

The cache is a catalog with evidence, not a claim that every link works in Russia.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
import time
from typing import Any

from app.proxy.decoder import DecodedSecret, decode_secret
from app.proxy.filter import filter_proxies
from app.proxy.harvester import harvest, harvest_channels
from app.proxy.identity import make_variant_id
from app.proxy.network import resolve_public_addresses
from app.proxy.probe_engine import get_probe_engine
from app.proxy.selection_service import rank_candidates, evidence_for, timestamp
from app.proxy.sources import get_channels, get_source_urls

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(os.getenv(name, str(default)))))
    except ValueError:
        return default


WORKER_INTERVAL = _env_int("PROXY_UPDATE_INTERVAL", 180, 60, 3600)
CACHE_SIZE = _env_int("PROXY_CACHE_SIZE", 300, 20, 1000)
LOCAL_RECHECK_SECONDS = _env_int("PROXY_RECHECK_INTERVAL", 180, 60, 3600)
LOCAL_BATCH_SIZE = _env_int("PROXY_PROBE_BATCH", 4, 1, 10)
CACHED_BEST_PROXIES: list[dict[str, Any]] = []
banned_proxies: dict[str, float] = {}  # Explicit compatibility exclusions only.
LAST_CYCLE_AT = 0.0
LAST_HARVEST_AT = 0.0
_force_update_event: asyncio.Event | None = None
_probe_update_event: asyncio.Event | None = None
_last_attempt: dict[str, float] = {}


def _proxy_id(host: str, port: int, secret: str) -> str:
    return make_variant_id(host, port, secret)


def calculate_transport_score(decoded: DecodedSecret, port: int, probe_state="tcp_only", source_count=1) -> int:
    """Legacy display helper; never used for eligibility or selection."""
    base = {"faketls": 68, "randpad": 46, "plain": 18}.get(decoded.generation, 10)
    base += 7 if decoded.generation == "faketls" and decoded.sni_domain else 0
    base += 6 if port == 443 else 2 if port in {80, 8080, 8443} else 0
    base += {"tls_verified": 15, "tls_unverified": 3, "tls_rejected": -8, "tls_timeout": -10}.get(probe_state, 0)
    return max(0, min(100, base + min(max(source_count - 1, 0) * 2, 6)))


async def run_pipeline(*, extra_urls=None, repo=None) -> list[dict]:
    """Discover and persist variants; discovery itself is never protocol evidence."""
    channels = get_channels()
    urls = extra_urls if extra_urls is not None else get_source_urls()
    batches = await asyncio.gather(
        harvest_channels(channels, pages=3, concurrency=min(8, len(channels) or 1), timeout_sec=15),
        harvest(urls, concurrency=8, timeout_sec=15), return_exceptions=True,
    )
    raw = [item for batch in batches if isinstance(batch, list) for item in batch]
    old = {p["id"]: p for p in CACHED_BEST_PROXIES}
    discovered: dict[str, dict] = {}
    now = datetime.now(timezone.utc)
    for proxy, decoded, category in filter_proxies(raw):
        variant_id = make_variant_id(proxy.host, proxy.port, decoded.raw)
        previous = old.get(variant_id, {})
        source_list = list(previous.get("sources", []))[:16]
        if proxy.source_url and proxy.source_url not in source_list and len(source_list) < 16:
            source_list.append(proxy.source_url[:2048])
        discovered[variant_id] = {
            **previous, "id": variant_id, "host": proxy.host, "server": proxy.host,
            "port": proxy.port, "secret": decoded.raw, "kind": "mtproto",
            "generation": decoded.generation, "sni_domain": decoded.sni_domain,
            "category": category, "sources": source_list, "source_count": len(source_list),
            "last_seen_at": now, "observations": previous.get("observations", []),
            "probe_state": previous.get("probe_state", "unverified"),
            "is_alive": previous.get("is_alive", False),
        }
        if len(discovered) >= CACHE_SIZE * 4:
            break
    values = list(discovered.values())
    if repo is not None and values:
        await repo.upsert_many(values)
    return values


async def load_initial_cache(repo: Any) -> bool:
    try:
        snapshot = getattr(repo, "get_selection_snapshot", None)
        if snapshot is None:
            rows = await repo.get_best(limit=CACHE_SIZE)
        else:
            import inspect
            rows = await snapshot(limit=CACHE_SIZE) if inspect.iscoroutinefunction(snapshot) else await repo.get_best(limit=CACHE_SIZE)
        CACHED_BEST_PROXIES[:] = [dict(row, server=row.get("host", row.get("server", ""))) for row in rows]
        # Never renew checked_at/valid_until when loading an old snapshot.
        return True
    except Exception:
        logger.warning("Unable to restore persisted proxy evidence")
        return False


def request_pipeline_update() -> bool:
    if _force_update_event is None:
        return False
    _force_update_event.set()
    if _probe_update_event is not None:
        _probe_update_event.set()
    return True


async def _wait(event: asyncio.Event, seconds: float):
    try:
        await asyncio.wait_for(event.wait(), timeout=max(.1, seconds))
    except asyncio.TimeoutError:
        pass
    event.clear()


async def _discovery_worker(repo):
    global LAST_HARVEST_AT
    while True:
        started = time.monotonic()
        try:
            found = await run_pipeline(repo=repo)
            if repo is not None:
                await load_initial_cache(repo)
            elif found:
                now = time.time()
                merged = {p["id"]: p for p in CACHED_BEST_PROXIES
                          if now - timestamp(p.get("last_seen_at")) < 86400}
                merged.update({p["id"]: p for p in found})
                ordered = rank_candidates(merged.values())
                CACHED_BEST_PROXIES[:] = ordered[:CACHE_SIZE]
            LAST_HARVEST_AT = time.time()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Proxy discovery failed; previous evidence retains its original expiry")
        await _wait(_force_update_event, WORKER_INTERVAL - (time.monotonic() - started))
        # Repeated clicks cannot turn the collector into an unbounded busy loop.
        remaining = 30 - (time.monotonic() - started)
        if remaining > 0:
            await asyncio.sleep(remaining)


async def _check_candidate(row: dict, repo, engine):
    variant_id = row["id"]
    _last_attempt[variant_id] = time.time()
    try:
        addresses = await resolve_public_addresses(row["host"], int(row["port"]))
        row["resolved_ips"] = addresses
        old_attempts = len(row.get("observations", []))
        ip = addresses[old_attempts % len(addresses)]
        result = await engine.check(row["host"], int(row["port"]), row["secret"], pinned_ip=ip, timeout=12)
    except (OSError, ValueError, asyncio.TimeoutError):
        # A resolver failure is not an authenticated negative result for every IP.
        row["probe_state"] = "dns_error"
        return
    observation = result.to_dict()
    observation.update(variant_id=variant_id, country="US", network_epoch="local", agent_id="oregon")
    # A snapshot refresh may have replaced the dictionary while TDLib was running.
    row = next((p for p in CACHED_BEST_PROXIES if p["id"] == variant_id), row)
    row["resolved_ips"] = addresses
    observations = list(row.get("observations", []))
    observations.append(observation)
    row["observations"] = observations[-40:]
    row["probe_state"] = result.outcome
    row["checked_at"] = datetime.fromisoformat(result.checked_at)
    row["is_alive"] = evidence_for(row)["status"] == "verified"
    if result.duration_ms is not None:
        row["ping_ms"] = result.duration_ms  # Full test duration, never labelled TCP RTT.
    if repo is not None:
        try:
            await repo.record_observation({**observation, "resolved_ips": addresses})
        except Exception:
            logger.warning("Proxy observation could not be persisted")


async def _measurement_worker(repo):
    global LAST_CYCLE_AT
    engine = get_probe_engine()
    try:
        while True:
            if engine.available:
                now = time.time()
                due = [p for p in CACHED_BEST_PROXIES if not p.get("blocked")
                       and now - _last_attempt.get(p["id"], 0) >= LOCAL_RECHECK_SECONDS]
                ranked = rank_candidates(due)
                hot = [p for p in ranked if p["evidence"]["status"] == "verified"][:max(1, LOCAL_BATCH_SIZE-1)]
                # At least one slot is oldest/unseen exploration, independent of popularity.
                rest = sorted([p for p in due if p["id"] not in {v["id"] for v in hot}],
                              key=lambda p: _last_attempt.get(p["id"], 0))
                selected = hot + rest[:max(0, LOCAL_BATCH_SIZE-len(hot))]
                indexed = {p["id"]: p for p in CACHED_BEST_PROXIES}
                for candidate in selected:
                    row = indexed.get(candidate["id"])
                    if row is not None:
                        await _check_candidate(row, repo, engine)
                if selected:
                    LAST_CYCLE_AT = time.time()
                live_ids = set(indexed)
                for pid in list(_last_attempt):
                    if pid not in live_ids:
                        _last_attempt.pop(pid, None)
            await _wait(_probe_update_event, 5 if CACHED_BEST_PROXIES and engine.available else 30)
    finally:
        await engine.close()


async def _refresh_worker(repo):
    while True:
        await asyncio.sleep(15)
        if repo is not None:
            await load_initial_cache(repo)


async def proxy_updater_worker(repo=None):
    global _force_update_event, _probe_update_event
    _force_update_event, _probe_update_event = asyncio.Event(), asyncio.Event()
    tasks = [asyncio.create_task(_discovery_worker(repo)), asyncio.create_task(_measurement_worker(repo)),
             asyncio.create_task(_refresh_worker(repo))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        _force_update_event = _probe_update_event = None
