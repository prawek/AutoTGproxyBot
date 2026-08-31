"""Run with python -m agents.probe_agent [--once].

PROBE_SERVER_URL=https://your-site.example
PROBE_AGENT_TOKEN=<one configured PROBE_AGENTS_JSON token>
TDJSON_LIBRARY=<locally installed trusted TDLib shared library>
PROBE_NETWORK_EPOCH=<change whenever the actual network route changes>

The agent opens only fixed, validated MTProto tasks and never executes commands.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import deque
from datetime import datetime, timezone
import logging
import os
import time
from urllib.parse import urlsplit

import aiohttp

from app.proxy.probe_engine import ProbeEngine

logger = logging.getLogger(__name__)


def server_url(raw: str) -> str:
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("PROBE_SERVER_URL must be an HTTPS origin without credentials/query")
    if parsed.path not in {"", "/"}:
        raise ValueError("PROBE_SERVER_URL must not contain a path")
    return raw.rstrip("/")


async def run(*, once: bool = False) -> None:
    base = server_url(os.getenv("PROBE_SERVER_URL", ""))
    token = os.getenv("PROBE_AGENT_TOKEN", "")
    epoch = os.getenv("PROBE_NETWORK_EPOCH", "")
    if not 32 <= len(token) <= 256:
        raise ValueError("Configure a provisioned PROBE_AGENT_TOKEN (at least 32 characters)")
    if not epoch or len(epoch) > 64 or not all(c.isalnum() or c in "_-" for c in epoch):
        raise ValueError("Set PROBE_NETWORK_EPOCH to identify the current real egress network")
    # The owner explicitly records route changes: no claimed inference from SIM or Wi-Fi names.
    max_hourly = max(1, min(1000, int(os.getenv("PROBE_MAX_CHECKS_PER_HOUR", "120"))))
    starts: deque[float] = deque()
    engine = ProbeEngine(library_path=os.getenv("TDJSON_LIBRARY") or None)
    timeout = aiohttp.ClientTimeout(total=25, connect=10)
    from app.proxy.network import public_connector
    async with aiohttp.ClientSession(timeout=timeout, headers={"Authorization": "Bearer " + token},
                                     connector=public_connector()) as session:
        async def post(path: str, payload: dict) -> dict:
            async with session.post(base + path, json=payload, allow_redirects=False) as response:
                raw = bytearray()
                async for chunk in response.content.iter_chunked(16384):
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise RuntimeError("Server response exceeded bound")
                if response.status == 401:
                    raise PermissionError("Agent token revoked or unknown")
                if response.status >= 400:
                    raise RuntimeError("Probe API request failed: " + str(response.status))
                import json
                value = json.loads(raw)
                if not isinstance(value, dict) or not value.get("ok"):
                    raise RuntimeError("Invalid probe API response")
                return value

        try:
            while True:
                try:
                    available = await engine.initialize()
                    metadata = engine.status
                    await post("/api/probes/heartbeat", {"network_epoch": epoch, "healthy": available,
                        "engine_name": "tdlib", "engine_version": metadata.get("engine_version", "unknown"),
                        "client_profile_id": metadata.get("client_profile_id", "unknown")})
                    if not available:
                        logger.warning("TDLib checker unavailable; no tasks claimed")
                        if once:
                            return
                        await asyncio.sleep(30)
                        continue
                    now = time.monotonic()
                    while starts and starts[0] < now-3600:
                        starts.popleft()
                    remaining = max_hourly-len(starts)
                    if remaining <= 0:
                        if once:
                            return
                        await asyncio.sleep(30)
                        continue
                    response = await post("/api/probes/claim", {"limit": min(2, remaining)})
                    jobs = response.get("jobs")
                    if not isinstance(jobs, list) or len(jobs) > 2:
                        raise RuntimeError("Invalid task batch")

                    async def check(job: dict) -> None:
                        if not isinstance(job, dict) or job.get("type") != "mtproto_check" or job.get("network_epoch") != epoch:
                            raise RuntimeError("Unexpected task type or route epoch")
                        expires = datetime.fromisoformat(str(job.get("expires_at", "")).replace("Z", "+00:00"))
                        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
                            return
                        starts.append(time.monotonic())
                        result = await engine.check(str(job["host"]), int(job["port"]), str(job["secret"]),
                            dc_id=int(job.get("dc_id", 2)), timeout=min(12, float(job.get("timeout", 12))))
                        payload = {"job_id": job["id"], "attempt_id": job["attempt_id"], "lease_token": job["lease_token"],
                                   "result": result.to_dict()}
                        # Immediate retry is idempotent; do not re-run the measurement.
                        for attempt in range(2):
                            try:
                                await post("/api/probes/results", payload)
                                return
                            except (aiohttp.ClientError, asyncio.TimeoutError):
                                if attempt:
                                    raise
                    await asyncio.gather(*(check(job) for job in jobs))
                    if once:
                        return
                    await asyncio.sleep(15)
                except PermissionError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError, ValueError):
                    logger.exception("Probe cycle failed; no success was reported")
                    if once:
                        raise
                    await asyncio.sleep(30)
        finally:
            await engine.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Claim and check at most one bounded batch")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run(once=args.once))


if __name__ == "__main__":
    main()
