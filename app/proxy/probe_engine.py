"""Bounded protocol checks through an isolated official TDLib worker process."""
from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.proxy.decoder import canonical_secret
from app.proxy.network import UnsafeTarget, resolve_public_addresses, validate_public_ip


@dataclass(slots=True)
class ProbeResult:
    outcome: str
    level: str = "auth_key"
    resolved_ip: str | None = None
    ip_family: str | None = None
    engine_name: str = "tdlib"
    engine_version: str = "unknown"
    client_profile_id: str = "tdlib-unknown"
    network_key: str = "us-oregon"
    checked_at: str = ""
    valid_until: str | None = None
    duration_ms: int | None = None
    error_code: str | None = None
    dc_id: int = 2
    probe_country: str = "US"
    access_type: str = "datacenter"
    agent_healthy: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


class ProbeEngine:
    def __init__(self, library_path: str | None = None, network_key: str | None = None):
        self.library_path = library_path if library_path is not None else os.getenv("TDJSON_LIBRARY", "").strip()
        self.network_key = network_key or os.getenv("PROBE_REGION", "us-oregon")
        self._process = None
        self._lock = asyncio.Lock()
        self._metadata = {}

    @property
    def available(self) -> bool:
        return bool(Path(self.library_path).is_file()) if self.library_path else importlib.util.find_spec("tdjson") is not None

    @property
    def status(self) -> dict:
        return {"available": self.available, "engine": "tdlib", **self._metadata}

    async def initialize(self) -> bool:
        if not self.available:
            return False
        async with self._lock:
            try:
                await self._start()
                return True
            except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                await self._stop()
                return False

    async def _stop(self):
        process, self._process = self._process, None
        if process and process.returncode is None:
            process.kill()
            await process.wait()

    async def close(self):
        async with self._lock:
            await self._stop()

    async def _start(self):
        if self._process and self._process.returncode is None:
            return
        # The native parser needs system library paths, not application credentials.
        inherited = {"PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP",
                     "LOCALAPPDATA", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}
        env = {name: value for name, value in os.environ.items() if name in inherited}
        env["TDJSON_LIBRARY"] = self.library_path
        env["PYTHONIOENCODING"] = "utf-8"
        self._process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "app.proxy.tdjson_helper", env=env,
            cwd=str(Path(__file__).resolve().parents[2]),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=65536,
        )
        line = await asyncio.wait_for(self._process.stdout.readline(), timeout=5)
        ready = json.loads(line)
        if not ready.get("ready"):
            await self._stop()
            raise RuntimeError("Native engine unavailable")
        self._metadata = {key: ready[key] for key in ("engine_version", "client_profile_id", "package_version") if key in ready}

    async def check(self, host: str, port: int, secret: str, *, dc_id: int = 2,
                    pinned_ip: str | None = None, timeout: float = 12) -> ProbeResult:
        started = datetime.now(timezone.utc)
        monotonic = time.monotonic()
        result = ProbeResult("engine_error", checked_at=started.isoformat(), network_key=self.network_key, dc_id=dc_id)
        if not self.available:
            result.outcome, result.level, result.error_code = "unsupported_checker", "none", "native_engine_unavailable"
            return result
        try:
            secret = canonical_secret(secret)
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("Invalid port")
            if isinstance(dc_id, bool) or dc_id not in (1, 2, 3, 4, 5):
                raise ValueError("Invalid DC")
            timeout = max(1.0, min(30.0, float(timeout)))
            addresses = [validate_public_ip(pinned_ip)] if pinned_ip else await resolve_public_addresses(host, port)
            # Every resolved target is independent evidence. The scheduler can enqueue other IPs.
            result.resolved_ip = addresses[0]
            result.ip_family = "ipv6" if ipaddress.ip_address(addresses[0]).version == 6 else "ipv4"
            async with self._lock:
                try:
                    async with asyncio.timeout(timeout + 6):
                        await self._start()
                        request_id = uuid.uuid4().hex
                        job = {"request_id": request_id, "resolved_ip": result.resolved_ip,
                               "port": port, "secret": secret, "dc_id": dc_id, "timeout": timeout}
                        self._process.stdin.write(json.dumps(job).encode() + b"\n")
                        await self._process.stdin.drain()
                        raw = await self._process.stdout.readline()
                        response = json.loads(raw)
                        if response.get("request_id") != request_id:
                            raise RuntimeError("Invalid worker response")
                        result.outcome = str(response.get("outcome", "engine_error"))
                        result.error_code = response.get("error_code")
                        result.engine_version = self._metadata.get("engine_version", "unknown")
                        result.client_profile_id = self._metadata.get("client_profile_id", "tdlib-unknown")
                except BaseException:
                    await self._stop()
                    raise
            if result.outcome == "success":
                result.valid_until = (started + timedelta(seconds=300)).isoformat()
        except asyncio.CancelledError:
            raise
        except UnsafeTarget:
            result.outcome, result.level, result.error_code = "unsafe_target", "none", "non_public_destination"
        except (OSError, asyncio.TimeoutError):
            result.outcome, result.error_code = "engine_error", "worker_or_resolver_unavailable"
        except (ValueError, RuntimeError, TypeError):
            result.outcome, result.error_code = "engine_error", "invalid_request_or_worker"
        result.duration_ms = round((time.monotonic() - monotonic) * 1000)
        return result


_engine: ProbeEngine | None = None


def get_probe_engine() -> ProbeEngine:
    global _engine
    if _engine is None:
        _engine = ProbeEngine()
    return _engine
