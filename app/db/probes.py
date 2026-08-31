"""Durable, bounded probe queue and immutable network observations.

Only administrator-provisioned agents can claim work. A result belongs to one
lease attempt; retries cannot turn an old result into a fresh confirmation.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_VARIANT = re.compile(r"^[0-9a-f]{32}$")
OUTCOMES = frozenset({"success", "connect_timeout", "connection_refused", "reset", "dns_error",
    "proxy_handshake_failed", "auth_key_failed", "invalid_response", "unsupported_checker",
    "engine_error", "unsafe_target", "agent_unhealthy", "control_failed", "cancelled"})

DDL = """
CREATE TABLE IF NOT EXISTS probe_agents (
    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, enabled BOOLEAN NOT NULL DEFAULT TRUE,
    country TEXT NOT NULL DEFAULT 'unknown', network_key TEXT NOT NULL DEFAULT 'unknown',
    access_type TEXT NOT NULL DEFAULT 'unknown', region TEXT NOT NULL DEFAULT '', asn TEXT NOT NULL DEFAULT '',
    network_epoch TEXT NOT NULL DEFAULT '', healthy BOOLEAN NOT NULL DEFAULT FALSE,
    capabilities JSONB NOT NULL DEFAULT '{}', last_seen_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS probe_jobs (
    id TEXT PRIMARY KEY, variant_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES probe_agents(id),
    dc_id INTEGER NOT NULL DEFAULT 2 CHECK(dc_id BETWEEN 1 AND 5),
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','leased','completed','expired','cancelled')),
    priority INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
    leased_at TIMESTAMPTZ, lease_until TIMESTAMPTZ, lease_token TEXT, attempt_id TEXT,
    network_epoch TEXT NOT NULL DEFAULT '', completed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_probe_jobs_active
    ON probe_jobs(variant_id, agent_id, dc_id) WHERE status IN ('queued','leased');
CREATE INDEX IF NOT EXISTS idx_probe_jobs_claim ON probe_jobs(agent_id,status,priority DESC,created_at);
CREATE TABLE IF NOT EXISTS probe_observations (
    attempt_id TEXT PRIMARY KEY, job_id TEXT, variant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
    network_key TEXT NOT NULL, network_epoch TEXT NOT NULL DEFAULT '',
    measured_at TIMESTAMPTZ NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ, outcome TEXT NOT NULL, level TEXT NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_probe_observations_latest
    ON probe_observations(variant_id,network_key,measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_probe_observations_retention ON probe_observations(received_at);
"""


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_agents_config(raw: str) -> list[dict[str, str]]:
    if not raw.strip():
        return []
    try:
        entries = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("PROBE_AGENTS_JSON must contain a JSON array") from exc
    if not isinstance(entries, list) or len(entries) > 20:
        raise ValueError("At most 20 explicitly provisioned probe agents are supported")
    result, ids, tokens = [], set(), set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid probe agent configuration")
        agent_id, token = entry.get("id"), entry.get("token")
        if not isinstance(agent_id, str) or not _ID.fullmatch(agent_id) or agent_id in ids:
            raise ValueError("Probe agent IDs must be unique and contain only letters, digits, _ or -")
        if not isinstance(token, str) or not 32 <= len(token) <= 256 or token in tokens:
            raise ValueError("Probe tokens must be unique and at least 32 characters long")
        network = entry.get("network_key", "unknown")
        country = str(entry.get("country", "unknown")).lower()
        access = entry.get("access_type", "unknown")
        if not isinstance(network, str) or not _ID.fullmatch(network):
            raise ValueError("Invalid configured network_key")
        if country != "unknown" and not re.fullmatch(r"[a-z]{2}", country):
            raise ValueError("Country must be an ISO two-letter label or unknown")
        if access not in {"home", "mobile", "datacenter", "unknown"}:
            raise ValueError("Invalid agent access_type")
        ids.add(agent_id); tokens.add(token)
        result.append({"id": agent_id, "token_hash": token_digest(token), "country": country,
                       "network_key": network, "access_type": access,
                       "region": str(entry.get("region", ""))[:64], "asn": str(entry.get("asn", ""))[:32]})
    return result


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and len(value) <= 64:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("Invalid measurement time")
    if parsed.tzinfo is None:
        raise ValueError("Measurement time must include timezone")
    return parsed.astimezone(timezone.utc)


def validate_observation(data: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """Validate facts, never infer a protocol success from an open TCP port."""
    if not isinstance(data, dict):
        raise ValueError("Observation must be an object")
    now = now or datetime.now(timezone.utc)
    outcome = data.get("outcome")
    level = data.get("level", "none")
    if outcome not in OUTCOMES or level not in {"none", "tcp", "faketls", "mtproto", "auth_key", "sustained"}:
        raise ValueError("Unsupported observation outcome or level")
    if outcome == "success" and level not in {"auth_key", "sustained"}:
        raise ValueError("A successful probe requires an authenticated Telegram exchange")
    measured = _dt(data.get("checked_at"))
    if measured > now + timedelta(seconds=15) or measured < now - timedelta(minutes=5):
        raise ValueError("Measurement time is outside the accepted window")
    duration = data.get("duration_ms", 0)
    if duration is None and outcome != "success":
        duration = 0
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not 0 <= duration <= 60000:
        raise ValueError("Invalid measurement duration")
    dc = data.get("dc_id", 2)
    if isinstance(dc, bool) or not isinstance(dc, int) or not 1 <= dc <= 5:
        raise ValueError("Invalid Telegram DC")
    value = {"outcome": outcome, "level": level, "checked_at": measured.isoformat(),
             "valid_until": (measured + timedelta(minutes=5)).isoformat() if outcome == "success" else None,
             "duration_ms": round(duration), "dc_id": dc}
    for key, limit in (("engine_name", 32), ("engine_version", 128), ("client_profile_id", 128),
                       ("error_code", 128), ("resolved_ip", 64), ("ip_family", 16)):
        item = data.get(key)
        # ProbeResult serializes absent optional diagnostics as null. They are
        # unknown facts, not invalid requests (notably error_code on success).
        if item is None:
            item = ""
        if not isinstance(item, (str, int)) or len(str(item)) > limit:
            raise ValueError("Invalid observation field: " + key)
        value[key] = str(item)
    if value["resolved_ip"]:
        from app.proxy.network import validate_public_ip
        value["resolved_ip"] = validate_public_ip(value["resolved_ip"])
        expected_family = "ipv6" if ipaddress.ip_address(value["resolved_ip"]).version == 6 else "ipv4"
        if value["ip_family"] and value["ip_family"] != expected_family:
            raise ValueError("IP family does not match the actual peer address")
        value["ip_family"] = expected_family
    elif value["ip_family"]:
        raise ValueError("IP family requires the actual peer address")
    if outcome == "success" and not value["resolved_ip"]:
        raise ValueError("Successful observations require the actual public peer address")
    return value


class ProbeRepository:
    def __init__(self, pool: Any):
        self._pool = pool

    async def migrate(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(DDL)

    async def configure_agents_from_env(self, raw: str | None = None) -> None:
        """The environment is the provisioning authority; removing a node revokes it."""
        agents = parse_agents_config(os.getenv("PROBE_AGENTS_JSON", "") if raw is None else raw)
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("UPDATE probe_agents SET enabled=FALSE")
                for agent in agents:
                    await conn.execute("""INSERT INTO probe_agents(id,token_hash,country,network_key,access_type,region,asn)
                        VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET
                        token_hash=EXCLUDED.token_hash,country=EXCLUDED.country,network_key=EXCLUDED.network_key,
                        access_type=EXCLUDED.access_type,region=EXCLUDED.region,asn=EXCLUDED.asn,enabled=TRUE,
                        healthy=FALSE,last_seen_at=NULL""",
                        agent["id"], agent["token_hash"], agent["country"], agent["network_key"],
                        agent["access_type"], agent["region"], agent["asn"])
                await conn.execute("""UPDATE probe_jobs SET status='cancelled'
                    WHERE status IN ('queued','leased') AND agent_id IN (SELECT id FROM probe_agents WHERE NOT enabled)""")

    async def authenticate(self, token: str) -> dict | None:
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM probe_agents WHERE token_hash=$1 AND enabled", token_digest(token))
        return dict(row) if row else None

    async def heartbeat(self, agent: dict, body: Any) -> dict:
        if not isinstance(body, dict):
            raise ValueError("Heartbeat must be an object")
        epoch = body.get("network_epoch", "")
        if not isinstance(epoch, str) or not _ID.fullmatch(epoch):
            raise ValueError("A valid network_epoch is required")
        capabilities = {"engine_name": str(body.get("engine_name", ""))[:32],
                        "engine_version": str(body.get("engine_version", ""))[:128],
                        "client_profile_id": str(body.get("client_profile_id", ""))[:128]}
        healthy = body.get("healthy") is True
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.fetchrow("SELECT id FROM probe_agents WHERE id=$1 AND enabled FOR UPDATE", agent["id"])
                await conn.execute("""UPDATE probe_agents SET network_epoch=$2, healthy=$3,
                    capabilities=$4::jsonb,last_seen_at=NOW() WHERE id=$1 AND enabled""",
                    agent["id"], epoch, healthy, json.dumps(capabilities))
                # Work measured on the previous route must neither be accepted
                # nor occupy this route's two active lease slots.
                await conn.execute("""UPDATE probe_jobs SET status='cancelled'
                    WHERE agent_id=$1 AND status='leased' AND network_epoch<>$2""", agent["id"], epoch)
        return {"ok": True, "network_key": agent["network_key"], "country": agent["country"],
                "access_type": agent["access_type"], "poll_after": 15}

    async def enqueue(self, variant_id: str, agent_id: str, *, dc_id: int = 2, priority: int = 0) -> bool:
        if not _VARIANT.fullmatch(variant_id) or not _ID.fullmatch(agent_id) or dc_id not in range(1, 6):
            raise ValueError("Invalid probe task")
        async with self._pool.acquire() as conn:
            row = await conn.fetchval("""INSERT INTO probe_jobs(id,variant_id,agent_id,dc_id,priority,expires_at)
                SELECT $1,$2,$3,$4,$5,NOW()+INTERVAL '5 minutes'
                WHERE EXISTS(SELECT 1 FROM proxies WHERE id=$2 AND NOT blocked)
                  AND EXISTS(SELECT 1 FROM probe_agents WHERE id=$3 AND enabled)
                ON CONFLICT DO NOTHING RETURNING id""", uuid.uuid4().hex, variant_id, agent_id, dc_id,
                max(0, min(int(priority), 100)))
        return row is not None

    async def claim(self, agent: dict, *, limit: int = 2) -> list[dict]:
        limit = max(1, min(2, limit))
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow("SELECT * FROM probe_agents WHERE id=$1 AND enabled FOR UPDATE", agent["id"])
                if not current or not current["healthy"] or not current["last_seen_at"] or current["last_seen_at"] < datetime.now(timezone.utc)-timedelta(seconds=90):
                    return []
                await conn.execute("""UPDATE probe_jobs SET status='expired'
                    WHERE agent_id=$1 AND status IN ('queued','leased') AND expires_at<=NOW()""", agent["id"])
                await conn.execute("""UPDATE probe_jobs SET status='queued',lease_token=NULL
                    WHERE agent_id=$1 AND status='leased' AND lease_until<=NOW() AND attempts<3 AND expires_at>NOW()""", agent["id"])
                active = await conn.fetchval("SELECT COUNT(*) FROM probe_jobs WHERE agent_id=$1 AND status='leased' AND lease_until>NOW()", agent["id"])
                slots = max(0, min(limit, 2-int(active or 0)))
                if not slots:
                    return []
                rows = await conn.fetch("""SELECT j.id,j.variant_id,j.dc_id,p.host,p.port,p.secret
                    FROM probe_jobs j JOIN proxies p ON p.id=j.variant_id
                    WHERE j.agent_id=$1 AND j.status='queued' AND j.expires_at>NOW() AND NOT p.blocked
                    ORDER BY j.priority DESC,j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT $2""", agent["id"], slots)
                jobs = []
                for row in rows:
                    attempt, lease = uuid.uuid4().hex, secrets.token_urlsafe(32)
                    leased = await conn.fetchrow("""UPDATE probe_jobs SET status='leased',attempts=attempts+1,
                        leased_at=NOW(),lease_until=LEAST(expires_at,NOW()+INTERVAL '90 seconds'),
                        attempt_id=$2,lease_token=$3,network_epoch=$4 WHERE id=$1
                        RETURNING lease_until""", row["id"], attempt, lease, current["network_epoch"])
                    jobs.append({**dict(row), "attempt_id": attempt, "lease_token": lease,
                                 "network_epoch": current["network_epoch"], "network_key": current["network_key"],
                                 "expires_at": leased["lease_until"].isoformat(), "timeout": 12, "type": "mtproto_check"})
                return jobs

    async def complete(self, agent: dict, body: Any) -> dict:
        if not isinstance(body, dict):
            raise ValueError("Result must be an object")
        job_id, attempt, token = (body.get(k) for k in ("job_id", "attempt_id", "lease_token"))
        if not all(isinstance(v, str) and 1 <= len(v) <= 128 for v in (job_id, attempt, token)):
            raise ValueError("Invalid result lease")
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                job = await conn.fetchrow("SELECT * FROM probe_jobs WHERE id=$1 AND agent_id=$2 FOR UPDATE", job_id, agent["id"])
                if not job or job["attempt_id"] != attempt or not secrets.compare_digest(job["lease_token"] or "", token):
                    raise ValueError("Unknown or replaced lease")
                if job["status"] == "completed":
                    return {"ok": True, "duplicate": True}
                now = datetime.now(timezone.utc)
                if job["status"] != "leased" or job["lease_until"] <= now:
                    raise ValueError("Lease expired")
                current = await conn.fetchrow("SELECT * FROM probe_agents WHERE id=$1 AND enabled", agent["id"])
                if not current or not current["healthy"] or current["network_epoch"] != job["network_epoch"]:
                    raise ValueError("Network changed during measurement")
                result = validate_observation(body.get("result"), now=now)
                measured = _dt(result["checked_at"])
                if measured < job["leased_at"]-timedelta(seconds=5) or result["dc_id"] != job["dc_id"]:
                    raise ValueError("Measurement does not belong to this assignment")
                result.update(variant_id=job["variant_id"], agent_id=agent["id"], network_epoch=job["network_epoch"],
                    network_key=current["network_key"], country=current["country"], access_type=current["access_type"],
                    region=current["region"], asn=current["asn"])
                result["agent_healthy"] = True
                await self._insert(conn, attempt, job_id, result)
                await conn.execute("UPDATE probe_jobs SET status='completed',completed_at=NOW() WHERE id=$1", job_id)
        return {"ok": True, "duplicate": False}

    @staticmethod
    async def _insert(conn, attempt_id: str, job_id: str | None, result: dict) -> None:
        measured = _dt(result["checked_at"])
        valid = _dt(result["valid_until"]) if result.get("valid_until") else None
        await conn.execute("""INSERT INTO probe_observations
            (attempt_id,job_id,variant_id,agent_id,network_key,network_epoch,measured_at,valid_until,outcome,level,payload)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb) ON CONFLICT(attempt_id) DO NOTHING""",
            attempt_id, job_id, result["variant_id"], result.get("agent_id", "oregon"), result.get("network_key", "us-oregon"),
            result.get("network_epoch", ""), measured, valid, result["outcome"], result["level"], json.dumps(result, default=str))

    async def record_local_observation(self, data: dict) -> None:
        variant = data.get("variant_id", data.get("id", ""))
        if not isinstance(variant, str) or not _VARIANT.fullmatch(variant):
            raise ValueError("Invalid variant ID")
        normalized = validate_observation(data)
        normalized.update(variant_id=variant, agent_id="oregon", network_key=data.get("network_key", "us-oregon"),
                          network_epoch="local", country="us", access_type="datacenter")
        async with self._pool.acquire() as conn:
            await self._insert(conn, uuid.uuid4().hex, None, normalized)

    async def latest_observations(self, variant_ids: list[str]) -> dict[str, list[dict]]:
        if not variant_ids:
            return {}
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""SELECT variant_id,payload FROM (
                SELECT o.variant_id,o.payload,o.measured_at,ROW_NUMBER() OVER (
                    PARTITION BY o.variant_id,o.agent_id,o.network_epoch,o.payload->>'resolved_ip',o.payload->>'ip_family',o.payload->>'client_profile_id',o.payload->>'dc_id'
                    ORDER BY o.measured_at DESC) AS sequence_no FROM probe_observations o
                LEFT JOIN probe_agents a ON a.id=o.agent_id
                WHERE o.variant_id=ANY($1::text[]) AND o.measured_at>NOW()-INTERVAL '1 day'
                  AND ((o.job_id IS NULL AND o.agent_id='oregon') OR
                       (a.enabled AND a.network_epoch=o.network_epoch AND a.network_key=o.network_key
                        AND a.country=o.payload->>'country' AND a.access_type=o.payload->>'access_type'
                        AND a.region=o.payload->>'region' AND a.asn=o.payload->>'asn'))
                ) recent WHERE sequence_no<=8 ORDER BY measured_at DESC LIMIT 10000""", variant_ids[:1000])
        result: dict[str, list[dict]] = {}
        for row in rows:
            payload = row["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            result.setdefault(row["variant_id"], []).append(dict(payload))
        return result

    async def schedule_once(self, *, limit_per_agent: int = 20) -> int:
        """Refresh a bounded active pool; leave a small rotating discovery share."""
        async with self._pool.acquire() as conn:
            agents = await conn.fetch("SELECT id FROM probe_agents WHERE enabled AND healthy AND last_seen_at>NOW()-INTERVAL '90 seconds'")
            total = 0
            for agent in agents:
                await conn.execute("UPDATE probe_jobs SET status='expired' WHERE agent_id=$1 AND status IN ('queued','leased') AND expires_at<=NOW()", agent["id"])
                rows = await conn.fetch("""SELECT p.id FROM proxies p WHERE length(p.id)=32 AND NOT p.blocked
                    AND p.last_seen_at>NOW()-INTERVAL '1 day'
                    AND NOT EXISTS(SELECT 1 FROM probe_jobs j WHERE j.agent_id=$1 AND j.variant_id=p.id AND j.status IN ('queued','leased'))
                    AND NOT EXISTS(SELECT 1 FROM probe_observations o JOIN probe_agents a ON a.id=o.agent_id
                        WHERE o.agent_id=$1 AND o.variant_id=p.id AND o.measured_at>NOW()-INTERVAL '3 minutes'
                          AND a.network_epoch=o.network_epoch AND a.network_key=o.network_key
                          AND a.country=o.payload->>'country' AND a.access_type=o.payload->>'access_type'
                          AND a.region=o.payload->>'region' AND a.asn=o.payload->>'asn')
                    ORDER BY p.admin_recommended DESC,p.checked_at DESC NULLS LAST,p.rank,p.last_seen_at DESC LIMIT $2""",
                    agent["id"], max(1, min(limit_per_agent, 50)))
                for row in rows:
                    inserted = await conn.fetchval("""INSERT INTO probe_jobs(id,variant_id,agent_id,dc_id,priority,expires_at)
                        VALUES($1,$2,$3,2,0,NOW()+INTERVAL '5 minutes')
                        ON CONFLICT DO NOTHING RETURNING id""", uuid.uuid4().hex, row["id"], agent["id"])
                    total += int(inserted is not None)
        return total

    async def cleanup(self, days: int = 7) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM probe_observations WHERE received_at<NOW()-INTERVAL '1 day' * $1", max(1, min(days, 30)))
            await conn.execute("DELETE FROM probe_jobs WHERE created_at<NOW()-INTERVAL '1 day' AND status IN ('completed','expired','cancelled')")

    async def status(self) -> dict:
        async with self._pool.acquire() as conn:
            agents = await conn.fetch("SELECT id,country,network_key,access_type,region,asn,healthy,last_seen_at,capabilities FROM probe_agents WHERE enabled ORDER BY id")
            jobs = await conn.fetch("SELECT status,COUNT(*) AS count FROM probe_jobs GROUP BY status")
        return {"agents": [dict(r) for r in agents], "jobs": {r["status"]: r["count"] for r in jobs}}


async def probe_scheduler(repo: ProbeRepository) -> None:
    cycle = 0
    while True:
        try:
            await repo.schedule_once()
            cycle += 1
            if cycle % 60 == 0:
                await repo.cleanup()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Probe scheduler failed")
        await asyncio.sleep(15)
