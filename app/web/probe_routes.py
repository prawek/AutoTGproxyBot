"""Scoped outbound probe API. There is deliberately no enrollment endpoint."""
from __future__ import annotations

import json
from functools import wraps

from aiohttp import web
from app.core.security import client_ip, rate_limit


def _json(data: dict, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, headers={"Cache-Control": "no-store"},
                             dumps=lambda value: json.dumps(value, ensure_ascii=False, default=str))


def _agent_required(handler):
    @wraps(handler)
    async def wrapped(request: web.Request):
        repo = request.app.get("probe_repo")
        if repo is None:
            return _json({"ok": False, "error": "Probe storage is unavailable"}, 503)
        rate_limit(request, "probe-ip:" + client_ip(request), limit=120, window=60)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or len(auth) > 270:
            return _json({"ok": False, "error": "Unauthorized"}, 401)
        agent = await repo.authenticate(auth[7:])
        if agent is None:
            return _json({"ok": False, "error": "Unauthorized"}, 401)
        if request.content_length is not None and request.content_length > 16384:
            return _json({"ok": False, "error": "Request too large"}, 413)
        try:
            body_raw = await request.read()
            if len(body_raw) > 16384:
                return _json({"ok": False, "error": "Request too large"}, 413)
            body = json.loads(body_raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("JSON object required")
            return await handler(request, repo, agent, body)
        except (ValueError, TypeError) as exc:
            return _json({"ok": False, "error": str(exc)[:160]}, 400)
    return wrapped


@_agent_required
async def heartbeat(request, repo, agent, body):
    return _json(await repo.heartbeat(agent, body))


@_agent_required
async def claim(request, repo, agent, body):
    limit = body.get("limit", 2)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 2:
        raise ValueError("limit must be 1 or 2")
    jobs = await repo.claim(agent, limit=limit)
    return _json({"ok": True, "jobs": jobs, "poll_after": 15})


@_agent_required
async def results(request, repo, agent, body):
    result = await repo.complete(agent, body)
    # Native checker results should become visible without waiting for harvest.
    proxy_repo = request.app.get("proxy_repo")
    if proxy_repo is not None and not result.get("duplicate"):
        from app.proxy import pipeline
        pipeline.request_pipeline_update()
    return _json(result)


def setup_probe_routes(app: web.Application) -> None:
    app.router.add_post("/api/probes/heartbeat", heartbeat)
    app.router.add_post("/api/probes/claim", claim)
    app.router.add_post("/api/probes/results", results)
