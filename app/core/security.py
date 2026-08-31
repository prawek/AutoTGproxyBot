"""HTTP boundaries shared by public, account and administration endpoints."""
from __future__ import annotations

from collections import OrderedDict, deque
import ipaddress
import json
import logging
import time
from urllib.parse import urlsplit

from aiohttp import web

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, capacity: int = 10_000):
        self.capacity = capacity
        self.entries: OrderedDict[str, deque[float]] = OrderedDict()

    def allow(self, key: str, *, limit: int, window: float, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        bucket = self.entries.pop(key, deque())
        while bucket and bucket[0] <= current - window:
            bucket.popleft()
        allowed = len(bucket) < limit
        if allowed:
            bucket.append(current)
        self.entries[key] = bucket
        while len(self.entries) > self.capacity:
            self.entries.popitem(last=False)
        return allowed


def client_ip(request: web.Request) -> str:
    """Forwarded addresses count only behind an explicitly configured proxy."""
    hops = int(request.app.get("trusted_proxy_hops", 0))
    if hops:
        chain = request.headers.get("X-Forwarded-For", "").split(",")
        if len(chain) >= hops:
            try:
                return str(ipaddress.ip_address(chain[-hops].strip()))
            except ValueError:
                pass
    return request.remote or "unknown"


def request_is_https(request: web.Request) -> bool:
    if request.secure or str(request.app.get("base_url", "")).startswith("https://"):
        return True
    return bool(request.app.get("trusted_proxy_hops", 0)) and request.headers.get("X-Forwarded-Proto", "").split(",")[-1].strip().lower() == "https"


def rate_limit(request: web.Request, key: str, *, limit: int, window: int) -> None:
    limiter = request.app.get("request_limiter")
    if limiter is None:
        limiter = request.app["request_limiter"] = RateLimiter()
    if not limiter.allow(key, limit=limit, window=window):
        raise web.HTTPTooManyRequests(
            text=json.dumps({"ok": False, "error": "Слишком много запросов. Повторите позже."}, ensure_ascii=False),
            content_type="application/json", headers={"Retry-After": str(window)},
        )


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def same_origin(request: web.Request) -> bool:
    if request.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
        return False
    origin = request.headers.get("Origin")
    if origin is None:
        return True  # Non-browser clients must still authenticate their requests.
    actual = _origin(origin)
    if actual is None:
        return False
    expected = {_origin(f"{'https' if request_is_https(request) else 'http'}://{request.host}")}
    configured = str(request.app.get("base_url", "")).rstrip("/")
    if configured:
        expected.add(_origin(configured))
    expected.discard(None)
    return actual in expected


@web.middleware
async def security_middleware(request: web.Request, handler):
    is_webhook = bool(request.app.get("webhook_path")) and request.path == request.app["webhook_path"]
    try:
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not is_webhook and not same_origin(request):
            raise web.HTTPForbidden(text='{"ok":false,"error":"Недопустимый источник запроса."}', content_type="application/json")
        if request.path == "/logout" and not same_origin(request):
            raise web.HTTPForbidden()
        if request.path in {"/api/auth/login", "/api/auth/register"}:
            rate_limit(request, "auth-ip:" + client_ip(request), limit=30, window=60)
        response = await handler(request)
    except web.HTTPException as exc:
        response = exc
        if exc.status >= 400 and exc.content_type != "application/json":
            response = web.json_response({"ok": False, "error": exc.reason}, status=exc.status,
                                         headers={key: value for key, value in exc.headers.items() if key.lower() == "retry-after"})
    except Exception:
        # No SQL, secrets, exception repr or local filesystem paths in the response.
        logger.exception("Unhandled request failure: %s %s", request.method, request.path)
        response = web.json_response({"ok": False, "error": "Ошибка сервера. Повторите позже."}, status=500)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if response.content_type == "text/html":
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    if request.path.startswith("/api/") or "/api/" in request.path:
        response.headers["Cache-Control"] = "no-store"
    if str(request.app.get("base_url", "")).startswith("https://"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response
