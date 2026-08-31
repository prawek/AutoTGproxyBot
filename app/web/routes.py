"""Website API: authenticated snapshots, measured selection and local feedback."""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import datetime
import html
import hmac
import inspect
import json
import logging
from pathlib import Path
import re
import time
from urllib.parse import urlencode

from aiohttp import web

from app.core.auth import SESSION_COOKIE, clear_session_cookie, get_uid_from_request, read_session_data, set_session_cookie
from app.core.security import client_ip, rate_limit, request_is_https
from app.proxy import pipeline as worker
from app.proxy.catalog import available_proxies, feedback, filter_proxies as catalog_filter_proxies, secret_type

logger = logging.getLogger(__name__)
PROJECT_DIR = Path(__file__).resolve().parents[2]
_STATIC_VER = str(int(time.time()))
_LOGIN_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _json(data, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, dumps=lambda value: json.dumps(value, ensure_ascii=False, default=str),
                             headers={"Cache-Control": "no-store"})


async def _body(request: web.Request) -> dict:
    try:
        value = await request.json()
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError):
        raise web.HTTPBadRequest(text='{"ok":false,"error":"Ожидается JSON-объект."}', content_type="application/json")


def _text(body: dict, name: str, *, limit: int = 128, default: str = "") -> str:
    value = body.get(name, default)
    if not isinstance(value, str) or len(value) > limit:
        raise web.HTTPBadRequest(text='{"ok":false,"error":"Неверный формат поля запроса."}', content_type="application/json")
    return value


async def _authenticated_uid(request: web.Request) -> int | None:
    uid = get_uid_from_request(request)
    if uid is None:
        return None
    repo = request.app.get("user_repo")
    if repo is None:
        raise web.HTTPServiceUnavailable(text='{"ok":false,"error":"База аккаунтов временно недоступна."}', content_type="application/json")
    try:
        user = await repo.get_user(uid)
    except Exception:
        raise web.HTTPServiceUnavailable(text='{"ok":false,"error":"База аккаунтов временно недоступна."}', content_type="application/json")
    session = read_session_data(request.cookies.get(SESSION_COOKIE, ""), request.app.get("secret_key", ""))
    if not user or session is None or session["ver"] != int(user.get("session_version", 0)):
        return None
    request["user"] = user
    rate_limit(request, f"account-api:{uid}", limit=180, window=60)
    return uid


def _available_proxies(user_id: int | None = None) -> list[dict]:
    return available_proxies(worker.CACHED_BEST_PROXIES, worker.banned_proxies, user_id=user_id)


def _get_proxies_filtered(region="all", proxy_type="all", sort_by="recommended", limit=10, user_id=None):
    return catalog_filter_proxies(_available_proxies(user_id), region=region, proxy_type=proxy_type, sort_by=sort_by, limit=limit)


def _get_top10() -> list[dict]:
    return _get_proxies_filtered()


_secret_type = secret_type
_request_is_https = request_is_https


async def _snapshot(request: web.Request, uid: int) -> list[dict]:
    repo = request.app.get("proxy_repo")
    get_snapshot = getattr(repo, "get_selection_snapshot", None)
    if inspect.iscoroutinefunction(get_snapshot):
        try:
            rows = await get_snapshot(limit=300)
            return available_proxies(rows, worker.banned_proxies, user_id=uid)
        except Exception:
            logger.warning("Selection snapshot unavailable; using remaining valid in-memory evidence")
    return _available_proxies(uid)


def _selection_options(body: dict) -> dict:
    region = _text(body, "region", default="all").strip()
    kind = _text(body, "type", default="all").strip()
    sort = _text(body, "sort", default="recommended").strip()
    network = _text(body, "network", limit=80, default="unknown").strip()
    if region not in {"all", "RU", "EU"} or kind not in {"all", "FakeTLS", "RandPad", "Plain"}:
        raise web.HTTPBadRequest(text='{"ok":false,"error":"Неверный фильтр."}', content_type="application/json")
    if sort not in {"recommended", "freshness", "stability", "ping", "quality", "server_rating", "user_rating"}:
        raise web.HTTPBadRequest(text='{"ok":false,"error":"Неверная сортировка."}', content_type="application/json")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", network):
        raise web.HTTPBadRequest(text='{"ok":false,"error":"Неверный сетевой контекст."}', content_type="application/json")
    skip = body.get("skip_ids", [])
    if not isinstance(skip, list) or len(skip) > 100 or not all(isinstance(v, str) and _ID_RE.fullmatch(v) for v in skip):
        raise web.HTTPBadRequest(text='{"ok":false,"error":"Неверный список исключений."}', content_type="application/json")
    return dict(region=region, proxy_type=kind, sort_by=sort, network=network, skip_ids=set(skip),
                allow_unverified=body.get("allow_unverified") is True)


def _proxy_dict(proxy: dict) -> dict:
    server = str(proxy.get("server") or proxy.get("host") or "")
    port = int(proxy.get("port", 0))
    secret = str(proxy.get("secret", ""))
    keys = ("evidence", "evidence_tier", "verification", "verification_level", "verified", "status", "observations",
            "last_success_at", "checked_at", "valid_until", "fresh_until", "network", "network_key", "probe_country",
            "probe_region", "engine_name", "engine_version", "client_profile_id", "match_reasons", "reason_codes")
    result = {key: proxy[key] for key in keys if key in proxy}
    result.update(id=str(proxy.get("id", "")), server=server, port=port, secret=secret,
                  ping=proxy.get("ping_ms", proxy.get("ping")), type=secret_type(secret),
                  sni=proxy.get("sni_domain", ""), category=proxy.get("category", ""),
                  probe=proxy.get("probe_state", "unverified"), admin_recommended=bool(proxy.get("admin_recommended")),
                  tg_url="tg://proxy?" + urlencode({"server": server, "port": port, "secret": secret}))
    return result


async def index(request):
    page = (PROJECT_DIR / "templates/index.html").read_text(encoding="utf-8")
    page = page.replace("__BOT_USERNAME__", html.escape(str(request.app.get("bot_username", "")), quote=True))
    return web.Response(text=page.replace("__STATIC_VER__", _STATIC_VER), content_type="text/html", headers={"Cache-Control": "no-store"})


async def favicon(request):
    return web.FileResponse(PROJECT_DIR / "static/favicon.ico", headers={"Cache-Control": "public, max-age=86400"})


async def logout(request):
    response = web.HTTPFound("/")
    clear_session_cookie(response)
    return response


async def api_config(request):
    return _json({"bot_username": request.app.get("bot_username", ""), "base_url": request.app.get("base_url", ""),
                  "probe_region": request.app.get("probe_region", "us-oregon"), "access_price_rub": 0,
                  "selection_version": 3, "feedback_scope": "personal", "verification_required": "auth_key"})


async def healthz(request):
    return _json({"ok": True, "probe_region": request.app.get("probe_region", "us-oregon"),
                  "cached_proxies": len(worker.CACHED_BEST_PROXIES)})


async def api_auth_login(request):
    repo = request.app.get("user_repo")
    if repo is None:
        return _json({"ok": False, "error": "База данных недоступна."}, 503)
    body = await _body(request)
    login = _text(body, "login", limit=32).strip().lower()
    password = _text(body, "password", limit=1024)
    if not _LOGIN_RE.fullmatch(login) or not password:
        return _json({"ok": False, "error": "Введите корректный логин и пароль."}, 400)
    rate_limit(request, "login-name:" + login, limit=8, window=60)
    rate_limit(request, "login-ip:" + client_ip(request), limit=30, window=60)
    user = await repo.login_user(login, password)
    if not user:
        return _json({"ok": False, "error": "Неверный логин или пароль."}, 401)
    response = _json({"ok": True})
    set_session_cookie(response, int(user["telegram_id"]), request.app.get("secret_key", ""),
                       secure=request_is_https(request), session_version=int(user.get("session_version", 0)))
    return response


async def api_auth_register(request):
    repo = request.app.get("user_repo")
    if repo is None:
        return _json({"ok": False, "error": "База данных недоступна."}, 503)
    body = await _body(request)
    login = _text(body, "login", limit=32).strip().lower()
    password = _text(body, "password", limit=1024)
    if not _LOGIN_RE.fullmatch(login) or not 10 <= len(password) <= 1024:
        return _json({"ok": False, "error": "Логин: 3–32 латинских символа, цифры или _. Пароль: от 10 символов."}, 400)
    rate_limit(request, "register-ip:" + client_ip(request), limit=5, window=600)
    try:
        # A public form cannot prove ownership of an existing Telegram identity.
        if await repo.get_user_by_login(login):
            return _json({"ok": False, "error": "Логин уже занят. Войдите в аккаунт."}, 409)
        user = await repo.create_web_user(login, password)
    except ValueError:
        return _json({"ok": False, "error": "Логин уже занят. Выберите другой."}, 409)
    response = _json({"ok": True, "login": login})
    set_session_cookie(response, int(user["telegram_id"]), request.app.get("secret_key", ""),
                       secure=request_is_https(request), session_version=int(user.get("session_version", 0)))
    return response


async def api_auth_reg_poll(request):
    return _json({"ok": False, "error": "Этот способ регистрации больше не поддерживается."}, 410)


async def api_me(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"authenticated": False})
    user = request["user"]
    photo = str(user.get("photo_url") or "")
    if not photo.startswith("https://"):
        photo = ""
    return _json({"authenticated": True, "account_login": user.get("account_login", ""),
                  "first_name": user.get("first_name", ""), "username": user.get("username", ""),
                  "photo_url": photo, "access_price_rub": 0})


async def api_account_password(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, 401)
    body = await _body(request)
    old = _text(body, "old_password", limit=1024)
    new = _text(body, "new_password", limit=1024)
    if not old or len(new) < 10 or old == new:
        return _json({"ok": False, "error": "Введите текущий пароль и новый пароль длиной от 10 символов."}, 400)
    rate_limit(request, f"change-password:{uid}", limit=5, window=300)
    user = request["user"]
    repo = request.app["user_repo"]
    login = user["account_login"]
    if not await repo.login_user(login, old):
        return _json({"ok": False, "error": "Текущий пароль указан неверно."}, 401)
    await repo.set_credentials(uid, login, new)
    refreshed = await repo.get_user(uid)
    response = _json({"ok": True})
    set_session_cookie(response, uid, request.app.get("secret_key", ""), secure=request_is_https(request),
                       session_version=int(refreshed.get("session_version", 0)))
    return response


async def _choose(request, uid, body, limit=3):
    from app.proxy.selection_service import select_proxies
    options = _selection_options(body)
    rows = await _snapshot(request, uid)
    return select_proxies(rows, limit=limit, **options)


async def api_find_best_proxy(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, 401)
    body = await _body(request) if request.method == "POST" else dict(request.query)
    rate_limit(request, f"selection:{uid}", limit=20, window=60)
    selection = await _choose(request, uid, body)
    primary = selection.proxy
    if primary:
        return _json({"ok": True, "status": selection.status, "proxy": _proxy_dict(primary),
                      "reserves": [_proxy_dict(p) for p in selection.reserves], "reasons": selection.reasons,
                      "profile_summary": "Подбор по измерениям; сеть пользователя не определяется по типу устройства."})
    queued = worker.request_pipeline_update() if request.method == "POST" else False
    return _json({"ok": False, "status": "pending" if queued else selection.status,
                  "error": "Нет свежего протокольного подтверждения по выбранным условиям.",
                  "reserves": [], "update_queued": queued, "retry_after": 15})


async def api_proxies(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, 401)
    try:
        limit = max(1, min(200, int(request.query.get("limit", "10"))))
    except ValueError:
        return _json({"ok": False, "error": "Неверный limit."}, 400)
    from app.proxy.selection_service import rank_candidates
    options = _selection_options(dict(request.query))
    options.pop("allow_unverified", None)
    rows = rank_candidates(await _snapshot(request, uid), **options)[:limit]
    elapsed = time.time() - worker.LAST_CYCLE_AT if worker.LAST_CYCLE_AT else 0
    return _json({"ok": True, "status": "available" if rows else "empty", "proxies": [_proxy_dict(p) for p in rows],
                  "total": len(rows), "next_update_in": max(15, int(worker.WORKER_INTERVAL - elapsed)),
                  "worker_interval": worker.WORKER_INTERVAL, "selection_version": 3})


async def _record_ru_feedback(request, uid, proxy_id, works, **unused):
    # Optional feedback only changes this user's exclusions; it is not a probe.
    if not any(p.get("id") == proxy_id for p in worker.CACHED_BEST_PROXIES):
        return False
    if works:
        feedback.report_success(proxy_id, uid)
    else:
        feedback.report_failure(proxy_id, uid)
    return True


async def api_proxy_feedback(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, 401)
    body = await _body(request)
    proxy_id = _text(body, "id", limit=64)
    outcome = _text(body, "outcome", limit=10)
    if not _ID_RE.fullmatch(proxy_id) or outcome not in {"works", "fails"}:
        return _json({"ok": False, "error": "Неверный результат."}, 400)
    rate_limit(request, f"feedback:{uid}", limit=30, window=60)
    saved = await _record_ru_feedback(request, uid, proxy_id, outcome == "works")
    return _json({"ok": saved, "scope": "personal"}, 200 if saved else 404)


async def api_proxy_ban(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, 401)
    body = await _body(request)
    ids = body.get("ids", [body["id"]] if "id" in body else [])
    if not isinstance(ids, list) or not 1 <= len(ids) <= 10 or not all(isinstance(pid, str) and _ID_RE.fullmatch(pid) for pid in ids):
        return _json({"ok": False, "error": "Неверный список ID."}, 400)
    rate_limit(request, f"feedback:{uid}", limit=30, window=60)
    count = 0
    for pid in set(ids):
        count += int(await _record_ru_feedback(request, uid, pid, False))
    return _json({"ok": True, "reported": count, "globally_hidden": 0, "scope": "personal"})


async def api_proxies_check(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, 401)
    body = await _body(request)
    candidates = body.get("proxies", [])
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 30 or not all(isinstance(p, dict) and isinstance(p.get("id"), str) for p in candidates):
        return _json({"ok": False, "error": "Передайте от 1 до 30 известных ID прокси."}, 400)
    rows = await _snapshot(request, uid)
    catalog = {p["id"]: p for p in rows}
    ids = [p["id"] for p in candidates]
    if any(pid not in catalog for pid in ids):
        return _json({"ok": False, "error": "Неизвестный ID прокси."}, 400)
    # Never open a user-supplied host/port: this endpoint is not a port scanner.
    rate_limit(request, f"recheck:{uid}", limit=5, window=60)
    queued = worker.request_pipeline_update()
    return _json({"ok": True, "update_queued": queued, "scope": "catalog",
                  "results": {pid: {"ok": None, "status": "queued" if queued else "unavailable", "ms": None} for pid in ids}})


async def api_proxies_replace(request):
    uid = await _authenticated_uid(request)
    if uid is None:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, 401)
    body = await _body(request)
    proxy_id = _text(body, "proxy_id", limit=64)
    if not _ID_RE.fullmatch(proxy_id):
        return _json({"ok": False, "error": "Укажите ID прокси."}, 400)
    if body.get("failed") is True:
        await _record_ru_feedback(request, uid, proxy_id, False)
    options = _selection_options(body)  # Validate elements before set/deduplication.
    body["skip_ids"] = list(options["skip_ids"] | {proxy_id})
    rate_limit(request, f"selection:{uid}", limit=20, window=60)
    selection = await _choose(request, uid, body)
    rows = ([selection.proxy] if selection.proxy else []) + list(selection.reserves)
    return _json({"ok": bool(rows), "status": selection.status, "proxies": [_proxy_dict(p) for p in rows],
                  "scope": "personal", "reserves": [_proxy_dict(p) for p in selection.reserves]})


async def telegram_webhook(request):
    expected = str(request.app.get("tg_webhook_secret", ""))
    received = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not expected or not hmac.compare_digest(received.encode(), expected.encode()):
        return _json({"ok": False}, 403)
    bot, dp = request.app.get("bot"), request.app.get("dp")
    if bot is None or dp is None:
        return _json({"ok": False}, 503)
    body = await _body(request)
    try:
        from aiogram.types import Update
        update = Update.model_validate(body)
    except ValueError:
        return _json({"ok": False}, 400)
    # One webhook worker per update, including duplicate concurrent deliveries.
    pending = request.app.setdefault("webhook_pending", set())
    done = request.app.setdefault("webhook_done", OrderedDict())
    if update.update_id in done:
        return _json({"ok": True})
    if update.update_id in pending or len(pending) >= 100:
        return _json({"ok": False}, 503)
    pending.add(update.update_id)
    try:
        await asyncio.wait_for(dp.feed_update(bot=bot, update=update), timeout=45)
        done[update.update_id] = time.monotonic()
        while len(done) > 5000:
            done.popitem(last=False)
    except Exception:
        logger.error("Telegram update processing failed")
        return _json({"ok": False}, 503)
    finally:
        pending.discard(update.update_id)
    return _json({"ok": True})


def setup_routes(app, webhook_path="", admin_path="admin"):
    from app.web.admin_routes import setup_admin_routes
    from app.web.probe_routes import setup_probe_routes
    from app.web.legal import setup_legal_routes
    setup_legal_routes(app, static_version=_STATIC_VER)
    setup_admin_routes(app, admin_path=admin_path)
    setup_probe_routes(app)
    for path in ("/", "/login", "/register", "/app", "/account", "/subscribe", "/connect_proxy"):
        app.router.add_get(path, index)
        if path != "/":
            app.router.add_get(path + "/", index)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/logout", logout)
    app.router.add_post("/logout", logout)
    for path, handler in (("/api/config", api_config), ("/healthz", healthz), ("/api/me", api_me),
                          ("/api/proxies", api_proxies), ("/api/proxies/find-best", api_find_best_proxy),
                          ("/api/auth/reg/poll", api_auth_reg_poll)):
        app.router.add_get(path, handler)
    for path, handler in (("/api/auth/login", api_auth_login), ("/api/auth/register", api_auth_register),
                          ("/api/account/password", api_account_password), ("/api/proxies/find-best", api_find_best_proxy),
                          ("/api/proxies/ban", api_proxy_ban), ("/api/proxies/feedback", api_proxy_feedback),
                          ("/api/proxies/check", api_proxies_check), ("/api/proxies/replace", api_proxies_replace)):
        app.router.add_post(path, handler)
    if webhook_path:
        app.router.add_post(webhook_path, telegram_webhook)
    app.router.add_static("/static/", path=str(PROJECT_DIR / "static"), name="static", follow_symlinks=False)
