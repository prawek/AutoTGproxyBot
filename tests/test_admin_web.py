from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import CookieJar, web
from aiohttp.test_utils import TestClient, TestServer

from app.db.schema import ProxyRepository
from app.main import performance_headers
from app.proxy import pipeline
from app.web import admin_routes as admin
from app.web.routes import setup_routes
from app.core.auth import make_session_token
from app.core.security import security_middleware


class AdminWebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.repo = MagicMock()
        for name, result in {
            "count_by_filter": 2, "delete_by_filter": 2, "delete_by_ids": 1,
            "purge_old_dead": 3, "cap_proxies": 4, "purge_old_feedback": 5,
            "get_db_size_mb": 12.5, "get_best": [], "stats": {},
        }.items():
            setattr(self.repo, name, AsyncMock(return_value=result))
        self.user_repo = MagicMock()
        self.user_repo.get_user = AsyncMock(return_value={"telegram_id": 42, "account_login": "test_user", "session_version": 0})
        self.user_repo.cleanup_expired = AsyncMock(return_value={"tokens": 6})
        self.app = web.Application(middlewares=[security_middleware, performance_headers])
        self.app.update(secret_key="test-secret", admin_password="test-password", proxy_repo=self.repo,
                        user_repo=self.user_repo, bot_username="test_bot", base_url="")
        setup_routes(self.app, admin_path="private-panel")
        self.client = TestClient(TestServer(self.app), cookie_jar=CookieJar(unsafe=True))
        await self.client.start_server()
        admin_token = admin._make_token("test-secret")
        self.app["admin_sessions"] = {hashlib.sha256(admin_token.encode()).hexdigest(): time.time()+3600}
        self.client.session.cookie_jar.update_cookies({"adm_s": admin_token, "tgsession": make_session_token(42, "test-secret")})
        self.cache = patch.object(pipeline, "CACHED_BEST_PROXIES", [
            {"id": "remove", "host": "EXAMPLE.com", "server": "EXAMPLE.com", "port": 443,
             "secret": "00112233445566778899aabbccddeeff", "generation": "faketls", "category": "RU", "is_alive": True},
            {"id": "keep", "host": "other.net", "server": "other.net", "port": 443,
             "secret": "00112233445566778899aabbccddeeff", "generation": "plain", "category": "EU", "is_alive": True},
        ])
        self.cache.start()

    async def asyncTearDown(self):
        self.cache.stop()
        await self.client.close()

    async def post(self, path, body=None):
        return await self.client.post("/private-panel/api/" + path, json=body)

    async def test_site_and_bot_share_primary_and_reserves(self):
        from app.bot import handlers
        now = datetime.now(timezone.utc)
        variants = []
        for name, ip in (("main-integration", "8.8.8.8"), ("reserve-integration", "1.1.1.1")):
            variants.append({"id":name, "host":ip, "port":443,
                "secret":"00112233445566778899aabbccddeeff", "observations":[{
                    "outcome":"success", "level":"auth_key", "network_key":"us-oregon", "country":"US",
                    "checked_at":now.isoformat(), "valid_until":(now+timedelta(minutes=5)).isoformat(),
                    "resolved_ip":ip, "ip_family":"ipv4", "client_profile_id":"test", "dc_id":2}]})
        pipeline.CACHED_BEST_PROXIES[:] = variants
        response = await self.client.post("/api/proxies/find-best", json={})
        self.assertEqual(response.status, 200)
        data = await response.json()
        result = handlers._selection(424242, handlers._DEFAULT_FILTER)
        self.assertEqual([data["proxy"]["id"]]+[p["id"] for p in data["reserves"]],
                         [p["id"] for p in result.proxies])
        self.assertEqual(data["status"], "verified")

    async def test_replace_rejects_malformed_skip_without_server_failure(self):
        response = await self.client.post("/api/proxies/replace", json={"proxy_id":"remove", "skip_ids":[{}]})
        self.assertEqual(response.status, 400)

    async def test_tools_require_admin_cookie(self):
        self.client.session.cookie_jar.clear()
        for path in ("purge", "proxies/count-filter", "proxies/delete-filter", "trigger-update", "maintenance/run"):
            with self.subTest(path=path):
                response = await self.post(path, {"days": 7})
                self.assertEqual(response.status, 401)
        self.repo.purge_old_dead.assert_not_awaited()

    async def test_filter_count_and_delete_use_same_normalized_filters(self):
        filters = {"host_contains": "  example.COM  ", "category": "RU", "alive_only": True}
        response = await self.post("proxies/count-filter", filters)
        self.assertEqual((response.status, (await response.json())["count"]), (200, 2))
        with patch.object(pipeline, "request_pipeline_update", return_value=True) as trigger:
            response = await self.post("proxies/delete-filter", filters)
        self.assertEqual(response.status, 200)
        self.assertTrue((await response.json())["update_queued"])
        self.assertEqual(self.repo.count_by_filter.await_args, self.repo.delete_by_filter.await_args)
        self.assertEqual(self.repo.delete_by_filter.await_args.kwargs["alive_only"], True)
        self.assertEqual([p["id"] for p in pipeline.CACHED_BEST_PROXIES], ["keep"])
        trigger.assert_called_once()

    async def test_dead_filter_does_not_remove_live_cache(self):
        response = await self.post("proxies/delete-filter", {"alive_only": "0"})
        self.assertEqual(response.status, 200)
        self.assertIs(self.repo.delete_by_filter.await_args.kwargs["alive_only"], False)
        self.assertEqual(len(pipeline.CACHED_BEST_PROXIES), 2)

    async def test_invalid_filters_cannot_broaden_deletion(self):
        for value in ({}, [], None, {"host_contains": 123}, {"category": "UNKNOWN"},
                      {"generation": "wrong"}, {"alive_only": "yes"}, {"host_contains": "%", "alive_only": []}):
            for endpoint in ("proxies/count-filter", "proxies/delete-filter"):
                with self.subTest(value=value, endpoint=endpoint):
                    response = await self.post(endpoint, value)
                    self.assertEqual(response.status, 400)
                    self.assertFalse((await response.json())["ok"])
        self.repo.delete_by_filter.assert_not_awaited()

    async def test_delete_ids_updates_public_cache(self):
        response = await self.post("proxies/delete", {"ids": ["remove", "remove"]})
        self.assertEqual(response.status, 200)
        self.repo.delete_by_ids.assert_awaited_once_with(["remove"])
        self.assertEqual([p["id"] for p in pipeline.CACHED_BEST_PROXIES], ["keep"])

    async def test_ids_must_be_a_list_of_nonempty_strings(self):
        for ids in ("remove", {}, [1], [""], []):
            with self.subTest(ids=ids):
                response = await self.post("proxies/delete", {"ids": ids})
                self.assertEqual(response.status, 400)
        self.repo.delete_by_ids.assert_not_awaited()

    async def test_purge_rejects_invalid_days_without_deleting(self):
        for days in (0, 366, None, "7", 1.5, True):
            with self.subTest(days=days):
                response = await self.post("purge", {"days": days})
                self.assertEqual(response.status, 400)
        self.repo.purge_old_dead.assert_not_awaited()

    async def test_purge_passes_valid_days_and_reports_count(self):
        response = await self.post("purge", {"days": 30})
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())["deleted"], 3)
        self.repo.purge_old_dead.assert_awaited_once_with(days=30)

    async def test_update_unavailable_and_queued(self):
        with patch.object(pipeline, "_force_update_event", None):
            response = await self.post("trigger-update")
        self.assertEqual(response.status, 503)
        event = asyncio.Event()
        with patch.object(pipeline, "_force_update_event", event):
            response = await self.post("trigger-update")
        self.assertEqual(response.status, 200)
        self.assertTrue(event.is_set())

    async def test_maintenance_returns_actual_counts_and_refreshes_cache(self):
        response = await self.post("maintenance/run")
        self.assertEqual(response.status, 200)
        data = await response.json()
        self.assertEqual(data["proxy_cleanup"], {"dead": 3, "cap": 4, "feedback": 5})
        self.assertEqual(data["user_cleanup"], {"tokens": 6})
        self.repo.purge_old_dead.assert_awaited_once_with(days=3)
        self.repo.cap_proxies.assert_awaited_once_with(3000)
        self.repo.purge_old_feedback.assert_awaited_once_with(days=30)
        self.assertEqual(pipeline.CACHED_BEST_PROXIES, [])

    async def test_maintenance_failure_is_json_with_partial_results(self):
        self.repo.cap_proxies.side_effect = RuntimeError("fixture failure")
        response = await self.post("maintenance/run")
        self.assertEqual(response.status, 500)
        data = await response.json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["proxy_cleanup"], {"dead": 3})
        self.assertEqual(data["user_cleanup"], {"tokens": 6})

    async def test_missing_database_is_not_success(self):
        # Repositories are mutable app state, just as a failed startup connection is.
        self.app["user_repo"] = self.app["proxy_repo"] = None
        for method, path in (("get", "maintenance/status"), ("post", "maintenance/run")):
            response = await getattr(self.client, method)("/private-panel/api/" + path)
            self.assertEqual(response.status, 503)
            self.assertFalse((await response.json())["ok"])

    async def test_maintenance_status_does_not_hide_errors(self):
        self.repo.get_db_size_mb.side_effect = RuntimeError("unavailable")
        response = await self.client.get("/private-panel/api/maintenance/status")
        self.assertEqual(response.status, 503)
        self.assertFalse((await response.json())["ok"])

    async def test_bad_users_pagination_is_400(self):
        response = await self.client.get("/private-panel/api/users?page=abc")
        self.assertEqual(response.status, 400)

    async def test_cross_site_mutations_are_blocked(self):
        response = await self.client.post("/private-panel/api/purge", json={"days":7}, headers={"Origin":"https://attacker.example"})
        self.assertEqual(response.status,403)
        self.repo.purge_old_dead.assert_not_awaited()

    async def test_public_registration_cannot_claim_known_telegram_account(self):
        self.user_repo.get_user_by_login=AsyncMock(return_value={"telegram_id":123,"password_hash":""})
        self.user_repo.register_existing_telegram_user=AsyncMock()
        self.user_repo.create_web_user=AsyncMock()
        response=await self.client.post("/api/auth/register",json={"login":"tg_owner","password":"password12345"})
        self.assertEqual(response.status,409)
        self.user_repo.register_existing_telegram_user.assert_not_awaited()
        self.user_repo.create_web_user.assert_not_awaited()

    async def test_deleted_accounts_and_changed_passwords_revoke_sessions(self):
        for user in (None,{"telegram_id":42,"account_login":"test_user","session_version":1}):
            self.user_repo.get_user.return_value=user
            response=await self.client.get("/api/proxies")
            self.assertEqual(response.status,401)

    async def test_catalog_check_cannot_scan_arbitrary_addresses(self):
        with patch("asyncio.open_connection",new_callable=AsyncMock) as connect:
            response=await self.client.post("/api/proxies/check",json={"proxies":[{"id":"not-in-catalog","server":"127.0.0.1","port":5432}]})
        self.assertEqual(response.status,400)
        connect.assert_not_awaited()

    async def test_admin_logout_revokes_replayed_cookie(self):
        token=next(cookie.value for cookie in self.client.session.cookie_jar if cookie.key=="adm_s")
        await self.client.post("/private-panel/logout")
        self.client.session.cookie_jar.update_cookies({"adm_s":token})
        response=await self.client.get("/private-panel/api/stats")
        self.assertEqual(response.status,401)

    async def test_public_mutations_reject_non_object_json(self):
        with patch("app.web.routes.get_uid_from_request", return_value=42):
            for path in ("auth/login", "auth/register", "account/password", "proxies/ban",
                         "proxies/feedback", "proxies/check", "proxies/replace"):
                for body in ([], None, 42, "invalid"):
                    with self.subTest(path=path, body=body):
                        response = await self.client.post("/api/" + path, json=body)
                        self.assertEqual(response.status, 400)

    async def test_public_proxy_limit_is_bounded(self):
        with patch("app.web.routes.get_uid_from_request", return_value=42):
            response = await self.client.get("/api/proxies?limit=-10")
        self.assertEqual(response.status, 200)
        self.assertEqual(len((await response.json())["proxies"]), 1)

    async def test_admin_login_and_logout_on_custom_path(self):
        self.client.session.cookie_jar.clear()
        response = await self.client.post("/private-panel/login", json={"password": "test-password"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.cookies["adm_s"]["path"], "/private-panel")
        self.assertTrue(response.cookies["adm_s"]["httponly"])
        self.assertEqual((await self.client.get("/private-panel/api/stats")).status, 200)
        await self.client.post("/private-panel/logout")
        self.assertEqual((await self.client.get("/private-panel/api/stats")).status, 401)

    async def test_login_rejects_non_object_body(self):
        response = await self.client.post("/private-panel/login", json=[])
        self.assertEqual(response.status, 400)

    async def test_pages_and_favicons_are_served(self):
        for path in ("/", "/login", "/register", "/account", "/connect_proxy", "/private-panel"):
            with self.subTest(path=path):
                response = await self.client.get(path)
                self.assertEqual(response.status, 200)
                html = await response.text()
                self.assertIn('rel="icon"', html)
                self.assertNotIn("__STATIC_VER__", html)
                self.assertNotIn("%%ADMIN_BASE%%", html)
                self.assertEqual(response.headers["Cache-Control"], "no-store")
        response = await self.client.get("/favicon.ico")
        self.assertEqual(response.status, 200)
        self.assertTrue((await response.read()).startswith(b"\x00\x00\x01\x00"))
        response = await self.client.get("/static/favicon.svg")
        self.assertEqual(response.status, 200)
        self.assertIn("svg", response.content_type)

    async def test_only_versioned_assets_are_cached_immutably(self):
        response = await self.client.get("/static/glass.css")
        self.assertEqual(response.headers["Cache-Control"], "no-cache")
        response = await self.client.get("/static/glass.css?v=test")
        self.assertIn("immutable", response.headers["Cache-Control"])


class AdminTokenTests(unittest.TestCase):
    def test_future_and_expired_tokens_are_invalid(self):
        for ts in (int(time.time()) + 3600, int(time.time()) - admin._ADM_MAX_AGE - 1):
            sig = hmac.new(b"test", f"adm:{ts}".encode(), hashlib.sha256).hexdigest()
            self.assertFalse(admin._verify_token(f"{ts}.{sig}", "test"))


class RepositoryFilterTests(unittest.IsolatedAsyncioTestCase):
    async def test_count_and_delete_treat_wildcards_as_literal_text(self):
        conn = MagicMock()
        conn.execute = AsyncMock(return_value="DELETE 0")
        conn.fetchval = AsyncMock(return_value=0)
        pool = MagicMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
        repo = ProxyRepository(pool)
        filters = dict(host_contains="EXAMPLE_%\\", alive_only=False)
        await repo.count_by_filter(**filters)
        await repo.delete_by_filter(**filters)
        count_args = conn.fetchval.await_args.args
        delete_args = conn.execute.await_args.args
        self.assertEqual(count_args[1:], delete_args[1:])
        self.assertEqual(count_args[1], "%example\\_\\%\\\\%")
        self.assertIn("is_alive = FALSE", delete_args[0])


if __name__ == "__main__":
    unittest.main()
