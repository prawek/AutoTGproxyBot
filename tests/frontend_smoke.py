"""Optional browser checks: pip install playwright; python tests/frontend_smoke.py.

Uses an installed Chrome and disposable repositories, with no production credentials.
Screenshots are written to build/ui-preview (ignored by git).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aiohttp import web
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright

from app.main import performance_headers
from app.core.security import security_middleware
from app.proxy import pipeline
from app.web.routes import setup_routes
from app.web.legal import DOCUMENTS, LegalProfile


async def main():
    logging.disable(logging.CRITICAL)
    artifacts = Path("build/ui-preview")
    artifacts.mkdir(parents=True, exist_ok=True)
    conn = MagicMock()
    conn.fetchrow = AsyncMock(return_value={"total_users": 1, "expired_auth_tokens": 2,
                                            "expired_pending_regs": 1, "old_proxy_feedback": 3})
    conn.fetch = AsyncMock(return_value=[])
    conn.fetchval = AsyncMock(return_value=0)
    user = {"telegram_id": 42, "account_login": "test_user", "username": "test_user", "first_name": "Тест"}
    users = MagicMock()
    users._pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    users._pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    users.get_user = AsyncMock(return_value=user)
    users.login_user = AsyncMock(return_value=user)
    users.table_sizes = AsyncMock(return_value=[{"table_name": "proxies", "size": "24 kB"}])
    users.cleanup_expired = AsyncMock(return_value={"auth_tokens": 2, "pending_regs": 1})
    now = datetime.now(timezone.utc)
    proxy = {"id": "test1234", "host": "proxy.example.com", "server": "proxy.example.com", "port": 443,
             "secret": "00112233445566778899aabbccddeeff", "generation": "plain", "category": "EU",
             "ping_ms": 42, "ping": 42, "transport_score": 85, "tspu_score": 85, "stability": 98,
             "is_alive": True, "rank": 1, "admin_recommended": True, "ru_feedback_total": 2,
             "observations": [{"outcome":"success", "level":"auth_key", "network_key":"us-oregon",
                 "checked_at":now.isoformat(), "valid_until":(now+timedelta(minutes=5)).isoformat(),
                 "resolved_ip":"8.8.8.8", "ip_family":"ipv4", "client_profile_id":"fixture", "dc_id":2,
                 "country":"US", "duration_ms":42}]}
    reserve = {**proxy, "id":"backup1234", "host":"backup.example.com", "server":"backup.example.com",
               "admin_recommended":False, "observations":[{**proxy["observations"][0], "resolved_ip":"1.1.1.1"}]}
    repo = MagicMock()
    for name, value in {"get_db_size_mb": 12.5, "stats": {"total": 1, "alive": 1, "dead": 0},
                        "count_by_filter": 1, "delete_by_filter": 1, "purge_old_dead": 3,
                        "cap_proxies": 4, "purge_old_feedback": 5, "get_best": [proxy],
                        "list_proxies": ([proxy], 1)}.items():
        setattr(repo, name, AsyncMock(return_value=value))
    app = web.Application(middlewares=[security_middleware, performance_headers])
    app.update(secret_key="browser-fixture", admin_password="fixture-only", proxy_repo=repo,
               user_repo=users, bot_username="test_bot", base_url="", legal_profile=LegalProfile())
    setup_routes(app, admin_path="test-admin")
    errors = []
    with patch.object(pipeline, "CACHED_BEST_PROXIES", [proxy, reserve]), patch.object(pipeline, "_force_update_event", asyncio.Event()):
        async with TestServer(app) as server, async_playwright() as playwright:
            browser = await playwright.chromium.launch(channel="chrome", headless=True)
            context = await browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            page = await context.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            base = str(server.make_url("/")).rstrip("/")
            checks = 0

            async def check_view(label):
                nonlocal checks
                await page.wait_for_load_state("networkidle")
                overflow = await page.evaluate("document.documentElement.scrollWidth > innerWidth + 1")
                assert not overflow, f"Page overflow: {label}"
                assert not errors, f"JS errors: {errors}"
                broken_images = await page.evaluate("Array.from(document.images).filter(i => i.complete && !i.naturalWidth).length")
                assert not broken_images, f"Broken image: {label}"
                checks += 1

            # Anonymous routes, both themes and mobile/desktop breakpoints.
            for theme in ("dark", "light"):
                for width in (320, 390, 768, 1440):
                    await page.set_viewport_size({"width": width, "height": 1000})
                    for route in ("/", "/login", "/register"):
                        await page.goto(base + route)
                        await page.evaluate("t => ProxyTheme.apply(t)", theme)
                        await page.locator(".landing-page, .auth-section").wait_for()
                        assert await page.locator('.footer-legal a').count() == len(DOCUMENTS)
                        if route == '/register':
                            notice = page.locator('#form-register .auth-legal-note')
                            assert await notice.locator('a[href="/legal/terms"][target="_blank"]').count() == 1
                            assert await notice.locator('a[href="/legal/privacy"][target="_blank"]').count() == 1
                        await check_view(f"{route} {theme} {width}")
                        if route == "/" and width in (390, 1440):
                            await page.screenshot(path=str(artifacts / f"landing-{theme}-{width}.png"))

            # Each footer link opens a real public document, in both themes and
            # at the same breakpoints as the app. No account or application JS is needed.
            for theme in ('dark', 'light'):
                for width in (320, 390, 768, 1440):
                    await page.set_viewport_size({'width':width, 'height':1000})
                    for key in DOCUMENTS:
                        response = await page.goto(base + '/legal/' + key)
                        assert response.status == 200
                        await page.locator('.legal-document h1').wait_for()
                        await page.evaluate('t => ProxyTheme.apply(t)', theme)
                        assert await page.locator('.legal-notice').count() == 1
                        assert await page.locator('.footer-legal a').count() == len(DOCUMENTS)
                        if width <= 390 and await page.locator('.legal-document table').count():
                            assert await page.locator('.legal-document tbody td:not([data-label])').count() == 0
                            assert await page.locator('.legal-document tbody tr').first.evaluate('el => getComputedStyle(el).display') == 'block'
                        await check_view(f'legal {key} {theme} {width}')
                        if key in ('privacy', 'cookies') and width == 390:
                            await page.screenshot(path=str(artifacts / f'legal-{key}-{theme}-390.png'), full_page=True)

            no_js_context = await browser.new_context(java_script_enabled=False, viewport={'width':390, 'height':1000})
            no_js_page = await no_js_context.new_page()
            legal_requests = []
            no_js_page.on('request', lambda request: legal_requests.append(request.url))
            await no_js_page.goto(base + '/legal/privacy')
            assert await no_js_page.locator('.legal-document h1').inner_text() == DOCUMENTS['privacy'][0]
            assert await no_js_page.locator('.legal-operator').count() > 0
            assert not any('/api/' in url for url in legal_requests)
            assert not await no_js_context.cookies()
            await no_js_context.close()
            checks += 1
            await page.set_viewport_size({'width':1440, 'height':1000})

            # One click must reach the instruction after the asynchronous render.
            async def check_instruction_link(target_page, route):
                await target_page.goto(base + route)
                await target_page.locator('.landing-page, .account-page').wait_for()
                await target_page.locator('a[href="/#how-it-works"]').click()
                await target_page.wait_for_function("""() => {
                    const section = document.getElementById('how-it-works');
                    const header = document.getElementById('site-header');
                    if (!section || !header) return false;
                    const top = section.getBoundingClientRect().top;
                    const edge = header.getBoundingClientRect().bottom;
                    return top >= edge - 2 && top <= edge + 35;
                }""", timeout=1500)
                assert await target_page.get_by_text('Нужна помощь?', exact=True).count() == 0

            await check_instruction_link(page, '/')
            checks += 1
            # localStorage exceptions must not prevent rendering.
            restricted = await browser.new_context()
            await restricted.add_init_script("Object.defineProperty(window, 'localStorage', {get() { throw new Error('blocked'); }});")
            blocked_page = await restricted.new_page()
            await blocked_page.goto(base + "/login")
            await blocked_page.locator("#login-login").wait_for()
            await blocked_page.locator("#theme-toggle").click()
            assert await blocked_page.locator("html").get_attribute("data-theme") == "dark"
            await blocked_page.locator("#theme-toggle").click()
            assert await blocked_page.locator("html").get_attribute("data-theme") == "light"
            await restricted.close()
            checks += 1

            response = await context.request.post(base + "/api/auth/login", data={"login": "test_user", "password": "fixture"})
            assert response.ok
            for theme in ("dark", "light"):
                for width in (320, 390, 768, 1440):
                    await page.set_viewport_size({"width": width, "height": 1000})
                    for route in ("/subscribe", "/account", "/connect_proxy"):
                        await page.goto(base + route)
                        await page.evaluate("t => ProxyTheme.apply(t)", theme)
                        await page.locator(".sub-page, .account-page, .proxy-page").wait_for()
                        assert await page.locator('#steps-wrap .steps-wrap').count() == 0
                        if route == '/account':
                            account_initial = await page.locator('.account-avatar-fallback').inner_text()
                            badge_initial = await page.locator('.badge-avatar').inner_text()
                            assert account_initial == badge_initial == 'T'
                            if width == 390 and theme == 'light':
                                await page.screenshot(path=str(artifacts / 'account-avatar-mobile.png'))
                        if route == "/connect_proxy":
                            await page.locator(".proxy-card").first.wait_for()
                            await page.locator("#find-btn").click()
                            await page.locator("#find-result .selection-heading").wait_for()
                            assert "Орегона" in await page.locator("#find-result").inner_text()
                            assert await page.locator('#find-result .connect-btn').count() == 2
                        await check_view(f"{route} {theme} {width}")
                        if route == "/connect_proxy" and width in (390, 1440):
                            await page.screenshot(path=str(artifacts / f"proxies-{theme}-{width}.png"), full_page=True)

            assert await page.evaluate("safePhotoUrl('')") == ''
            assert await page.evaluate("evidenceInfo({}).timing") == 'не измерен'
            await page.evaluate("document.querySelector('#find-result .proxy-card').dataset.validUntil = Date.now()-1000; expireRenderedEvidence()")
            assert await page.locator('#find-result .proxy-card .evidence-status').first.inner_text() == 'Подтверждение устарело'

            await check_instruction_link(page, '/account')
            checks += 1

            # The access transition is animated once and leaves no permanent steps
            # or empty reserved space, including after reloading the target page.
            animated_context = await browser.new_context(
                viewport={"width": 390, "height": 1000}, reduced_motion='no-preference',
                storage_state=await context.storage_state())
            access_page = await animated_context.new_page()
            access_page.on('pageerror', lambda e: errors.append(str(e)))
            await access_page.goto(base + '/subscribe')
            await access_page.locator('.sub-page').wait_for()
            assert await access_page.locator('#steps-wrap .steps-wrap').count() == 0
            await access_page.locator('.btn-sbp').click()
            await access_page.locator('.proxy-page').wait_for()
            steps = access_page.locator('#steps-wrap .steps-wrap')
            await steps.wait_for(state='visible', timeout=1500)
            assert await access_page.locator('#steps-wrap').evaluate('el => el.getAnimations({subtree:true}).length > 0')
            assert 'Вход' in await steps.inner_text() and 'Доступ' in await steps.inner_text()
            await access_page.screenshot(path=str(artifacts / 'access-progress-mobile.png'))
            await steps.wait_for(state='detached', timeout=7000)
            assert await access_page.locator('#steps-wrap').inner_html() == ''
            assert await access_page.locator('#steps-wrap').evaluate('el => el.getBoundingClientRect().height') == 0
            await access_page.reload()
            await access_page.locator('.proxy-page').wait_for()
            assert await access_page.locator('#steps-wrap .steps-wrap').count() == 0
            await animated_context.close()
            checks += 1

            response = await context.request.post(base + "/test-admin/login", data={"password": "fixture-only"})
            assert response.ok
            for theme in ("dark", "light"):
                for width in (320, 390, 768, 1440):
                    await page.set_viewport_size({"width": width, "height": 1000})
                    await page.goto(base + "/test-admin")
                    await page.locator("#app").wait_for(state="visible")
                    await page.evaluate("t => ProxyTheme.apply(t)", theme)
                    for tab in ("stats", "proxies", "users", "tools"):
                        await page.locator(f'[aria-controls="tab-{tab}"]').click()
                        await check_view(f"admin {tab} {theme} {width}")
                        if tab == "tools" and width in (390, 1440):
                            await page.screenshot(path=str(artifacts / f"admin-tools-{theme}-{width}.png"), full_page=True)

            # Exercise tool buttons against the real handlers and disposable fixtures.
            await page.locator("#df-host").fill("proxy.example.com")
            await page.locator("#df-count-btn").click()
            await page.locator("#df-result").filter(has_text="1").wait_for()
            await page.locator("#trigger-btn").click()
            await page.locator("#trigger-result").filter(has_text="очередь").wait_for()
            page.on("dialog", lambda dialog: dialog.accept())
            await page.locator("#purge-days").fill("")
            await page.locator("#purge-btn").click()
            await page.locator("#purge-result.error").wait_for()
            await page.locator("#purge-days").fill("30")
            await page.locator("#purge-btn").click()
            await page.locator("#purge-result").filter(has_text="3 записей").wait_for()
            await page.locator("#purge-result.success").wait_for()
            repo.purge_old_dead.assert_awaited_with(days=30)
            await page.locator("#maint-run-btn").click()
            await page.locator(".cleanup-summary").wait_for()
            assert "сверх лимита — 4" in await page.locator(".cleanup-summary").inner_text()
            await page.locator("#df-del-btn").click()
            await page.locator("#df-result").filter(has_text="Исключено 1").wait_for()
            repo.delete_by_filter.assert_awaited_once()
            assert not errors, errors
            await browser.close()
            print(f"PASS: {checks} layout/interaction checks, public legal documents without JS, footer links, instruction anchors, initial avatars, transient access animation, primary/reserve selection, proof expiry, restricted storage, 5 admin tools; no JS errors or broken images. Screenshots: {artifacts}")


if __name__ == "__main__":
    asyncio.run(main())
