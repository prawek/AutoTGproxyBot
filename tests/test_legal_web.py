"""Public document access and safe rendering of operator-provided details."""
from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from app.core.security import security_middleware
from app.main import performance_headers
from app.web.legal import DOCUMENTS, LegalProfile, render_document
from app.web.routes import setup_routes


def complete_profile(**overrides):
    return replace(LegalProfile(
        operator_name="Тестовый владелец", postal_address="Тестовый адрес для обращений",
        privacy_email="privacy@example.com", database_country="Россия",
        processors="Тестовые сведения о привлечённых лицах",
        log_retention="Тестовый срок журналов", backup_retention="Тестовый срок копий"), **overrides)


class LegalWebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = web.Application(middlewares=[security_middleware, performance_headers])
        self.app.update(legal_profile=LegalProfile(), secret_key="legal-test-only", bot_username="test_bot")
        setup_routes(self.app, admin_path="legal-test-admin")
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()

    async def test_documents_are_public_complete_html_without_app_or_cookie(self):
        for key, (title, _) in DOCUMENTS.items():
            for suffix in ("", "/"):
                with self.subTest(document=key, suffix=suffix):
                    response = await self.client.get("/legal/" + key + suffix)
                    text = await response.text()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.content_type, "text/html")
                    self.assertIn("<h1>" + title + "</h1>", text)
                    self.assertNotRegex(text, r"__[A-Z_]+__")
                    self.assertNotIn("/static/app.js", text)
                    self.assertNotIn("Set-Cookie", response.headers)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    for linked_key in DOCUMENTS:
                        self.assertIn('href="/legal/' + linked_key + '"', text)

    async def test_missing_details_are_visible_and_foreign_processing_is_not_hidden(self):
        response = await self.client.get("/legal/privacy")
        text = await response.text()
        self.assertIn('class="legal-notice"', text)
        self.assertIn("остаётся проектом", text)
        self.assertIn("Орего", text)
        self.assertIn("США", text)
        self.assertIn("страна базы аккаунтов", text)

    async def test_footer_links_are_present_on_auth_and_account_pages(self):
        for path in ("/", "/login", "/register", "/account", "/connect_proxy"):
            with self.subTest(path=path):
                response = await self.client.get(path)
                self.assertEqual(response.status, 200)
                footer = (await response.text()).split('<footer class="site-footer"', 1)[1]
                for key in DOCUMENTS:
                    self.assertIn('href="/legal/' + key + '"', footer)

    async def test_unknown_document_and_traversal_are_not_served(self):
        for path in ("/legal/unknown", "/legal/.env", "/legal/%2e%2e%2f.env", "/legal/privacy/extra"):
            with self.subTest(path=path):
                response = await self.client.get(path)
                self.assertEqual(response.status, 404)


class LegalRenderingTests(unittest.TestCase):
    def test_configured_profile_removes_only_the_missing_information_notice(self):
        page = render_document("privacy", complete_profile(), "test-static")
        self.assertNotIn('class="legal-notice"', page)
        self.assertIn("Тестовый владелец", page)
        self.assertIn("privacy@example.com", page)
        self.assertIn("США", page)  # A Russian database does not change the server location.

    def test_operator_fields_are_escaped_and_not_interpreted_as_template_tokens(self):
        page = render_document("privacy", complete_profile(
            operator_name='<img src=x onerror="alert(1)"> __STATIC_VER__',
            postal_address="<script>alert('address')</script>",
            processors="<script>alert('processor')</script>"), "safe-static")
        self.assertIn("&lt;img", page)
        self.assertIn("__STATIC_VER__", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("<script>alert", page)

    def test_invalid_contact_cannot_inject_email_headers(self):
        with patch.dict("os.environ", {"LEGAL_PRIVACY_EMAIL": "privacy@example.com\nBcc:attacker@example.com"}):
            with self.assertRaises(ValueError):
                LegalProfile.from_env()


if __name__ == "__main__":
    unittest.main()
