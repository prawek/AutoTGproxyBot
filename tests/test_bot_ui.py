"""Telegram navigation and message rendering, without contacting Telegram."""
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from app.bot import handlers


class BotInterfaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_account_callback_uses_the_person_who_clicked(self):
        callback = SimpleNamespace(
            from_user=SimpleNamespace(id=42),
            message=SimpleNamespace(from_user=SimpleNamespace(id=999)),
            answer=AsyncMock(),
        )
        with patch.object(handlers, "_send_account", AsyncMock()) as send:
            await handlers.cb_account(callback)
        send.assert_awaited_once_with(callback.message, 42)

    async def test_selection_contains_evidence_for_reserves_and_escaped_hosts(self):
        evidence = {"status": "verified", "level": "auth_key", "coverage_label": "Орегон <test>",
                    "checked_at": datetime.now(timezone.utc).isoformat(), "duration_ms": 42}
        proxy = {"id": "main", "host": "main.example.com", "port": 443,
                 "secret": "00" * 16, "evidence": evidence}
        reserve = {**proxy, "id": "reserve", "host": "backup<test>.example.com"}
        with patch.object(handlers, "_selection", return_value=SimpleNamespace(proxy=proxy, reserves=[reserve])), \
             patch.object(handlers, "_answer", AsyncMock()) as answer:
            await handlers._send_selection(SimpleNamespace(), 42, "aar")
        text = answer.await_args.args[1]
        self.assertIn("backup&lt;test&gt;.example.com", text)
        self.assertEqual(text.count("Орегон &lt;test&gt;"), 2)
        self.assertEqual(text.count("Время теста: 42 мс"), 2)
        self.assertLess(len(text), 4096)
        buttons = answer.await_args.kwargs["keyboard"].inline_keyboard
        self.assertEqual(buttons[0][0].style, "primary")
        self.assertTrue(buttons[0][0].url.startswith("tg://proxy?"))
        self.assertEqual(buttons[-1][0].callback_data, "home")

    async def test_new_user_credentials_stay_protected(self):
        message = SimpleNamespace(answer=AsyncMock())
        await handlers._send_credentials(message, "test<user>", "secret&password")
        call = message.answer.await_args
        self.assertTrue(call.kwargs["protect_content"])
        self.assertIn("test&lt;user&gt;", call.args[0])
        self.assertIn("secret&amp;password", call.args[0])

    async def test_empty_selection_keeps_the_selected_protocol(self):
        result = SimpleNamespace(proxy=None, reserves=[])
        with patch.object(handlers, "_selection", return_value=result), \
             patch.object(handlers.worker, "request_pipeline_update"), \
             patch.object(handlers, "_answer", AsyncMock()) as answer:
            await handlers._send_selection(SimpleNamespace(), 42, "afr")
        keyboard = answer.await_args.kwargs["keyboard"].inline_keyboard
        callbacks = {button.callback_data for row in keyboard for button in row}
        self.assertTrue({"fb:afr", "prx:afr", "pc:afr"}.issubset(callbacks))


if __name__ == "__main__":
    unittest.main()
