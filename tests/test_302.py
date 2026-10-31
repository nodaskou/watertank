"""Telegram Detect chat ID: mocked Bot API, no token in logs or errors."""
import io
import json
import logging
import os
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pingmonitor as pm

TOKEN = "123456789:AAHdummyTokenForTestsOnly000000000"


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class API:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, req, timeout=20):
        method = req.full_url.rsplit("/", 1)[-1].split("?", 1)[0]
        self.calls.append(method)
        spec = self.routes[method]
        if isinstance(spec, Exception):
            raise spec
        status, payload = spec
        body = json.dumps(payload).encode()
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(body))
        return _Body(body)


class _Body:
    def __init__(self, body):
        self._body = body

    def read(self, n=None):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def updates(*rows):
    return {"ok": True, "result": list(rows)}


class TelegramDetect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pm.DB_PATH = os.path.join(self.tmp.name, "t.db")
        pm.DATA_DIR = self.tmp.name
        pm.SNAP_DIR = os.path.join(self.tmp.name, "snap")
        os.makedirs(pm.SNAP_DIR, exist_ok=True)
        pm.init_db()
        pm.app.secret_key = "test-secret"
        self.logs = Capture()
        self.logs.setLevel(logging.DEBUG)
        logging.getLogger("pingmonitor").addHandler(self.logs)
        logging.getLogger("pingmonitor").setLevel(logging.DEBUG)

    def tearDown(self):
        logging.getLogger("pingmonitor").removeHandler(self.logs)
        self.tmp.cleanup()

    def assert_token_hidden(self, *blobs):
        for blob in list(self.logs.messages) + list(blobs):
            self.assertNotIn(TOKEN, str(blob))
            self.assertNotIn("AAHdummyToken", str(blob))

    def test_chats_newest_first_and_deduped(self):
        rows = pm.chats_from_updates([
            {"update_id": 1, "message": {"date": 10, "chat": {"id": 42, "type": "private", "first_name": "Old", "username": "old"}}},
            {"update_id": 2, "message": {"date": 50, "chat": {"id": -100555, "type": "supergroup", "title": "Office"}}},
            {"update_id": 3, "message": {"date": 30, "chat": {"id": 42, "type": "private", "first_name": "Maria", "username": "maria"}}},
            {"update_id": 4, "channel_post": {"date": 40, "chat": {"id": -100777, "type": "channel", "title": "Alerts"}}},
            {"update_id": 5, "my_chat_member": {"date": 20, "chat": {"id": -88, "type": "group", "title": "Warehouse"}}},
        ])
        self.assertEqual([r["id"] for r in rows], [-100555, -100777, 42, -88])
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(by_id[42]["label"], "Maria (@maria)")
        self.assertEqual(by_id[42]["kind"], "private")
        self.assertEqual(by_id[-100555]["label"], "Office")
        self.assertEqual(by_id[-100555]["kind"], "supergroup")
        self.assertEqual(by_id[-100777]["label"], "Alerts")
        self.assertEqual(by_id[-88]["label"], "Warehouse")
        self.assertEqual(len(rows), 4)

    def test_username_only_private_chat(self):
        rows = pm.chats_from_updates([
            {"update_id": 1, "message": {"date": 1, "chat": {"id": 7, "type": "private", "username": "noda"}}},
        ])
        self.assertEqual(rows[0]["label"], "@noda")

    def test_invalid_token_401_is_friendly_and_unlogged(self):
        api = API({"getWebhookInfo": (401, {"ok": False, "error_code": 401, "description": "Unauthorized"})})
        with self.assertRaises(pm.TelegramError) as caught:
            pm.telegram_call(TOKEN, "getWebhookInfo", urlopen=api)
        self.assertIn("401", str(caught.exception))
        self.assertIn("BotFather", str(caught.exception))
        self.assert_token_hidden(caught.exception)

    def test_detect_lists_chats_without_calling_delete(self):
        api = API({
            "getWebhookInfo": (200, {"ok": True, "result": {"url": ""}}),
            "getUpdates": (200, updates(
                {"update_id": 2, "message": {"date": 9, "chat": {"id": -1005, "type": "supergroup", "title": "Site <b>"}}},
                {"update_id": 1, "message": {"date": 1, "chat": {"id": 9, "type": "private", "first_name": "ww", "username": "ww"}}},
            )),
        })
        real = pm.telegram_call
        pm.telegram_call = lambda token, method, params=None, urlopen=None: real(token, method, params, api)
        try:
            with pm.app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["role"] = "viewer"
                    sess["csrf"] = "tok"
                denied = client.post("/settings/telegram/detect", data={"csrf": "tok", "telegram_token": TOKEN})
                self.assertEqual(denied.status_code, 302)
                self.assertIn("/login", denied.headers["Location"])
                with client.session_transaction() as sess:
                    sess["role"] = "admin"
                    sess["csrf"] = "tok"
                bad = client.post("/settings/telegram/detect", data={"csrf": "no", "telegram_token": TOKEN})
                self.assertEqual(bad.status_code, 400)
                ok = client.post("/settings/telegram/detect", data={"csrf": "tok", "telegram_token": TOKEN})
                self.assertEqual(ok.status_code, 302)
                page = client.get("/settings")
        finally:
            pm.telegram_call = real
        self.assertEqual(api.calls, ["getWebhookInfo", "getUpdates"])
        html = page.get_data(as_text=True)
        self.assertIn("Detect chat ID", html)
        self.assertIn("Send test message", html)
        self.assertIn("ww (@ww)", html)
        self.assertIn("-1005", html)
        self.assertIn("Use this chat", html)
        self.assertIn("data-chat=\"-1005\"", html)
        self.assertIn("Site &lt;b&gt;", html)
        self.assertNotIn("Remove webhook", html)
        self.assert_token_hidden(html, ok.get_data(as_text=True))
        with pm.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["role"] = "admin"
                sess["csrf"] = "tok"
                sess["tg_lookup"] = {"webhook": False, "chats": [], "empty": True}
            empty = client.get("/settings").get_data(as_text=True)
        self.assertIn(pm._TG_EMPTY, empty)
        self.assertIn(pm._TG_EMPTY_EL, empty)

    def test_webhook_blocks_getupdates_until_explicit_delete(self):
        api = API({
            "getWebhookInfo": (200, {"ok": True, "result": {"url": "https://example.invalid/hook"}}),
            "getUpdates": (200, updates()),
            "deleteWebhook": (200, {"ok": True, "result": True}),
        })
        real = pm.telegram_call
        pm.telegram_call = lambda token, method, params=None, urlopen=None: real(TOKEN, method, params, api)
        try:
            with pm.app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["role"] = "admin"
                    sess["csrf"] = "tok"
                client.post("/settings/telegram/detect", data={"csrf": "tok"})
                page = client.get("/settings").get_data(as_text=True)
                self.assertIn("getUpdates cannot read messages", page)
                self.assertIn("Remove webhook", page)
                self.assertNotIn(pm._TG_EMPTY, page)
                self.assertEqual(api.calls, ["getWebhookInfo"])
                pm.set_settings(telegram_token=TOKEN)
                client.post("/settings/telegram/webhook", data={"csrf": "tok"})
        finally:
            pm.telegram_call = real
        self.assertEqual(api.calls, ["getWebhookInfo", "deleteWebhook"])
        self.assert_token_hidden(page)

    def test_saved_token_used_when_field_blank(self):
        pm.set_settings(telegram_token=TOKEN)
        seen = {}

        def fake(token, urlopen=None):
            seen["token"] = token
            return {"webhook": False, "chats": []}

        real = pm.discover_telegram_chats
        pm.discover_telegram_chats = fake
        try:
            with pm.app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["role"] = "admin"
                    sess["csrf"] = "tok"
                client.post("/settings/telegram/detect", data={"csrf": "tok", "telegram_token": ""})
                page = client.get("/settings").get_data(as_text=True)
        finally:
            pm.discover_telegram_chats = real
        self.assertEqual(seen["token"], TOKEN)
        self.assertIn(pm._TG_EMPTY, page)
        self.assertIn(pm._TG_EMPTY_EL, page)

    def test_send_test_message_uses_chat_id(self):
        sent = {}

        def fake_send(s, text, photo_path=None):
            sent["chat"] = s["telegram_chat_id"]
            sent["token"] = s["telegram_token"]
            sent["text"] = text

        real = pm.send_telegram
        pm.send_telegram = fake_send
        try:
            with pm.app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["role"] = "admin"
                    sess["csrf"] = "tok"
                resp = client.post("/settings/test/telegram", data={
                    "csrf": "tok", "telegram_token": TOKEN, "telegram_chat_id": "-1005", "telegram_enabled": "1",
                }, follow_redirects=True)
        finally:
            pm.send_telegram = real
        html = resp.get_data(as_text=True)
        self.assertIn("Test telegram sent successfully", html)
        self.assertEqual(sent["chat"], "-1005")
        self.assertEqual(sent["token"], TOKEN)
        self.assertNotIn(TOKEN, html)
        self.assertEqual(pm.get_settings()["telegram_chat_id"], "-1005")

    def test_send_failure_hides_token(self):
        pm.MOCK_TELEGRAM = False

        def boom(url, data, headers, timeout=15):
            raise urllib.error.HTTPError(
                "https://api.telegram.org/bot" + TOKEN + "/sendMessage", 401, "Unauthorized", {}, io.BytesIO(b"")
            )

        real_post = pm._http_post
        real_mock = pm.MOCK_TELEGRAM
        pm._http_post = boom
        try:
            with self.assertRaises(RuntimeError) as caught:
                pm.send_telegram({"telegram_token": TOKEN, "telegram_chat_id": "9"}, "hello")
        finally:
            pm._http_post = real_post
            pm.MOCK_TELEGRAM = real_mock
        self.assertIn("401", str(caught.exception))
        self.assert_token_hidden(caught.exception)


if __name__ == "__main__":
    unittest.main()
