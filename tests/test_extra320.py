"""Client branding and the extra 3.2.0 checks. Payloads are local fixtures, not live devices."""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import branding
import extraops
import pingmonitor as pm


class Brand(unittest.TestCase):
    def test_formats_and_svg_script_removed(self):
        kind, body = branding.prepare(b"\x89PNG\r\n\x1a\n" + b"x" * 20)
        self.assertEqual(kind, "png")
        self.assertTrue(body.startswith(b"\x89PNG"))
        self.assertEqual(branding.sniff(b"\xff\xd8\xff" + b"j" * 10), "jpeg")
        self.assertEqual(branding.sniff(b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"x"), "webp")
        with self.assertRaises(branding.LogoError):
            branding.sanitize_svg(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect width="10" height="10"/></svg>')
        safe = branding.sanitize_svg(b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="10" height="10"/></svg>')
        self.assertNotIn(b"onload", safe.lower())
        self.assertIn(b"<rect", safe)
        with self.assertRaises(branding.LogoError):
            branding.prepare(b"<html></html>")
        self.assertEqual(branding.adopt_client_name("", "Hotel"), "Hotel")
        self.assertEqual(branding.adopt_client_name("Kept", "Hotel"), "Kept")
        with self.assertRaises(branding.LogoError):
            branding.prepare(b"\x89PNG\r\n\x1a\n" + b"x" * (branding.MAX_LOGO + 2))

    def test_store_and_remove(self):
        import tempfile
        folder = tempfile.mkdtemp()
        name = branding.store(folder, b"\x89PNG\r\n\x1a\nrest")
        self.assertTrue(branding.find(folder, name))
        branding.remove(folder)
        self.assertIsNone(branding.find(folder, name))


class ExtraChecks(unittest.TestCase):
    def test_kiosk_camera_router_fiber_voip_power_rota(self):
        self.assertTrue(extraops.kiosk_matches("abc", "abc"))
        self.assertFalse(extraops.kiosk_matches("abc", "abd"))
        self.assertFalse(extraops.kiosk_matches("", "abc"))
        self.assertIsNone(extraops.parse_hik_tamper("<config><enabled>true</enabled></config>"))
        self.assertTrue(extraops.parse_hik_tamper("<TamperStatus>true</TamperStatus>"))
        self.assertIsNone(extraops.clock_drift_seconds(None, datetime(2026, 11, 20, 12, 0, 0)))
        drift = extraops.clock_drift_seconds(datetime(2026, 11, 20, 12, 0, 30), datetime(2026, 11, 20, 12, 0, 0))
        self.assertEqual(drift, 30)
        self.assertIsNone(extraops.recording_gap_minutes(None, 0, 600))
        self.assertEqual(extraops.recording_gap_minutes([(0, 300)], 0, 600), 5)
        res = extraops.parse_routeros_resource({"cpu-load": 4, "free-memory": 50, "total-memory": 100, "voltage": 24})
        self.assertEqual(res["cpu"], 4)
        self.assertEqual(res["mem_pct"], 50.0)
        self.assertEqual(extraops.parse_default_gateway([{"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "active": True}]), "1.1.1.1")
        self.assertEqual(extraops.route_event("1.1.1.1", "2.2.2.2"), "changed")
        self.assertIsNone(extraops.route_event("", "2.2.2.2"))
        optics = extraops.parse_sfp([{"name": "sfp1", "sfp-rx-power": -22.0, "sfp-tx-power": -3}])
        self.assertEqual(extraops.sfp_level(optics[0]["rx"], -20, -28), "warning")
        self.assertEqual(extraops.sfp_level(optics[0]["rx"], -23, -28), "ok")
        self.assertEqual(extraops.sfp_level(None, -20, -28), "unknown")
        self.assertIn("<polyline", extraops.sparkline([-10, -12, -11]))
        masked = extraops.mask_secrets("set password=hunter2\nset name=office")
        self.assertNotIn("hunter2", masked)
        self.assertIn("office", masked)
        self.assertIn("***", extraops.config_change("password=a\n", "password=b\n"))
        peers = extraops.parse_sip_peers("trunk 1.2.3.4 OK\n")
        self.assertTrue(peers[0]["online"])
        self.assertIsNone(extraops.sip_code_online(None))
        self.assertTrue(extraops.sip_code_online(200))
        pbx = extraops.parse_pbx_api({"trunks": [{"name": "pstn", "status": "Registered"}], "extensions": []})
        self.assertTrue(pbx["trunks"][0]["online"])
        self.assertIsNone(extraops.parse_pbx_api({"ok": True}))
        self.assertTrue(extraops.power_url("shelly-gen1", 0, False).endswith("turn=off"))
        self.assertNotIn("password", extraops.power_url("tasmota", 1, True))
        when = datetime(2026, 11, 16, 10, 0)  # Monday
        self.assertEqual(when.weekday(), 0)
        duty = extraops.on_duty([{"name": "Ada", "chat_id": "55", "day": 0, "start": "09:00", "end": "17:00"}], when)
        self.assertEqual(duty["chat_id"], "55")
        self.assertIsNone(extraops.on_duty([{"name": "Ada", "chat_id": "55", "day": 1, "start": "09:00", "end": "17:00"}], when))


class ClearMapKiosk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._db = pm.DB_PATH
        self._data = pm.DATA_DIR
        self._snap = pm.SNAP_DIR
        pm.DB_PATH = os.path.join(self.tmp.name, "t.db")
        pm.DATA_DIR = self.tmp.name
        pm.SNAP_DIR = os.path.join(self.tmp.name, "snap")
        os.makedirs(pm.SNAP_DIR, exist_ok=True)
        pm.init_db()
        pm.set_settings(site_name="Kept", fail_threshold=1, repeat_min=0, quiet_start="", quiet_end="",
                        maintenance_until=0, kiosk_token="tok", ui_lang="en")
        self._ping = {}
        self._real = pm.get_pinger

        def fake(_method):
            def ping(host, _timeout):
                ok = self._ping.get(host, False)
                return (ok, 1.0 if ok else None)
            return {"fn": ping, "name": "mock"}

        pm.get_pinger = fake
        pm.app.secret_key = "t"

    def tearDown(self):
        pm.get_pinger = self._real
        pm.DB_PATH = self._db
        pm.DATA_DIR = self._data
        pm.SNAP_DIR = self._snap
        self.tmp.cleanup()

    def _pool(self):
        class Pool:
            def map(self, fn, items):
                return list(map(fn, items))
        return Pool()

    def test_clear_alarms_rearms_once_and_keeps_history(self):
        now = time.time()
        with pm.db() as c:
            c.execute("""INSERT INTO hosts(name, host, grp, device_type, enabled, created_at, state, alerted_down, last_alert, down_since, repeat_min)
                         VALUES('Cam','10.1.1.5','Shop','generic',1,?,?,1,?,?,-1)""",
                      (now, "down", now - 100, now - 100))
            c.execute("INSERT INTO results(host_id, ts, ok, ms) VALUES(1, ?, 0, NULL)", (now,))
            c.execute("""INSERT INTO events(ts, source, kind, severity, title, message)
                         VALUES(?, 'ping', 'host_down', 'critical', 'History kept', 'old')""", (now - 50,))
            c.execute("""INSERT INTO sia_accounts(account, name, state, offline_alerted, last_text)
                         VALUES('123456','Panel','alarm',0,'Burglary')""")
            c.execute("""INSERT INTO sia_accounts(account, name, state, offline_alerted, last_ts)
                         VALUES('999999','Quiet','offline',1,?)""", (now - 9999,))
        before = None
        with pm.db() as c:
            before = c.execute("SELECT COUNT(*) AS n FROM results").fetchone()["n"]
        pm.clear_all_alarms("203.0.113.8")
        with pm.db() as c:
            host = c.execute("SELECT alarm_rearm, alerted_down, last_alert, repeat_min, state FROM hosts").fetchone()
            msgs = [r["message"] for r in c.execute("SELECT message FROM events ORDER BY id")]
            ack = c.execute("SELECT ack_at, ack_by FROM sia_accounts WHERE account='123456'").fetchone()
            offline = c.execute("SELECT offline_alerted, state FROM sia_accounts WHERE account='999999'").fetchone()
            kept = c.execute("SELECT COUNT(*) AS n FROM events WHERE title='History kept'").fetchone()["n"]
            results = c.execute("SELECT COUNT(*) AS n FROM results").fetchone()["n"]
        self.assertEqual(host["alarm_rearm"], 1)
        self.assertEqual(host["alerted_down"], 0)
        self.assertEqual(host["last_alert"], 0)
        self.assertEqual(host["repeat_min"], -1)
        self.assertEqual(host["state"], "down")
        self.assertEqual(pm.get_settings()["site_name"], "Kept")
        self.assertEqual(results, before)
        self.assertEqual(kept, 1)
        self.assertEqual(msgs.count("Alarms cleared by admin from 203.0.113.8"), 1)
        self.assertGreater(ack["ack_at"], 0)
        self.assertEqual(ack["ack_by"], "admin")
        self.assertEqual(offline["offline_alerted"], 0)
        self.assertEqual(offline["state"], "offline")
        self.assertIsNone(pm._problem_banner({"state": "down"}, []))
        pm.monitor_cycle(self._pool())
        with pm.db() as c:
            c.execute("UPDATE hosts SET last_check=0")
        pm.monitor_cycle(self._pool())
        with pm.db() as c:
            titles = [r["title"] for r in c.execute("SELECT title FROM events ORDER BY id")]
            host = c.execute("SELECT alarm_rearm, alerted_down FROM hosts").fetchone()
        self.assertEqual(titles.count("Down"), 1)
        self.assertEqual(host["alarm_rearm"], 0)
        self.assertEqual(host["alerted_down"], 1)
        pm.release_alarm_quiet()
        self.assertIsNotNone(pm._problem_banner({"state": "down"}, []))

    def test_clear_button_admin_csrf_and_map_kiosk(self):
        client = pm.app.test_client()
        with client.session_transaction() as sess:
            sess["role"] = "viewer"
            sess["csrf"] = "t"
        denied = client.post("/alarms/clear", data={"csrf": "t"})
        self.assertEqual(denied.status_code, 302)
        with client.session_transaction() as sess:
            sess["role"] = "admin"
            sess["csrf"] = "t"
        missing = client.post("/alarms/clear", data={})
        self.assertEqual(missing.status_code, 400)
        page = client.get("/").get_data(as_text=True)
        self.assertIn("Clear all alarms", page)
        self.assertIn('data-confirm=', page)
        ok = client.post("/alarms/clear", data={"csrf": "t"})
        self.assertEqual(ok.status_code, 302)
        with client.session_transaction() as sess:
            sess["ui_lang"] = "el"
        greek = client.get("/").get_data(as_text=True)
        self.assertIn("Εκκαθάριση όλων των συναγερμών", greek)
        with pm.db() as c:
            c.execute("""INSERT INTO hosts(name, host, grp, device_type, enabled, created_at, state)
                         VALUES('Core','10.0.0.1','Shop','mikrotik',1,?,'up')""", (time.time(),))
            c.execute("""INSERT INTO hosts(name, host, grp, device_type, enabled, created_at, state, parent_id)
                         VALUES('Other','10.0.0.2','Other','generic',1,?,'down',1)""", (time.time(),))
        mapped = client.get("/map?site=Shop").get_data(as_text=True)
        self.assertIn("map-zoom-in", mapped)
        self.assertIn("map-fit", mapped)
        self.assertNotIn("cdn.", mapped)
        self.assertIn("Core", mapped)
        self.assertNotIn('data-name="Other"', mapped)
        board = client.get("/kiosk/tok").get_data(as_text=True)
        self.assertIn("fetch(", board)
        self.assertNotIn('http-equiv="refresh"', board)
        self.assertNotIn("cdn.", board)
        self.assertIn("id=\"clock\"", board)
        light = client.get("/kiosk/tok?theme=light").get_data(as_text=True)
        self.assertIn('class="light"', light)
        self.assertEqual(client.get("/kiosk/nope").status_code, 404)
        live = client.get("/kiosk/tok/live").get_json()
        blob = json.dumps(live).lower()
        for banned in ("password", "secret", "kiosk_token", "api_token"):
            self.assertNotIn(banned, blob)
        self.assertIn("categories", live)
        self.assertIn("availability", live)
        self.assertIn("down", live)
        self.assertTrue(any(item["name"] == "Other" for item in live["down"]))


if __name__ == "__main__":
    unittest.main()
