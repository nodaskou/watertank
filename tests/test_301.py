"""Release 3.0.1: healthy disks are not alarms, and SIA tests are supervision."""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import camapi
import jobs
import pingmonitor as pm
import siarecv


def _quiet_covering_now():
    local = datetime.now(pm.tzinfo())
    minute = local.hour * 60 + local.minute
    start = (minute - 30) % 1440
    end = (minute + 30) % 1440
    if start == end:
        end = (end + 1) % 1440

    def fmt(value):
        return f"{value // 60:02d}:{value % 60:02d}"

    return fmt(start), fmt(end)


class Release301(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pm.DB_PATH = os.path.join(self.tmp.name, "t.db")
        pm.DATA_DIR = self.tmp.name
        pm.SNAP_DIR = os.path.join(self.tmp.name, "snap")
        os.makedirs(pm.SNAP_DIR, exist_ok=True)
        pm.init_db()
        pm.set_settings(sia_ts_mode="off", sia_log_tests=0, quiet_start="", quiet_end="",
                        maintenance_until=0, repeat_min=30, disk_repeat_min=0, quiet_critical=1)

    def tearDown(self):
        self.tmp.cleanup()

    def events(self):
        with pm.db() as c:
            return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id")]

    def account(self, **extra):
        row = {"account": "123456", "name": "ww", "panel": "other", "supervise_min": 10,
               "last_ts": None, "state": "disarmed", "rest_state": "disarmed"}
        row.update(extra)
        with pm.db() as c:
            c.execute("""INSERT INTO sia_accounts(account, name, panel, supervise_min, last_ts, state, rest_state)
                         VALUES(:account,:name,:panel,:supervise_min,:last_ts,:state,:rest_state)""", row)
        return row

    def send(self, body, peer="192.168.51.100"):
        return pm.on_sia_frame(siarecv.build_frame(body), peer)

    def test_disk_status_words(self):
        self.assertFalse(camapi._disk_problem("ok", 1000000, 0))
        self.assertFalse(camapi._disk_problem("OK", 1000000, 0))
        self.assertFalse(camapi._disk_problem("normal", 100, 0))
        self.assertFalse(camapi._disk_problem("idle", 100, 0))
        self.assertFalse(camapi._disk_problem("sleeping", 100, 0))
        self.assertFalse(camapi._disk_problem("sleep", 100, 0))
        self.assertFalse(camapi._disk_problem("notexist", 0, 0))
        self.assertTrue(camapi._disk_problem("error", 100, 80))
        self.assertTrue(camapi._disk_problem("abnormal", 100, 80))
        self.assertTrue(camapi._disk_problem("unformatted", 100, 80))
        self.assertTrue(camapi._disk_problem("uninitialized", 100, 80))
        self.assertTrue(camapi._disk_problem("smart failed", 100, 80))
        xml = """<storage><hdd><hddName>hdda</hddName><status>ok</status>
                 <capacity>1000000</capacity><freeSpace>0</freeSpace></hdd></storage>"""
        disks = camapi.parse_hik_storage(xml)
        self.assertEqual(disks[0]["name"], "hdda")
        self.assertFalse(disks[0]["problem"])
        dahua_ok = "\n".join([
            "list.info[0].Name=hdda",
            "list.info[0].State=Success",
            "list.info[0].IsError=true",
            "list.info[0].TotalBytes=1000000",
            "list.info[0].UsedBytes=1000000",
        ])
        self.assertFalse(camapi.parse_dahua_storage(dahua_ok)[0]["problem"])
        dahua_bad = "\n".join([
            "list.info[0].Name=hdda",
            "list.info[0].State=Error",
            "list.info[0].IsError=false",
            "list.info[0].TotalBytes=1000000",
            "list.info[0].UsedBytes=1",
        ])
        self.assertTrue(camapi.parse_dahua_storage(dahua_bad)[0]["problem"])

    def _hik(self, status, free=0, cap=1000000):
        xml = (f"<storage><hdd><hddName>hdda</hddName><status>{status}</status>"
               f"<capacity>{cap}</capacity><freeSpace>{free}</freeSpace></hdd></storage>")
        disks = camapi.parse_hik_storage(xml)
        return camapi._result("hikvision", True, {"model": "DS"}, disks, [], [])

    def _host(self):
        with pm.db() as c:
            c.execute("INSERT INTO hosts(name, host, device_type, created_at) VALUES(?,?,?,?)",
                      ("hik", "192.168.50.2", "hikvision", time.time()))
            hid = c.execute("SELECT id FROM hosts WHERE host=?", ("192.168.50.2",)).fetchone()["id"]
        return {"id": hid, "name": "hik", "host": "192.168.50.2"}

    def _prev(self, host):
        with pm.db() as c:
            return c.execute("SELECT ts, data FROM cam_state WHERE host_id=?", (host["id"],)).fetchone()

    def test_disk_ok_never_reminds_and_recovery_is_once(self):
        host = self._host()
        now = time.time()
        jobs.apply_camera_result(pm, host, self._hik("ok"), True, None, now)
        self.assertEqual(self.events(), [])
        jobs.apply_camera_result(pm, host, self._hik("error", 50, 100), True, self._prev(host), now + 1)
        titles = [e["title"] for e in self.events()]
        self.assertEqual(titles, ["Disk hdda"])
        self.assertEqual(self.events()[0]["severity"], "critical")
        self.assertIn("status error", self.events()[0]["message"])
        jobs.apply_camera_result(pm, host, self._hik("error", 50, 100), True, self._prev(host), now + 2)
        self.assertEqual([e["title"] for e in self.events()], ["Disk hdda"])
        with pm.db() as c:
            raw = json.loads(c.execute("SELECT data FROM cam_state WHERE host_id=?", (host["id"],)).fetchone()["data"])
            raw["notified"]["disk:hdda"] = now - 31 * 60
            c.execute("UPDATE cam_state SET data=? WHERE host_id=?", (json.dumps(raw), host["id"]))
        jobs.apply_camera_result(pm, host, self._hik("error", 50, 100), True, self._prev(host), now + 3)
        self.assertEqual([e["title"] for e in self.events()], ["Disk hdda", "Disk hdda (still)"])
        jobs.apply_camera_result(pm, host, self._hik("ok"), True, self._prev(host), now + 4)
        titles = [e["title"] for e in self.events()]
        self.assertEqual(titles, ["Disk hdda", "Disk hdda (still)", "Disk hdda recovered"])
        self.assertEqual(self.events()[-1]["severity"], "info")
        self.assertEqual(pm.event_mark("cam", "info", "cam_recovered"), "✅ ")
        with pm.db() as c:
            raw = json.loads(c.execute("SELECT data FROM cam_state WHERE host_id=?", (host["id"],)).fetchone()["data"])
        self.assertNotIn("disk:hdda", raw.get("notified") or {})
        jobs.apply_camera_result(pm, host, self._hik("ok"), True, self._prev(host), now + 5)
        self.assertEqual([e["title"] for e in self.events()], titles)

    def test_stuck_ok_disk_self_heals(self):
        host = self._host()
        stuck = {"notified": {"disk:hdda": time.time() - 3600}, "disks": [
            {"name": "hdda", "status": "ok", "problem": True}], "problems": [
            {"key": "disk:hdda", "kind": "cam_disk_error", "severity": "critical",
             "title": "Disk hdda", "message": "hdda status ok"}]}
        with pm.db() as c:
            c.execute("INSERT INTO cam_state(host_id, ts, data) VALUES(?,?,?)",
                      (host["id"], time.time() - 60, json.dumps(stuck)))
        jobs.apply_camera_result(pm, host, self._hik("ok"), True, self._prev(host), time.time())
        ev = self.events()
        self.assertEqual([e["title"] for e in ev], ["Disk hdda recovered"])
        self.assertEqual(ev[0]["severity"], "info")
        jobs.apply_camera_result(pm, host, self._hik("ok", 0, 1000000), True, self._prev(host), time.time() + 1)
        self.assertEqual(len(self.events()), 1)

    def test_periodic_tests_are_not_logged_and_do_not_flash(self):
        self.account()
        calls = []
        real = pm.consider_notify

        def wrapped(*args, **kwargs):
            calls.append(args[3] if len(args) > 3 else "")
            return real(*args, **kwargs)

        pm.consider_notify = wrapped
        try:
            for code in ("RP", "RX", "TX"):
                info = self.send(f'"SIA-DCS"0001L0#123456[#123456|N{code}0]')
                self.assertTrue(info.get("ok"), info)
                self.assertTrue(info.get("supervision") or siarecv.is_supervision(code, False))
            info = self.send('"NULL"0000L0#123456[]')
            self.assertTrue(info.get("ok"), info)
            self.assertTrue(info.get("heartbeat"))
        finally:
            pm.consider_notify = real
        self.assertEqual(self.events(), [])
        self.assertEqual(calls, [])
        with pm.db() as c:
            row = dict(c.execute("SELECT * FROM sia_accounts WHERE account='123456'").fetchone())
        self.assertIsNotNone(row["last_ts"])
        self.assertIsNotNone(row["last_test"])
        self.assertEqual(row["last_text"], "")
        self.assertNotEqual(row["state"], "alarm")
        tile = pm._alarm_rows(pm.tzinfo())[0]
        self.assertFalse(tile["flash"])
        self.assertTrue(tile["seen"])
        self.assertTrue(tile["test_time"])

    def test_real_alarm_has_source_and_siren_only(self):
        self.account()
        info = self.send('"SIA-DCS"0001L0#123456[#123456|NBA1]', "192.168.51.100")
        self.assertTrue(info.get("ok"), info)
        ev = self.events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["severity"], "critical")
        self.assertEqual(ev[0]["host_name"], "ww (123456)")
        self.assertEqual(ev[0]["host_ip"], "192.168.51.100")
        self.assertTrue(ev[0]["host_name"])
        self.assertEqual(pm.event_mark("alarm", "critical", "alarm"), "🚨 ")
        self.assertEqual(pm.event_mark("alarm", "info", "sia_test"), "")
        self.assertEqual(pm.event_mark("alarm", "warning", "sia_offline"), "⚠️ ")
        tile = pm._alarm_rows(pm.tzinfo())[0]
        self.assertTrue(tile["flash"])
        text = tile["last_text"]
        self.send('"SIA-DCS"0001L0#123456[#123456|NRP0]')
        self.assertEqual(len(self.events()), 1)
        tile = pm._alarm_rows(pm.tzinfo())[0]
        self.assertTrue(tile["flash"])
        self.assertEqual(tile["last_text"], text)
        self.assertTrue(tile["test_time"])
        with pm.db() as c:
            row = c.execute("SELECT last_event_ts, last_test FROM sia_accounts WHERE account='123456'").fetchone()
        self.assertIsNotNone(row["last_event_ts"])
        self.assertGreaterEqual(row["last_test"], row["last_event_ts"])

    def test_log_periodic_tests_is_info_without_alert(self):
        self.account()
        pm.set_settings(sia_log_tests=1)
        calls = []
        real = pm.consider_notify
        pm.consider_notify = lambda *a, **k: calls.append(a) or real(*a, **k)
        try:
            self.send('"SIA-DCS"0001L0#123456[#123456|NRP0]')
        finally:
            pm.consider_notify = real
        ev = self.events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["severity"], "info")
        self.assertEqual(ev[0]["host_name"], "ww (123456)")
        self.assertIn("Automatic", ev[0]["title"])
        self.assertEqual(calls, [])
        self.assertEqual(pm.get_settings()["sia_log_tests"], 1)
        pm.set_settings(sia_log_tests=0)
        self.assertEqual(pm.get_settings()["sia_log_tests"], 0)

    def test_supervision_timeout_once_each_way(self):
        self.account(last_ts=time.time() - 11 * 60, state="disarmed")
        pm.sia_supervise()
        pm.sia_supervise()
        ev = self.events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["title"], "panel communication lost")
        self.assertEqual(ev[0]["severity"], "warning")
        self.assertEqual(ev[0]["host_name"], "ww (123456)")
        with pm.db() as c:
            state = c.execute("SELECT state, offline_alerted FROM sia_accounts WHERE account='123456'").fetchone()
        self.assertEqual(state["state"], "offline")
        self.assertEqual(state["offline_alerted"], 1)
        self.send('"NULL"0000L0#123456[]')
        self.send('"SIA-DCS"0001L0#123456[#123456|NRP0]')
        titles = [e["title"] for e in self.events()]
        self.assertEqual(titles.count("communication restored"), 1)
        self.assertEqual(titles.count("panel communication lost"), 1)
        self.assertNotIn("Automatic", " ".join(titles))
        with pm.db() as c:
            state = c.execute("SELECT state, offline_alerted FROM sia_accounts WHERE account='123456'").fetchone()
        self.assertNotEqual(state["state"], "offline")
        self.assertEqual(state["offline_alerted"], 0)

    def test_lost_alert_respects_quiet_and_maintenance(self):
        start, end = _quiet_covering_now()
        pm.set_settings(quiet_start=start, quiet_end=end)
        self.assertTrue(pm.is_quiet(pm.get_settings()))
        self.account(last_ts=time.time() - 11 * 60)
        pm.sia_supervise()
        self.assertEqual(self.events()[0]["title"], "panel communication lost")
        with pm.db() as c:
            queued = c.execute("SELECT COUNT(*) AS n FROM alert_queue").fetchone()["n"]
        self.assertEqual(queued, 1)
        with pm.db() as c:
            c.execute("DELETE FROM events")
            c.execute("DELETE FROM alert_queue")
            c.execute("UPDATE sia_accounts SET state='disarmed', offline_alerted=0, last_ts=? WHERE account='123456'",
                      (time.time() - 11 * 60,))
        pm.set_settings(quiet_start="", quiet_end="", maintenance_until=int(time.time()) + 3600)
        pm.sia_supervise()
        self.assertEqual(self.events()[0]["severity"], "warning")
        with pm.db() as c:
            queued = c.execute("SELECT COUNT(*) AS n FROM alert_queue").fetchone()["n"]
        self.assertEqual(queued, 0)

    def test_recent_events_heading(self):
        self.assertIn("<h2>Recent events</h2>", pm.INDEX_BODY)
        self.assertNotIn("ping + device e-mails", pm.INDEX_BODY)
        self.assertNotIn("ping + device e-mails", pm.LOG_BODY)
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "pingmonitor.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("ping + device e-mails", src)
        self.assertIn("Clear all log entries and events?", src)
        self.assertIn(">Clear log<", src)
        self.assertEqual(pm.VERSION, "3.0.1")

    def test_clear_log_keeps_active_state(self):
        self.account(state="alarm", last_ts=time.time())
        with pm.db() as c:
            c.execute("UPDATE sia_accounts SET ack_at=0 WHERE account='123456'")
            c.execute("INSERT INTO hosts(name, host, device_type, state, created_at) VALUES(?,?,?,?,?)",
                      ("hik", "192.168.50.2", "hikvision", "down", time.time()))
            hid = c.execute("SELECT id FROM hosts WHERE host='192.168.50.2'").fetchone()["id"]
            c.execute("INSERT INTO cam_state(host_id, ts, data) VALUES(?,?,?)",
                      (hid, time.time(), json.dumps({"notified": {"disk:hdda": time.time()}})))
            c.execute("INSERT INTO events(ts, source, kind, severity, title, message) VALUES(?,?,?,?,?,?)",
                      (time.time(), "ping", "host_down", "critical", "Down", "hik is down"))
            c.execute("INSERT INTO events(ts, source, kind, severity, title, message) VALUES(?,?,?,?,?,?)",
                      (time.time(), "alarm", "alarm", "critical", "Burglary", "ww"))
        pm.app.secret_key = "test-secret"
        with pm.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["role"] = "viewer"
                sess["csrf"] = "tok"
            denied = client.post("/log/clear", data={"csrf": "tok", "next": "log"})
            self.assertEqual(denied.status_code, 302)
            self.assertIn("/login", denied.headers["Location"])
            with client.session_transaction() as sess:
                sess["role"] = "admin"
                sess["csrf"] = "tok"
            bad = client.post("/log/clear", data={"csrf": "nope", "next": "dashboard"})
            self.assertEqual(bad.status_code, 400)
            ok = client.post("/log/clear", data={"csrf": "tok", "next": "dashboard"})
        self.assertEqual(ok.status_code, 302)
        self.assertTrue(ok.headers["Location"].endswith("/"))
        ev = self.events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["title"], "Log cleared")
        self.assertEqual(ev[0]["kind"], "log_cleared")
        self.assertEqual(ev[0]["severity"], "info")
        self.assertEqual(ev[0]["message"], "Cleared by admin from 127.0.0.1")
        self.assertEqual(pm.event_mark("log", "info", "log_cleared"), "🧹 ")
        self.assertTrue(pm.last_cleared_text(pm.tzinfo()))
        with pm.db() as c:
            host = c.execute("SELECT state FROM hosts WHERE id=?", (hid,)).fetchone()
            cam = c.execute("SELECT data FROM cam_state WHERE host_id=?", (hid,)).fetchone()
            alarm = c.execute("SELECT state FROM sia_accounts WHERE account='123456'").fetchone()
        self.assertEqual(host["state"], "down")
        self.assertIn("disk:hdda", json.loads(cam["data"])["notified"])
        self.assertEqual(alarm["state"], "alarm")
        tile = pm._alarm_rows(pm.tzinfo())[0]
        self.assertTrue(tile["flash"])
        with pm.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["role"] = "admin"
                sess["csrf"] = "tok"
            client.post("/log/clear", data={"csrf": "tok", "next": "log"})
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.events()[0]["title"], "Log cleared")
        with pm.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["role"] = "admin"
                sess["csrf"] = "tok"
            page = client.get("/log")
            dash = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Clear log", page.data)
        self.assertIn(b"Clear all log entries and events?", page.data)
        self.assertIn(b"Last cleared:", page.data)
        self.assertIn("🧹", page.get_data(as_text=True))
        self.assertIn(b"Clear log", dash.data)
        self.assertIn(b"Recent events", dash.data)
        self.assertNotIn(b"ping + device e-mails", dash.data)


if __name__ == "__main__":
    unittest.main()
