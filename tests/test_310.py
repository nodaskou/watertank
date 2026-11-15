"""3.1.0 rules with mocked device payloads. No real Shelly, Sonoff, or NVR is contacted."""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import camapi
import healthmon
import iotmon
import pingmonitor as pm
import wirelogic


class Rules(unittest.TestCase):
    def test_dependency_cycle_and_hold(self):
        parents = {1: None, 2: 1, 3: 2}
        self.assertTrue(wirelogic.dependency_cycle(1, 3, {**parents, 1: 3}))
        self.assertFalse(wirelogic.dependency_cycle(3, 1, parents))
        self.assertEqual(wirelogic.upstream_down(3, {3: 2, 2: 1, 1: None}, {1}), 1)
        held = wirelogic.plan_ping("up", 2, 0, 0, 0, None, False, 1000, 3, 30, True)
        self.assertEqual(held["action"], "held")
        self.assertEqual(held["state"], "down")
        quiet = wirelogic.plan_ping("down", 5, 0, 0, 1, 900, False, 2000, 3, 30, True)
        self.assertIsNone(quiet["action"])
        release = wirelogic.plan_ping("down", 6, 0, 0, 1, 900, False, 3000, 3, 30, False)
        self.assertEqual(release["action"], "release")
        no_flood = wirelogic.plan_ping("down", 9, 1, 1000, 1, 900, False, 5000, 3, 30, False)
        self.assertIsNone(no_flood["action"])
        self.assertEqual(no_flood["last_alert"], 5000)
        again = wirelogic.plan_ping("down", 10, 1, 5000, 0, 900, False, 5100, 3, 30, False)
        self.assertIsNone(again["action"])

    def test_disk_and_backup_rules(self):
        self.assertEqual(healthmon.disk_level(5, 100, 15, 5), "critical")
        self.assertEqual(healthmon.disk_level(10, 100, 15, 5), "warning")
        self.assertEqual(healthmon.disk_level(50, 100, 15, 5), "ok")
        self.assertEqual(healthmon.disk_level(None, None, 15, 5), "unknown")
        self.assertEqual(healthmon.disk_level(0, 100, 0, 0), "off")
        now = 1_000_000
        self.assertEqual(healthmon.backup_status(now - 8 * 86400, now, 7 * 86400, 12 * 3600, True), "stale")
        self.assertEqual(healthmon.backup_status(now - 3600, now, 7 * 86400, 12 * 3600, True), "ok")
        self.assertEqual(healthmon.backup_status(None, now, 86400, 0, False), "off")
        self.assertEqual(healthmon.heartbeat_view(10, 180, True), "ok")
        self.assertEqual(healthmon.heartbeat_view(1000, 180, True), "hung")
        self.assertEqual(healthmon.heartbeat_view(None, 180, False), "stopped")
        self.assertEqual(healthmon.heartbeat_view(None, 180, None), "unknown")

    def test_recording_does_not_invent_failure(self):
        channels = [
            {"id": "1", "online": True, "recording": False},
            {"id": "2", "online": False, "recording": False},
            {"id": "3", "online": True, "recording": None},
        ]
        none, note = camapi.recording_assessment(channels, {"channels": []}, datetime(2026, 11, 6, 12, 0))
        self.assertEqual(none, [])
        self.assertIn("motion-only", note)
        problems, note = camapi.recording_assessment(
            channels, {"channels": ["1", "2", "3"], "start": "00:00", "end": "23:59", "days": "0123456"},
            datetime(2026, 11, 6, 12, 0))
        self.assertEqual([p["key"] for p in problems], ["rec:1"])
        self.assertIn("unknown", note)
        outside, _ = camapi.recording_assessment(
            channels, {"channels": ["1"], "start": "22:00", "end": "23:00", "days": "0123456"},
            datetime(2026, 11, 6, 12, 0))
        self.assertEqual(outside, [])
        live = camapi.parse_hik_working(
            "<WorkingStatus><ChanStatus><chanNo>1</chanNo><record>0</record></ChanStatus></WorkingStatus>")
        self.assertIs(live["1"], False)
        self.assertEqual(camapi.parse_hik_working("<WorkingStatus></WorkingStatus>"), {})

    def test_shelly_and_sonoff_mocked(self):
        gen1 = {
            "relays": [{"ison": False}, {"ison": True}],
            "inputs": [{"input": 1}],
            "meters": [{"power": 12.5, "total": 100}],
            "tmp": {"tC": 41.2, "is_valid": True},
            "uptime": 50,
        }
        parsed = iotmon.parse_shelly_gen1(gen1)
        self.assertEqual([c["on"] for c in parsed["channels"]], [False, True])
        self.assertEqual(parsed["power"][0]["watts"], 12.5)
        self.assertIsNone(iotmon.parse_shelly_gen1({"relays": [{"ison": False}]})["temp_c"])
        calls = []

        def fetch(path, body=None):
            calls.append((path, body))
            if path == "/shelly":
                return 200, json.dumps({"type": "SHSW-1"}), "online"
            if path == "/status":
                return 200, json.dumps(gen1), "online"
            return 404, "", "api_error"

        result = iotmon.check_shelly(fetch, "gen1")
        self.assertEqual(result["observation"], "online")
        self.assertFalse(any("turn" in path or "relay/" in path for path, _b in calls))
        auth = iotmon.check_shelly(lambda path, body=None: (0, "", "auth"), "gen1")
        self.assertEqual(auth["observation"], "auth")
        self.assertNotEqual(auth["observation"], "offline")
        down = iotmon.check_shelly(lambda path, body=None: (0, "", "offline"), "auto")
        self.assertEqual(down["observation"], "offline")
        gen2 = {"switch:0": {"output": False, "apower": 3}, "input:0": {"state": True}, "sys": {"uptime": 9}}
        parsed2 = iotmon.parse_shelly_gen2(gen2, {"model": "SNSW-001X16EU"})
        self.assertEqual(parsed2["channels"][0]["on"], False)
        self.assertEqual(parsed2["model"], "SNSW-001X16EU")
        diy = iotmon.parse_sonoff_diy({"data": {"switch": "off", "fwVersion": "3.5.0", "deviceid": "1000"}})
        self.assertEqual(diy["channels"][0]["on"], False)
        self.assertIsNone(diy["temp_c"])
        body = json.dumps({"deviceid": "abc", "data": {}})

        def diy_fetch(path, payload=None):
            self.assertEqual(path, "/zeroconf/info")
            self.assertNotIn("switch", path)
            return 200, json.dumps({"error": 0, "data": {"switch": "on", "fwVersion": "3.6.0"}}), "online"

        diy_result = iotmon.check_sonoff_diy(diy_fetch, "abc")
        self.assertEqual(diy_result["observation"], "online")
        self.assertTrue(diy_result["parsed"]["channels"][0]["on"])
        tasmota = iotmon.parse_tasmota(
            {"Status": {"DeviceName": "Bench"}, "StatusSTS": {"POWER1": "OFF", "POWER2": "ON", "UptimeSec": 12}},
            {"StatusSNS": {"ENERGY": {"Power": 4, "Total": 1.5}}})
        self.assertEqual([c["on"] for c in tasmota["channels"]], [False, True])
        self.assertEqual(tasmota["power"][0]["watts"], 4)
        missing = iotmon.mqtt_library_missing()
        self.assertEqual(missing["observation"], "unknown")
        fresh = iotmon.evaluate_mqtt(
            [{"topic": "tele/sw/LWT", "payload": "Online", "ts": 1000},
             {"topic": "tele/sw/STATE", "payload": json.dumps({"POWER": "OFF", "UptimeSec": 3}), "ts": 1000}],
            1100, 180)
        self.assertEqual(fresh["reach"], "online")
        self.assertFalse(fresh["parsed"]["channels"][0]["on"])
        stale = iotmon.evaluate_mqtt(
            [{"topic": "tele/sw/LWT", "payload": "Online", "ts": 1000},
             {"topic": "tele/sw/STATE", "payload": "{}", "ts": 1000}],
            2000, 180)
        self.assertEqual(stale["reach"], "offline")
        silent = iotmon.evaluate_mqtt([], 2000, 180)
        self.assertEqual(silent["reach"], "unknown")
        will = iotmon.evaluate_mqtt([{"topic": "tele/sw/LWT", "payload": "Offline", "ts": 2000}], 2010, 180)
        self.assertEqual(will["reach"], "offline")
        plan = iotmon.plan_iot("online", 0, 0, 0, 0, "offline", 50, 3, 30, False)
        self.assertIsNone(plan["action"])
        plan = iotmon.plan_iot("unknown", 2, 0, 0, 0, "offline", 60, 3, 30, True)
        self.assertEqual(plan["action"], "held")
        self.assertEqual(plan["reach"], "offline")
        plan = iotmon.plan_iot("online", 0, 0, 0, 0, "auth", 70, 3, 30, False)
        self.assertEqual(plan["reach"], "auth")
        self.assertNotEqual(plan["reach"], "offline")


class MonitorIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pm.DB_PATH = os.path.join(self.tmp.name, "t.db")
        pm.DATA_DIR = self.tmp.name
        pm.SNAP_DIR = os.path.join(self.tmp.name, "snap")
        os.makedirs(pm.SNAP_DIR, exist_ok=True)
        pm.init_db()
        pm.set_settings(fail_threshold=1, repeat_min=0, quiet_start="", quiet_end="", maintenance_until=0)
        self._ping = {}
        real = pm.get_pinger

        def fake(_method):
            def ping(host, _timeout):
                ok = self._ping.get(host, True)
                return (ok, 1.0 if ok else None)
            return {"fn": ping, "name": "mock"}

        pm.get_pinger = fake
        self._real_pinger = real

    def tearDown(self):
        pm.get_pinger = self._real_pinger
        self.tmp.cleanup()

    def _add(self, name, host, parent=None):
        with pm.db() as c:
            c.execute("""INSERT INTO hosts(name, host, device_type, enabled, created_at, state, fail_n, parent_id)
                         VALUES(?,?,?,?,?,?,?,?)""",
                      (name, host, "generic", 1, time.time(), "up", 1, parent))
            return c.execute("SELECT id FROM hosts WHERE host=?", (host,)).fetchone()["id"]

    def titles(self):
        with pm.db() as c:
            return [r["title"] for r in c.execute("SELECT title FROM events ORDER BY id")]

    def test_parent_down_holds_child_then_one_release(self):
        parent = self._add("core", "10.0.0.1")
        child = self._add("cam", "10.0.0.2", parent)
        self._ping = {"10.0.0.1": False, "10.0.0.2": False}

        class Pool:
            def map(self, fn, items):
                return list(map(fn, items))

        pm.monitor_cycle(Pool())
        self.assertIn("Down", self.titles())
        self.assertIn("Down (alerts held)", self.titles())
        with pm.db() as c:
            c.execute("UPDATE hosts SET last_check=0")
        with pm.db() as c:
            row = c.execute("SELECT state, dep_held, alerted_down FROM hosts WHERE id=?", (child,)).fetchone()
        self.assertEqual(row["state"], "down")
        self.assertEqual(row["dep_held"], 1)
        self.assertEqual(row["alerted_down"], 0)
        self._ping["10.0.0.1"] = True
        pm.monitor_cycle(Pool())
        self.assertEqual(self.titles().count("Down"), 2)
        with pm.db() as c:
            child_row = c.execute("SELECT state, dep_held, alerted_down FROM hosts WHERE id=?", (child,)).fetchone()
            parent_row = c.execute("SELECT state FROM hosts WHERE id=?", (parent,)).fetchone()
        self.assertEqual(parent_row["state"], "up")
        self.assertEqual(child_row["state"], "down")
        self.assertEqual(child_row["alerted_down"], 1)
        before = len(self.titles())
        with pm.db() as c:
            c.execute("UPDATE hosts SET last_check=0")
        pm.monitor_cycle(Pool())
        self.assertEqual(len(self.titles()), before)


if __name__ == "__main__":
    unittest.main()
