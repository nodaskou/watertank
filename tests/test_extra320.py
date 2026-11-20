"""Client branding and the extra 3.2.0 checks. Payloads are local fixtures, not live devices."""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import branding
import extraops


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


if __name__ == "__main__":
    unittest.main()
