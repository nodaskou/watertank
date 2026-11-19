"""3.2.0 helpers. Controllers, dish, NUT, certificates and commands are mocked."""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import siteops


class Categories(unittest.TestCase):
    def test_guess_and_counts(self):
        self.assertEqual(siteops.guess_category("shelly", "plug"), "iot")
        self.assertEqual(siteops.guess_category("hikvision", "Shop NVR"), "nvr")
        self.assertEqual(siteops.guess_category("hikvision", "Door"), "cameras")
        self.assertEqual(siteops.guess_category("mikrotik", "CRS326"), "switches")
        self.assertEqual(siteops.guess_category("mikrotik", "Office"), "routers")
        self.assertEqual(siteops.guess_category("unifi", "Hall"), "wifi")
        hosts = [{"category": "cameras", "state": "up"}, {"category": "cameras", "state": "down"}]
        counts = siteops.category_counts(hosts)
        cam = next(row for row in counts if row["id"] == "cameras")
        self.assertEqual((cam["total"], cam["online"], cam["offline"]), (2, 1, 1))
        self.assertEqual(siteops.summary_counts(hosts)["availability"], 50.0)
        self.assertIn("Πίνακας", siteops.strings("el")["dashboard"])
        self.assertIn("Dashboard", siteops.strings("en")["dashboard"])


class MapAndUps(unittest.TestCase):
    def test_svg_uses_parent_and_colour(self):
        svg = siteops.map_svg([
            {"id": 1, "name": "Core", "parent_id": None, "state": "up"},
            {"id": 2, "name": "Cam", "parent_id": 1, "state": "down"},
        ], "el")
        self.assertIn("#dc2626", svg)
        self.assertIn("#16a34a", svg)
        self.assertIn("<line", svg)
        self.assertNotIn("cdn.", svg)

    def test_nut_parser(self):
        text = '\n'.join([
            "BEGIN LIST VAR ups",
            'VAR ups battery.charge "88"',
            'VAR ups battery.runtime "1200"',
            'VAR ups ups.status "OB LB"',
            'VAR ups ups.load "40"',
            "END LIST VAR ups",
        ])
        parsed = siteops.parse_nut(text)
        self.assertTrue(parsed["on_battery"])
        self.assertEqual(parsed["charge_pct"], 88)
        self.assertEqual(parsed["battery_status"], "low")
        self.assertIsNone(siteops.parse_nut("BEGIN\nEND"))


class Controllers(unittest.TestCase):
    def test_unifi_and_omada_and_starlink(self):
        aps = siteops.parse_unifi_devices({"data": [{
            "name": "Hall", "mac": "aa", "model": "U6", "state": 1, "num_sta": 12,
            "radio_table_stats": [{"channel": 36, "cu_total": 20}],
        }]})
        self.assertEqual(aps[0]["clients"], 12)
        self.assertEqual(aps[0]["channel"], 36)
        self.assertEqual(aps[0]["state"], "up")
        omada = siteops.parse_omada_devices({"result": [{"name": "AP1", "status": 1, "clientNum": 3}]})
        self.assertEqual(omada[0]["clients"], 3)
        dish = siteops.parse_starlink({"dishGetStatus": {
            "state": "CONNECTED",
            "downlinkThroughputBps": 20_000_000,
            "uplinkThroughputBps": 5_000_000,
            "obstructionStats": {"fractionObstructed": 0.02},
            "alerts": {"motorsStuck": False, "obstructed": True},
        }})
        self.assertTrue(dish["online"])
        self.assertEqual(dish["down_mbps"], 20)
        self.assertEqual(dish["obstruction_pct"], 2)
        self.assertEqual(dish["alerts"], ["obstructed"])
        self.assertIsNone(siteops.parse_starlink({"other": 1}))
        self.assertIsNone(siteops.speedtest_args(""))
        self.assertTrue(siteops.speedtest_args("/usr/bin/speedtest"))


class QualityCertsCommands(unittest.TestCase):
    def test_latency_not_down(self):
        now = 10_000
        samples = [(now - 60, True, 400), (now - 50, True, 450), (now - 40, True, 500),
                   (now - 30, True, 420), (now - 20, True, 410)]
        bad = siteops.sustained_bad(samples, now, 300, 200, 50)
        self.assertEqual(bad["kind"], "latency")
        down = [(now - i, False, None) for i in range(5)]
        self.assertIsNone(siteops.sustained_bad(down, now, 300, 200, 20))

    def test_thresholds_once(self):
        self.assertEqual(siteops.next_threshold(12, (30, 14, 7, 0), None), 14)
        self.assertIsNone(siteops.next_threshold(12, (30, 14, 7, 0), 14))
        self.assertEqual(siteops.next_threshold(3, (30, 14, 7, 0), 14), 7)
        self.assertEqual(siteops.next_threshold(-1, (30, 14, 7), 7), None)
        ends = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        days = siteops.rdap_expiry({"events": [{"eventAction": "expiration", "eventDate": ends}]})
        self.assertTrue(8 <= days <= 10)

    def test_commands_authorized_only(self):
        snap = {"site": "Hotel", "online": 3, "offline": 1, "availability": 75,
                "down_names": ["Door"], "ups": [{"name": "ups", "charge": 90, "source": "mains"}]}
        self.assertIsNone(siteops.command_reply("/status", "999", ["123"], snap))
        text = siteops.command_reply("/down", "123", ["123"], snap, "el")
        self.assertIn("Door", text)
        self.assertIn("Εκτός", text)
        self.assertIn("/status", siteops.command_reply("/help", "123", ["123"], snap, "en"))
        self.assertIn("90", siteops.command_reply("/ups", "123", ["123"], snap))
        self.assertIn("Hotel", siteops.command_reply("/site Hotel", "123", ["123"], snap))
        self.assertIsNone(siteops.command_reply("hello", "123", ["123"], snap))


if __name__ == "__main__":
    unittest.main()
