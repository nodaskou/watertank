#!/usr/bin/env python3
"""Independent check that the monitor process is still writing a heartbeat.

This runs from systemd as its own oneshot. It can notice a stopped or hung
monitor while this machine is still up, and it sends that through the same
Telegram and e-mail settings. It cannot report a powered-off host or a dead
network: nothing on this machine runs in that case. Point an external heartbeat
service at the URL in Settings → Alerts if you need that. This program does not
create that service.

The bot token is read only to send, and it is not written to the log.
"""
import argparse
import json
import os
import subprocess
import time
def service_active():
    try:
        out = subprocess.run(["systemctl", "is-active", "pingmonitor.service"],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or "").strip()
    if text == "active":
        return True
    if text in ("inactive", "failed", "deactivating"):
        return False
    return None


def beat_age(path):
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Wirewave monitor watchdog")
    ap.add_argument("--db", default=os.environ.get("PINGMON_DB", "/opt/pingmonitor/data/pingmonitor.db"))
    args = ap.parse_args()
    import pingmonitor as pm
    pm.DB_PATH = os.path.abspath(args.db)
    pm.DATA_DIR = os.path.dirname(pm.DB_PATH)
    pm.SNAP_DIR = os.path.join(pm.DATA_DIR, "snapshots")
    if not os.path.isfile(pm.DB_PATH):
        return
    import healthmon
    s = pm.get_settings()
    limit = int(s.get("health_watchdog_sec") or 180)
    age = beat_age(os.path.join(pm.DATA_DIR, "heartbeat"))
    view = healthmon.heartbeat_view(age, limit, service_active())
    flag = os.path.join(pm.DATA_DIR, "watchdog-state.json")
    try:
        state = json.loads(open(flag, encoding="utf-8").read())
    except (OSError, ValueError):
        state = {}
    alerted = bool(state.get("alerted"))
    if view in ("stopped", "hung", "stale"):
        if alerted:
            return
        text = {
            "stopped": "The monitor service is not running. This machine is still up, so this watchdog could send. A full power cut cannot be reported from here.",
            "hung": "The monitor service is active but its heartbeat is late. It may be stuck.",
            "stale": "The monitor heartbeat is late.",
        }[view]
        try:
            pm.add_event("health", "watchdog", "critical", None, "Monitor " + view, text)
            pm.consider_notify(s, None, "critical", f"[{s.get('site_name') or 'site'}] Monitor {view}", text,
                               pm.build_payload(s, "device_alert", None, None, severity="critical", message=text))
        except Exception:
            pm.log.info("watchdog notify failed")
        with open(flag, "w", encoding="utf-8") as fh:
            json.dump({"alerted": True, "view": view, "ts": time.time()}, fh)
        return
    if view == "ok" and alerted:
        text = "The monitor heartbeat is fresh again."
        try:
            pm.add_event("health", "watchdog_recovered", "info", None, "Monitor heartbeat restored", text)
            pm.consider_notify(s, None, "info", f"[{s.get('site_name') or 'site'}] Monitor heartbeat restored", text,
                               pm.build_payload(s, "device_alert", None, None, severity="info", message=text))
        except Exception:
            pm.log.info("watchdog recovery notify failed")
        with open(flag, "w", encoding="utf-8") as fh:
            json.dump({"alerted": False, "view": "ok", "ts": time.time()}, fh)


if __name__ == "__main__":
    main()
