#!/usr/bin/env python3
"""
Wirewave Ping Monitor v2 - all-in-one network monitor for client sites.

 * Pings hosts (MikroTik, UniFi, Hikvision, Dahua, TP-Link/Omada, ...) every N seconds
 * Read-only dashboard (green / amber / red, latency, uptime, 24h graphs, events)
 * Admin settings page: hosts, site name, intervals, Telegram, SMTP e-mail,
   webhook, built-in SMTP receiver for camera/NVR/controller alert e-mails, API token
 * Alerts: Telegram, e-mail, generic JSON webhook (for Grok Bot / automations)
 * Token-protected JSON API: /api/status and /api/events
 * Everything stored in one SQLite file. Admin password asked on first run.

Run:  python3 pingmonitor.py [--host 127.0.0.1] [--port 8080] [--db pingmonitor.db]
      python3 pingmonitor.py --set-password      (set / reset admin password)
"""
import argparse
import asyncio
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import shutil
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from functools import wraps
from html import unescape

try:
    from zoneinfo import ZoneInfo, available_timezones
except ImportError:  # pragma: no cover
    ZoneInfo = None

from flask import (Flask, abort, flash, jsonify, redirect, render_template_string,
                   request, send_from_directory, session, url_for)

VERSION = "2.1"
log = logging.getLogger("pingmonitor")
MOCK_TELEGRAM = os.environ.get("PINGMON_MOCK_TELEGRAM") == "1"

DB_PATH = None
DATA_DIR = None
SNAP_DIR = None

# ----------------------------------------------------------------------------- device presets
DEVICE_TYPES = {
    "generic":   ("Generic device", "IP", "#64748b"),
    "hikvision": ("Hikvision camera / NVR", "HIK", "#c8102e"),
    "dahua":     ("Dahua camera / NVR", "DAH", "#e05a00"),
    "mikrotik":  ("MikroTik router / switch", "MT", "#2d3748"),
    "airmax":    ("Ubiquiti airMAX / UISP", "UBNT", "#0559c9"),
    "unifi":     ("UniFi (AP / switch / gateway)", "UniFi", "#006fff"),
    "tplink":    ("TP-Link (standalone)", "TP", "#0b9fb3"),
    "omada":     ("TP-Link Omada", "Omada", "#00897b"),
    "starlink":  ("Starlink", "SL", "#111827"),
    "fortinet":  ("Fortinet FortiGate", "FG", "#ee3124"),
    "pbx":       ("Phone system / PBX", "PBX", "#7c3aed"),
    "server":    ("PC / server / NVR software", "PC", "#475569"),
    "printer":   ("Printer", "PRN", "#a16207"),
}

# ----------------------------------------------------------------------------- settings
DEFAULTS = {
    "site_name": "CLIENT-NAME",
    "timezone": "Europe/Athens",
    "public_url": "",
    "ping_interval": 60,
    "ping_timeout": 2,
    "fail_threshold": 3,
    "retention_days": 30,
    "ping_method": "auto",
    "dashboard_access": "login",          # login | public
    "viewer_hash": "",
    "admin_hash": "",
    "secret_key": "",
    "api_token": "",
    "telegram_enabled": 0, "telegram_token": "", "telegram_chat_id": "", "telegram_photos": 1,
    "email_enabled": 0, "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls",
    "smtp_user": "", "smtp_password": "", "smtp_from": "", "smtp_to": "",
    "webhook_enabled": 0, "webhook_url": "", "webhook_header_name": "Authorization",
    "webhook_header_value": "",
    "rx_enabled": 0, "rx_host": "0.0.0.0", "rx_port": 2525, "rx_security": "none",  # none|starttls|ssl
    "rx_require_auth": 0, "rx_user": "alerts", "rx_password": "",
    "rx_allowed_nets": "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 100.64.0.0/10",
    "rx_forward_min": "warning",          # info|warning|critical|none
    "rx_rate_limit": 300,
    # SNMP polling (per host config is stored with the host) + trap receiver
    "snmp_enabled": 1, "snmp_interval": 300, "snmp_timeout": 2, "snmp_cpu_threshold": 90,
    "snmp_alert_ifdown": 1, "snmp_alert_reboot": 1, "snmp_forward_min": "warning",
    "trap_enabled": 0, "trap_host": "0.0.0.0", "trap_port": 1162, "trap_community": "", "trap_forward_min": "warning",
}
INT_KEYS = {k for k, v in DEFAULTS.items() if isinstance(v, int)}
SECRET_KEYS = {"telegram_token", "smtp_password", "webhook_header_value", "rx_password"}
SEVERITY_RANK = {"info": 1, "warning": 2, "critical": 3, "none": 99}

_db_lock = threading.RLock()


class _Conn(sqlite3.Connection):
    """`with db() as c:` commits (or rolls back) and then closes the connection."""
    def __exit__(self, et, ev, tb):
        try:
            return super().__exit__(et, ev, tb)
        finally:
            self.close()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=30, factory=_Conn)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock, db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS hosts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, host TEXT NOT NULL,
            grp TEXT NOT NULL DEFAULT '', device_type TEXT NOT NULL DEFAULT 'generic',
            enabled INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL DEFAULT 'pending',
            consec_fail INTEGER NOT NULL DEFAULT 0, last_ms REAL, last_check REAL,
            last_seen REAL, down_since REAL, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS results(host_id INTEGER NOT NULL, ts REAL NOT NULL,
            ok INTEGER NOT NULL, ms REAL);
        CREATE INDEX IF NOT EXISTS idx_results ON results(host_id, ts);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, source TEXT NOT NULL,
            kind TEXT NOT NULL, severity TEXT NOT NULL, host_id INTEGER, host_name TEXT,
            host_ip TEXT, title TEXT, message TEXT, details TEXT, attachments TEXT);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE TABLE IF NOT EXISTS snmp_state(host_id INTEGER PRIMARY KEY, ts REAL, data TEXT);
        CREATE TABLE IF NOT EXISTS snmp_samples(host_id INTEGER NOT NULL, ts REAL NOT NULL, cpu REAL, mem REAL, ifs TEXT);
        CREATE INDEX IF NOT EXISTS idx_snmp_samples ON snmp_samples(host_id, ts);
        """)
        cols = {r[1] for r in c.execute("PRAGMA table_info(hosts)")}
        if "snmp" not in cols:   # upgrade from 2.0
            c.execute("ALTER TABLE hosts ADD COLUMN snmp TEXT NOT NULL DEFAULT ''")
        for k, v in DEFAULTS.items():
            c.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, str(v)))
        for k in ("secret_key", "api_token"):
            if not c.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()[0]:
                c.execute("UPDATE settings SET value=? WHERE key=?", (secrets.token_urlsafe(32), k))


def get_settings():
    with db() as c:
        raw = {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM settings")}
    s = {}
    for k, d in DEFAULTS.items():
        v = raw.get(k, str(d))
        if k in INT_KEYS:
            try:
                v = int(v)
            except (TypeError, ValueError):
                v = d
        s[k] = v
    return s


def set_settings(**kv):
    with _db_lock, db() as c:
        for k, v in kv.items():
            if k not in DEFAULTS:
                raise KeyError(k)
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, str(v)))


# ----------------------------------------------------------------------------- passwords
def hash_password(pw):
    salt = os.urandom(16)
    n, r, p = 2 ** 14, 8, 1
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        test = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r),
                              p=int(p), dklen=len(dk) // 2)
        return hmac.compare_digest(test.hex(), dk)
    except Exception:
        return False


def prompt_new_password(from_stdin=False):
    if from_stdin:
        pw = sys.stdin.readline().rstrip("\r\n")
        if len(pw) < 8:
            sys.exit("Password must be at least 8 characters")
        return pw
    print("=== Wirewave Ping Monitor - set admin password ===")
    for _ in range(3):
        pw = getpass.getpass("New admin password (min 8 chars): ")
        if len(pw) < 8:
            print("Too short, try again.")
            continue
        if getpass.getpass("Repeat password: ") != pw:
            print("Passwords do not match, try again.")
            continue
        return pw
    sys.exit("Password not set.")


# ----------------------------------------------------------------------------- time helpers
def tzinfo():
    try:
        return ZoneInfo(get_settings()["timezone"])
    except Exception:
        return timezone.utc


def iso(ts, tz=None):
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz or tzinfo()).isoformat(timespec="seconds")


def fmt_ts(ts, tz=None):
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts, tz or tzinfo()).strftime("%Y-%m-%d %H:%M:%S")


def fmt_dur(sec):
    sec = int(sec or 0)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    return (f"{d}d " if d else "") + (f"{h}h " if h or d else "") + f"{m}m {s}s"


def parse_since(v):
    """epoch seconds, ISO-8601 (2026-10-30T22:00:00+02:00) or relative: 30m, 2h, 1d."""
    if not v:
        return 0.0
    rel = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", v)
    if rel:
        return time.time() - int(rel.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[rel.group(2)]
    try:
        return float(v)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tzinfo())
        return dt.timestamp()
    except ValueError:
        abort(400, "since must be epoch seconds, ISO-8601 or relative like 30m / 2h / 1d")


# ----------------------------------------------------------------------------- ping
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.\-:]*[A-Za-z0-9])?$")
_ping_impl = {"key": None, "name": None, "fn": None}


def parse_ping_output(out, rc, system="linux"):
    """(ok, ms) from ping output; handles localized Windows output."""
    if system == "windows":
        for line in out.splitlines():
            if "TTL=" in line.upper():
                m = re.search(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", line, re.I)
                return True, float(m.group(1).replace(",", ".")) if m else 0.5
        return False, None
    if rc != 0:
        return False, None
    m = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", out)
    return True, (float(m.group(1)) if m else None)


def _ping_system(host, timeout):
    system = platform.system().lower()
    flags = 0
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        flags = 0x08000000
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3, creationflags=flags)
    except (subprocess.TimeoutExpired, OSError):
        return False, None
    return parse_ping_output(p.stdout, p.returncode, system)


def _icmplib(privileged):
    from icmplib import ping as icmp_ping

    def _p(host, timeout):
        try:
            r = icmp_ping(host, count=1, timeout=timeout, privileged=privileged)
            return (True, round(r.avg_rtt, 2)) if r.is_alive else (False, None)
        except Exception as e:
            log.debug("icmplib %s: %s", host, e)
            return False, None
    return _p


def get_pinger(method):
    if _ping_impl["key"] == method and _ping_impl["fn"]:
        return _ping_impl
    cands = []
    if method in ("auto", "icmplib"):
        try:
            import icmplib  # noqa: F401
            cands += [("icmplib-unprivileged", _icmplib(False), False),
                      ("icmplib-privileged", _icmplib(True), True)]
        except ImportError:
            pass
    if method in ("auto", "system") and shutil.which("ping"):
        cands.append(("system-ping", _ping_system, None))
    for name, fn, priv in cands:
        if priv is not None:
            try:
                from icmplib import ping as icmp_ping
                icmp_ping("127.0.0.1", count=1, timeout=1, privileged=priv)
            except Exception as e:
                log.info("%s not usable: %s", name, e)
                continue
        log.info("Ping method: %s", name)
        _ping_impl.update(key=method, name=name, fn=fn)
        return _ping_impl
    raise RuntimeError("No usable ping method (install iputils-ping or grant CAP_NET_RAW)")


# ----------------------------------------------------------------------------- notifications
def _http_post(url, data, headers, timeout=15):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(2000)


def send_telegram(s, text, photo_path=None):
    if MOCK_TELEGRAM:
        log.info("[MOCK TELEGRAM] chat=%s photo=%s text=%s", s["telegram_chat_id"],
                 os.path.basename(photo_path) if photo_path else None, text.replace("\n", " / "))
        return
    if not s["telegram_token"] or not s["telegram_chat_id"]:
        raise RuntimeError("Telegram bot token / chat id not set")
    base = f"https://api.telegram.org/bot{s['telegram_token']}"
    if photo_path and os.path.exists(photo_path):
        boundary = uuid.uuid4().hex
        with open(photo_path, "rb") as f:
            img = f.read()
        parts = []
        for k, v in (("chat_id", s["telegram_chat_id"]), ("caption", text[:1024])):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; filename="snapshot.jpg"\r\n'
                     f'Content-Type: image/jpeg\r\n\r\n'.encode() + img + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        _http_post(base + "/sendPhoto", b"".join(parts), {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    else:
        data = urllib.parse.urlencode({"chat_id": s["telegram_chat_id"], "text": text[:4000]}).encode()
        _http_post(base + "/sendMessage", data, {"Content-Type": "application/x-www-form-urlencoded"})


def send_email(s, subject, text):
    to = [a.strip() for a in s["smtp_to"].replace(";", ",").split(",") if a.strip()]
    if not s["smtp_host"] or not to:
        raise RuntimeError("SMTP server / recipients not set")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = s["smtp_from"] or s["smtp_user"] or "pingmonitor@localhost"
    msg["To"] = ", ".join(to)
    msg.set_content(text)
    ctx = ssl.create_default_context()
    port = int(s["smtp_port"])
    if s["smtp_security"] == "ssl":
        srv = smtplib.SMTP_SSL(s["smtp_host"], port, timeout=20, context=ctx)
    else:
        srv = smtplib.SMTP(s["smtp_host"], port, timeout=20)
    with srv:
        srv.ehlo()
        if s["smtp_security"] == "starttls":
            srv.starttls(context=ctx)
            srv.ehlo()
        if s["smtp_user"]:
            srv.login(s["smtp_user"], s["smtp_password"])
        srv.send_message(msg)


def send_webhook(s, payload):
    if not s["webhook_url"].startswith(("http://", "https://")):
        raise RuntimeError("Webhook URL must start with http:// or https://")
    headers = {"Content-Type": "application/json", "User-Agent": f"WirewavePingMonitor/{VERSION}",
               "X-PingMonitor-Event": payload["event"]}
    if s["webhook_header_name"] and s["webhook_header_value"]:
        headers[s["webhook_header_name"]] = s["webhook_header_value"]
    status, _ = _http_post(s["webhook_url"], json.dumps(payload, ensure_ascii=False).encode(), headers)
    if status >= 300:
        raise RuntimeError(f"HTTP {status}")


def build_payload(s, event, ev_id=None, host=None, state=None, down_since=None, downtime=None,
                  fails=None, latency=None, severity="info", message="", alert=None, ts=None):
    ts = ts or time.time()
    tz = tzinfo()
    base = s["public_url"].rstrip("/")
    return {
        "event": event,                     # host_down | host_recovered | device_alert | test
        "event_id": ev_id,
        "site": s["site_name"],
        "timestamp": iso(ts, tz),
        "timezone": s["timezone"],
        "severity": severity,               # info | warning | critical
        "host": None if not host else {
            "id": host.get("id"), "name": host.get("name"), "ip": host.get("host"),
            "group": host.get("grp") or None, "device_type": host.get("device_type") or "generic"},
        "state": state,                     # down | up | null
        "down_since": iso(down_since, tz) if down_since else None,
        "downtime_seconds": int(downtime) if downtime is not None else None,
        "downtime": fmt_dur(downtime) if downtime is not None else None,
        "consecutive_failures": fails,
        "latency_ms": latency,
        "alert": alert,                     # only for device_alert (e-mail from a device)
        "message": message,
        "dashboard_url": (f"{base}/host/{host['id']}" if host and host.get("id") else base or None) if base else None,
    }


def notify(subject, text, payload, photo=None, sync=False):
    """Send to all enabled channels. Async with retries unless sync=True."""
    s = get_settings()
    jobs = []
    if s["telegram_enabled"]:
        jobs.append(("telegram", lambda: send_telegram(s, text, photo if s["telegram_photos"] else None)))
    if s["email_enabled"]:
        jobs.append(("email", lambda: send_email(s, subject, text)))
    if s["webhook_enabled"]:
        jobs.append(("webhook", lambda: send_webhook(s, payload)))

    def run():
        for name, fn in jobs:
            for attempt in range(3):
                try:
                    fn()
                    log.info("%s alert sent: %s", name, subject)
                    break
                except Exception as e:
                    log.error("%s alert failed (try %d): %s", name, attempt + 1, e)
                    time.sleep(3 * (attempt + 1))
    if sync:
        run()
    else:
        threading.Thread(target=run, daemon=True).start()


def add_event(source, kind, severity, host=None, title="", message="", details=None, attachments=None, ts=None, conn=None):
    if conn is None:
        with _db_lock, db() as c:
            return add_event(source, kind, severity, host, title, message, details, attachments, ts, conn=c)
    cur = conn.execute(
        "INSERT INTO events(ts, source, kind, severity, host_id, host_name, host_ip, title, message, details, attachments)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (ts or time.time(), source, kind, severity, host["id"] if host else None,
         host["name"] if host else None, host["host"] if host else None, title, message,
         json.dumps(details or {}, ensure_ascii=False), json.dumps(attachments or [])))
    return cur.lastrowid


# ----------------------------------------------------------------------------- monitor
def monitor_cycle(pool):
    s = get_settings()
    pinger = get_pinger(s["ping_method"])
    with db() as c:
        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts WHERE enabled=1")]
    if not hosts:
        return
    timeout = float(s["ping_timeout"])
    now = time.time()
    results = list(pool.map(lambda h: (h, *pinger["fn"](h["host"], timeout)), hosts))
    threshold = max(1, s["fail_threshold"])
    site = s["site_name"]
    with _db_lock, db() as c:
        for h, ok, ms in results:
            if not c.execute("SELECT 1 FROM hosts WHERE id=? AND enabled=1", (h["id"],)).fetchone():
                continue
            c.execute("INSERT INTO results(host_id, ts, ok, ms) VALUES(?,?,?,?)", (h["id"], now, int(ok), ms))
            label = f"{h['name']} ({h['host']})"
            if ok:
                if h["state"] == "down":
                    downtime = now - (h["down_since"] or now)
                    msg = f"{label} is back UP ({ms} ms) after {fmt_dur(downtime)} down."
                    eid = add_event("ping", "host_recovered", "info", h, "Recovered", msg, {"downtime_seconds": int(downtime)}, ts=now, conn=c)
                    text = f"✅ RECOVERED [{site}]\n{label} is back UP ({ms} ms)\nDowntime: {fmt_dur(downtime)}\n{fmt_ts(now)}"
                    notify(f"[{site}] RECOVERED: {h['name']}", text,
                           build_payload(s, "host_recovered", eid, h, "up", h["down_since"], downtime, 0, ms, "info", msg, ts=now))
                c.execute("UPDATE hosts SET state='up', consec_fail=0, last_ms=?, last_check=?, last_seen=?, down_since=NULL WHERE id=?",
                          (ms, now, now, h["id"]))
            else:
                fails = h["consec_fail"] + 1
                state, down_since = h["state"], h["down_since"]
                if fails >= threshold and state != "down":
                    state, down_since = "down", now
                    msg = f"{label} is not responding ({fails} failed pings in a row). Last seen: {fmt_ts(h['last_seen'])}."
                    eid = add_event("ping", "host_down", "critical", h, "Down", msg, {"consecutive_failures": fails}, ts=now, conn=c)
                    text = (f"🔴 DOWN [{site}]\n{label} is not responding ({fails} failed pings in a row)\n"
                            f"Last seen: {fmt_ts(h['last_seen'])}\n{fmt_ts(now)}")
                    notify(f"[{site}] DOWN: {h['name']}", text,
                           build_payload(s, "host_down", eid, h, "down", now, 0, fails, None, "critical", msg, ts=now))
                elif state != "down":
                    state = "warn"
                c.execute("UPDATE hosts SET state=?, consec_fail=?, last_check=?, last_ms=NULL, down_since=? WHERE id=?",
                          (state, fails, now, down_since, h["id"]))


def prune():
    s = get_settings()
    cutoff = time.time() - max(1, s["retention_days"]) * 86400
    with _db_lock, db() as c:
        old = c.execute("SELECT attachments FROM events WHERE ts < ?", (cutoff,)).fetchall()
        c.execute("DELETE FROM results WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM snmp_samples WHERE ts < ?", (cutoff,))
    for row in old:
        for f in json.loads(row["attachments"] or "[]"):
            try:
                os.remove(os.path.join(SNAP_DIR, f))
            except OSError:
                pass
    with db() as c:
        c.execute("PRAGMA optimize")
    log.info("Pruned data older than %s days", s["retention_days"])


def monitor_loop(stop):
    last_prune = 0
    with ThreadPoolExecutor(max_workers=16) as pool:
        while not stop.is_set():
            start = time.time()
            try:
                monitor_cycle(pool)
                if start - last_prune > 6 * 3600:
                    prune()
                    last_prune = start
            except Exception:
                log.exception("monitor cycle failed")
            interval = max(5, get_settings()["ping_interval"])
            stop.wait(max(1, interval - (time.time() - start)))


# ----------------------------------------------------------------------------- incoming e-mail (SMTP receiver)
# Classification rules, checked in order against "subject + body". (regex, type, severity, title)
MAIL_RULES = [
    (r"test\s*(mail|e-?mail|message)|this\s+is\s+a\s+test|smtp\s+test|email\s+test", "test", "info", "Test e-mail"),
    (r"(hdd|disk|storage|sd\s*card)\s*(is\s*)?full|disk\s*full|no\s+(free\s+)?space|storage\s+space\s+(is\s+)?(full|insufficient)",
     "disk_full", "critical", "Disk full"),
    (r"(hdd|hard\s*disk|disk|storage|sd\s*card)\s*(error|fail|failure|abnormal|exception|unformatted)|no\s+(hdd|disk)\b|hdd\s+not\s+found|disk\s+no\s+exist",
     "hdd_error", "critical", "Disk error"),
    (r"video\s*(signal\s*)?loss|video\s*lost|signal\s*loss|no\s+video", "video_loss", "critical", "Video loss"),
    (r"video\s*tamper|tamper(ing)?\s*(detect|alarm)?|video\s*blind|camera\s*mask|lens\s*(covered|blocked)|scene\s*change",
     "tamper", "warning", "Camera tampering"),
    (r"ip\s*(address\s*)?conflict", "ip_conflict", "critical", "IP address conflict"),
    (r"network\s*(is\s*)?(disconnect(ed)?|down|broken|abnormal|lost)|net(work)?\s*cable\s*(disconnect|unplug)|offline\s+alarm|network\s+exception",
     "network_disconnected", "critical", "Network disconnected"),
    (r"illegal\s*(login|access)|login\s*(fail(ed|ure)?|lock(ed)?)|invalid\s*(login|password|user)|brute\s*force|unauthori[sz]ed\s+(login|access)",
     "illegal_login", "warning", "Illegal login attempt"),
    (r"(was|is|has\s+been|got)\s+disconnected|disconnected\s+from|went\s+offline|is\s+(now\s+)?offline|lost\s+contact|is\s+unreachable|"
     r"(is|went)\s+down\b|heartbeat\s+(missed|lost)|offline\b", "device_offline", "critical", "Device offline"),
    (r"reconnected|is\s+back\s+online|back\s+up\b|came\s+(back\s+)?online|is\s+(now\s+)?online|(is|went)\s+up\b|(was|is)\s+connected|"
     r"recovered|restored|\bonline\b", "device_online", "info", "Device back online"),
    (r"line\s*crossing|intrusion|region\s*(entrance|exiting)|tripwire|perimeter|loitering", "intrusion", "warning", "Intrusion / line crossing"),
    (r"alarm\s*input|i/o\s*alarm|external\s*alarm|local\s*alarm", "alarm_input", "warning", "Alarm input"),
    (r"motion\s*detect(ion|ed)?|motion\s*alarm|\bmotion\b|\bvmd\b|human\s*detect|vehicle\s*detect|face\s*detect|smd\b",
     "motion", "info", "Motion detection"),
    (r"reboot(ed)?|restart(ed)?|power\s*(on|up|fail(ure)?|loss|lost)|cold\s*start|ups\s+", "device_restart", "warning", "Device restart / power"),
    (r"firmware|upgrade\s+available|update\s+available|new\s+version", "firmware", "info", "Firmware / update"),
]
MAIL_RULES = [(re.compile(r, re.I), t, sev, title) for r, t, sev, title in MAIL_RULES]

BRAND_HINTS = [
    ("hikvision", r"hikvision|hik-?connect|EVENT TYPE:|CAMERA NAME\(NUM\)|ivms"),
    ("dahua", r"dahua|dmss|Alarm Event\s*:|Alarm Input Channel|Alarm Device Name|imou"),
    ("unifi", r"unifi|ui\.com|ubiquiti\s+network"),
    ("airmax", r"uisp|airmax|airos|unms|ubnt"),
    ("omada", r"omada"),
    ("tplink", r"tp-?link"),
    ("mikrotik", r"mikrotik|routeros|netwatch"),
    ("fortinet", r"forti(gate|os|net)"),
]
BRAND_HINTS = [(b, re.compile(r, re.I)) for b, r in BRAND_HINTS]

FIELD_PATTERNS = {
    "camera": [r"CAMERA NAME\(NUM\)\s*:\s*(.+)", r"Camera\s*Name\s*:\s*(.+)", r"Alarm\s+(?:Input\s+)?Channel(?:\s*No\.)?\s*:\s*(.+)",
               r"Channel\s*(?:No\.|Name|Number)?\s*:\s*(.+)"],
    "device_name": [r"DEVICE NAME\s*:\s*(.+)", r"Alarm Device Name\s*:\s*(.+)", r"Device\s*Name\s*:\s*(.+)", r"NVR\s*NAME\s*:\s*(.+)"],
    "device_serial": [r"DEVICE SERIAL(?: No\.)?\s*:\s*(.+)", r"(?:NVR|DVR|DEVICE|IPC)\s*S/N\s*:\s*(.+)", r"Serial(?:\s*No\.?|\s*Number)?\s*:\s*(.+)"],
    "event_time": [r"EVENT TIME\s*:\s*(.+)", r"Alarm (?:Start )?Time(?:\s*\([^)]*\))?\s*:\s*(.+)", r"Time\s*:\s*(.+)"],
    "event_type": [r"EVENT TYPE\s*:\s*(.+)", r"Alarm Event\s*:\s*(.+)", r"Event\s*:\s*(.+)"],
}
FIELD_PATTERNS = {k: [re.compile(p, re.I) for p in v] for k, v in FIELD_PATTERNS.items()}


def html_to_text(html):
    html = re.sub(r"(?is)<(script|style|head).*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h\d|table)>", "\n", html)
    html = re.sub(r"(?i)</t[dh]>", " ", html)
    text = unescape(re.sub(r"<[^>]+>", "", html))
    lines = [re.sub(r"[ \t\xa0]+", " ", l).strip() for l in text.splitlines()]
    return "\n".join(l for l in lines if l)


def _decode_part(part):
    data = part.get_payload(decode=True) or b""
    for cs in (part.get_content_charset(), "utf-8", "gb18030", "latin-1"):
        if not cs:
            continue
        try:
            return data.decode(cs)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", "replace")


def parse_mail(raw):
    """Parse raw RFC822 bytes -> dict(subject, from, text, images=[(name, bytes)])"""
    msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    from email.header import decode_header, make_header
    def hdr(name):
        v = msg.get(name, "")
        try:
            return str(make_header(decode_header(v))).strip()
        except Exception:
            return str(v).strip()
    text, html, images = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        fname = part.get_filename() or ""
        disp = (part.get("Content-Disposition") or "").lower()
        if ctype.startswith("image/") or fname.lower().endswith((".jpg", ".jpeg", ".png")) or \
                (ctype == "application/octet-stream" and fname.lower().endswith((".jpg", ".jpeg"))):
            data = part.get_payload(decode=True)
            if data:
                images.append((fname or "snapshot.jpg", data))
        elif ctype == "text/plain" and "attachment" not in disp:
            text += _decode_part(part) + "\n"
        elif ctype == "text/html" and "attachment" not in disp:
            html += _decode_part(part) + "\n"
    if not text.strip() and html:
        text = html_to_text(html)
    text = text.replace("\r\n", "\n").strip()
    return {"subject": hdr("Subject"), "from": hdr("From"), "text": text[:20000], "images": images}


def classify_mail(subject, text, host=None):
    blob = f"{subject}\n{text[:6000]}"
    kind, severity, title = "other", "warning", None
    # Prefer the subject; fall back to the body
    for scope in (subject, blob):
        for rx, t, sev, ttl in MAIL_RULES:
            if rx.search(scope):
                kind, severity, title = t, sev, ttl
                break
        if title:
            break
    brand = None
    for b, rx in BRAND_HINTS:
        if rx.search(blob):
            brand = b
            break
    if not brand and host and host.get("device_type") not in (None, "generic"):
        brand = host["device_type"]
    fields = {}
    for key, pats in FIELD_PATTERNS.items():
        for rx in pats:
            m = rx.search(text)
            if m:
                fields[key] = m.group(1).strip()[:120]
                break
    if kind in ("device_offline", "device_online"):
        # "[UniFi] AP Lobby-U6 was disconnected", "EAP245-Pool is disconnected", "Netwatch: 192.168.88.20 is DOWN"
        dm = re.search(r"(?:\b(?:AP|Switch|Gateway|Device|EAP|Router|Client)\s+)?\[?([\w.:\-]{2,64})\]?\s+(?:was|is|has been|went)\s+"
                       r"(?:disconnected|offline|down|lost|connected|online|up|reconnected|adopted)", subject or "", re.I) or \
            re.search(r"\[?([\w.:\-]{2,64}?)(?::[0-9A-F]{2}(?:-[0-9A-F]{2}){5})?\]?\s+(?:was|is)\s+(?:disconnected|offline)", text[:2000], re.I)
        if dm:
            fields["device"] = dm.group(1)
    if not title:
        title = subject or "E-mail from device"
    return {"type": kind, "severity": severity, "title": title, "brand": brand, "fields": fields}


_rx_rate = {}


def process_incoming_mail(raw, peer_ip, mail_from, rcpts, auth_user=None):
    s = get_settings()
    m = parse_mail(raw)
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE host=? ORDER BY id LIMIT 1", (peer_ip,)).fetchone()
    host = dict(row) if row else None
    cl = classify_mail(m["subject"], m["text"], host)
    f = cl["fields"]
    source_label = host["name"] if host else (f.get("device_name") or peer_ip)
    if f.get("camera") and cl["type"] in ("motion", "video_loss", "tamper", "intrusion", "alarm_input", "other"):
        title = f"{cl['title']} - {f['camera']}"
    elif f.get("device"):
        title = f"{cl['title']} - {f['device']}"
    else:
        title = cl["title"]
    details = {"type": cl["type"], "brand": cl["brand"], "source_ip": peer_ip, "mail_from": mail_from,
               "from": m["from"], "to": rcpts, "subject": m["subject"], "fields": f,
               "body": m["text"][:3000], "auth_user": auth_user, "source_label": source_label}
    now = time.time()
    eid = add_event("mail", cl["type"], cl["severity"], host, title, m["text"][:500], details, [], ts=now)
    saved = []
    for i, (name, data) in enumerate(m["images"][:5]):
        if len(data) > 3 * 1024 * 1024:
            continue
        ext = ".png" if name.lower().endswith(".png") else ".jpg"
        fn = f"ev{eid}_{i}{ext}"
        with open(os.path.join(SNAP_DIR, fn), "wb") as fh:
            fh.write(data)
        saved.append(fn)
    if saved:
        with _db_lock, db() as c:
            c.execute("UPDATE events SET attachments=? WHERE id=?", (json.dumps(saved), eid))
    log.info("Mail from %s (%s): %s [%s/%s] %d image(s)", peer_ip, cl["brand"], m["subject"], cl["type"],
             cl["severity"], len(saved))
    # forward?
    if SEVERITY_RANK[cl["severity"]] < SEVERITY_RANK.get(s["rx_forward_min"], 2) and cl["type"] != "test":
        return eid
    # per sender + type + subject: one controller (UniFi/Omada) reports many APs from one IP
    key = (peer_ip, cl["type"], re.sub(r"\d{1,2}[:/.-]\d{1,2}([:/.-]\d{2,4})?", "", m["subject"] or "")[:120])
    if cl["type"] != "test" and now - _rx_rate.get(key, 0) < s["rx_rate_limit"]:
        log.info("Rate limited forward for %s", key)
        return eid
    _rx_rate[key] = now
    icon = {"critical": "🔴", "warning": "🟠", "info": "🔵"}[cl["severity"]]
    lines = [f"{icon} {title} [{s['site_name']}]", f"Sender: {source_label} ({peer_ip})"]
    if f.get("device_name") and f.get("device_name") != source_label:
        lines.append(f"Device: {f['device_name']}")
    if m["subject"] and m["subject"] != cl["title"]:
        lines.append(f"Subject: {m['subject']}")
    lines.append(fmt_ts(now))
    text = "\n".join(lines)
    alert = {"type": cl["type"], "title": title, "brand": cl["brand"], "source_ip": peer_ip,
             "from": m["from"], "subject": m["subject"], "fields": f, "attachments": len(saved)}
    payload = build_payload(s, "device_alert", eid, host, None, severity=cl["severity"], message=text, alert=alert, ts=now)
    notify(f"[{s['site_name']}] {title}", text, payload,
           photo=os.path.join(SNAP_DIR, saved[0]) if saved else None)
    return eid


class _MailHandler:
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        s = get_settings()
        if not ip_allowed(session.peer[0], s["rx_allowed_nets"]):
            log.warning("SMTP: rejected sender IP %s (not in allowed networks)", session.peer[0])
            return "550 5.7.1 Sender network not allowed"
        if s["rx_require_auth"] and not session.authenticated:
            return "530 5.7.0 Authentication required"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        peer = session.peer[0]
        if peer.startswith("::ffff:"):
            peer = peer[7:]
        user = None
        if session.auth_data is not None:
            user = getattr(session.auth_data, "login", None)
            user = user.decode(errors="replace") if isinstance(user, bytes) else user
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, process_incoming_mail, envelope.original_content or envelope.content, peer,
                envelope.mail_from, list(envelope.rcpt_tos), user)
        except Exception:
            log.exception("Failed to process incoming mail")
        return "250 OK Message accepted"


def ip_allowed(ip, nets):
    try:
        addr = ipaddress.ip_address(ip.replace("::ffff:", ""))
    except ValueError:
        return False
    for n in [x.strip() for x in (nets or "").split(",") if x.strip()]:
        try:
            if addr in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def _tls_context():
    cert, key = os.path.join(DATA_DIR, "smtp_cert.pem"), os.path.join(DATA_DIR, "smtp_key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        if not shutil.which("openssl"):
            raise RuntimeError("openssl not found - cannot create self-signed certificate for STARTTLS/SSL")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", "/CN=pingmonitor", "-keyout", key, "-out", cert],
                       check=True, capture_output=True)
        os.chmod(key, 0o600)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1   # old cameras/NVRs only speak TLS 1.0
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.load_cert_chain(cert, key)
    return ctx


class SmtpReceiver:
    def __init__(self):
        self.ctrl = None
        self.error = None
        self.lock = threading.Lock()

    def status(self):
        if self.ctrl:
            s = get_settings()
            return f"running on {s['rx_host']}:{s['rx_port']} ({s['rx_security']})"
        return f"error: {self.error}" if self.error else "stopped"

    def restart(self):
        with self.lock:
            self.stop()
            s = get_settings()
            if not s["rx_enabled"]:
                return
            try:
                from aiosmtpd.controller import Controller
                from aiosmtpd.smtp import AuthResult

                def authenticator(server, session, envelope, mechanism, auth_data):
                    st = get_settings()
                    login = getattr(auth_data, "login", b"") or b""
                    pw = getattr(auth_data, "password", b"") or b""
                    login = login.decode(errors="replace") if isinstance(login, bytes) else str(login)
                    pw = pw.decode(errors="replace") if isinstance(pw, bytes) else str(pw)
                    if not st["rx_require_auth"]:
                        return AuthResult(success=True, handled=False)   # quirky devices that always AUTH: accept
                    ok = hmac.compare_digest(login, st["rx_user"]) and bool(st["rx_password"]) and \
                        hmac.compare_digest(pw, st["rx_password"])
                    if not ok:
                        log.warning("SMTP: bad login '%s' from %s", login, session.peer[0])
                    return AuthResult(success=ok, handled=False)   # handled=False -> server replies 235/535

                kw = dict(hostname=s["rx_host"], port=int(s["rx_port"]), authenticator=authenticator,
                          auth_required=False, auth_require_tls=False, data_size_limit=15 * 1024 * 1024,
                          decode_data=False, server_hostname="pingmonitor", ident=f"Wirewave PingMonitor {VERSION}")
                if s["rx_security"] == "starttls":
                    kw.update(tls_context=_tls_context(), require_starttls=False)
                elif s["rx_security"] == "ssl":
                    kw.update(ssl_context=_tls_context())
                self.ctrl = Controller(_MailHandler(), **kw)
                self.ctrl.start()
                self.error = None
                log.info("SMTP receiver %s", self.status())
            except Exception as e:
                self.ctrl = None
                self.error = str(e)
                log.error("SMTP receiver failed to start: %s", e)

    def stop(self):
        if self.ctrl:
            try:
                self.ctrl.stop()
            except Exception:
                pass
            self.ctrl = None


RECEIVER = SmtpReceiver()


# ----------------------------------------------------------------------------- SNMP (polling + traps)
# Pure python: pysnmp (lextudio, 7.x, asyncio). Everything runs in one background asyncio thread.
O_SYS = {"sysDescr": "1.3.6.1.2.1.1.1.0", "sysObjectID": "1.3.6.1.2.1.1.2.0", "sysUpTime": "1.3.6.1.2.1.1.3.0",
         "sysName": "1.3.6.1.2.1.1.5.0", "sysLocation": "1.3.6.1.2.1.1.6.0"}
O_IF = {"descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3", "speed": "1.3.6.1.2.1.2.2.1.5",
        "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8", "in": "1.3.6.1.2.1.2.2.1.10",
        "inerr": "1.3.6.1.2.1.2.2.1.14", "out": "1.3.6.1.2.1.2.2.1.16", "outerr": "1.3.6.1.2.1.2.2.1.20",
        "name": "1.3.6.1.2.1.31.1.1.1.1", "hcin": "1.3.6.1.2.1.31.1.1.1.6", "hcout": "1.3.6.1.2.1.31.1.1.1.10",
        "highspeed": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18"}
O_HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"                    # hrProcessorLoad (per core, %)
O_HR_STORE = {"type": "1.3.6.1.2.1.25.2.3.1.2", "descr": "1.3.6.1.2.1.25.2.3.1.3", "units": "1.3.6.1.2.1.25.2.3.1.4",
              "size": "1.3.6.1.2.1.25.2.3.1.5", "used": "1.3.6.1.2.1.25.2.3.1.6"}
HR_RAM, HR_DISK = "1.3.6.1.2.1.25.2.1.2", "1.3.6.1.2.1.25.2.1.4"
O_UCD = {"memTotal": "1.3.6.1.4.1.2021.4.5.0", "memAvail": "1.3.6.1.4.1.2021.4.6.0", "memBuf": "1.3.6.1.4.1.2021.4.14.0",
         "memCached": "1.3.6.1.4.1.2021.4.15.0", "cpuIdle": "1.3.6.1.4.1.2021.11.11.0"}  # net-snmp (UniFi/airOS/EdgeOS/Linux)
O_MT = {"temp": "1.3.6.1.4.1.14988.1.1.3.10.0", "cpu_temp": "1.3.6.1.4.1.14988.1.1.3.11.0",
        "voltage": "1.3.6.1.4.1.14988.1.1.3.8.0"}                       # MIKROTIK-MIB (RouterOS 6, x10)
O_MT_GAUGE = {"name": "1.3.6.1.4.1.14988.1.1.3.100.1.2", "value": "1.3.6.1.4.1.14988.1.1.3.100.1.3",
              "unit": "1.3.6.1.4.1.14988.1.1.3.100.1.4"}                 # mtxrGaugeTable (RouterOS 7)
O_MT_WLCLIENTS = "1.3.6.1.4.1.14988.1.1.1.3.1.6"                         # mtxrWlApClientCount
O_MT_CAPS = "1.3.6.1.4.1.14988.1.1.1.6.0"                                # mtxrWlCMRegClientCount (CAPsMAN)
O_UBNT_VAP_STA = "1.3.6.1.4.1.41112.1.6.1.2.1.8"                         # UBNT-UniFi-MIB unifiVapNumStations
O_UBNT_AIRMAX_STA = "1.3.6.1.4.1.41112.1.4.5.1.15"                       # UBNT-AirMAX-MIB ubntWlStatStaCount
O_HIK_DISK = "1.3.6.1.4.1.39165.1.20"   # HIK-DEVICE-MIB area seen on some NVRs - read best-effort, firmware dependent
IFTYPE_PHYS = {6, 62, 69, 117, 71}       # ethernet, fastEther, gigabit..., ieee80211
TRAP_NAMES = {"1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart", "1.3.6.1.6.3.1.1.5.3": "linkDown",
              "1.3.6.1.6.3.1.1.5.4": "linkUp", "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
              "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss"}
V1_GENERIC = ["coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss", "enterpriseSpecific"]
TRAP_INFO = {"coldStart": ("critical", "Device rebooted (coldStart trap)"), "warmStart": ("warning", "Device restarted (warmStart trap)"),
             "linkDown": ("critical", "Interface down (linkDown trap)"), "linkUp": ("info", "Interface up (linkUp trap)"),
             "authenticationFailure": ("warning", "SNMP authentication failure"), "egpNeighborLoss": ("warning", "EGP neighbor loss")}
O_SNMPTRAPOID, O_IFINDEX, O_IFDESCR_PFX, O_IFNAME_PFX = "1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.2.1.2.2.1.1.", "1.3.6.1.2.1.2.2.1.2.", "1.3.6.1.2.1.31.1.1.1.1."
SNMP_DEFAULT_CFG = {"enabled": 0, "version": "2c", "community": "", "port": 161, "user": "", "auth_proto": "SHA",
                    "auth_key": "", "priv_proto": "AES", "priv_key": "", "ifaces": None, "alert_ifaces": None}


def host_snmp_cfg(h):
    cfg = dict(SNMP_DEFAULT_CFG)
    try:
        cfg.update(json.loads(h.get("snmp") or "{}"))
    except (TypeError, ValueError):
        pass
    return cfg


def fmt_bps(v):
    if v is None:
        return "-"
    for unit, div in (("Gb/s", 1e9), ("Mb/s", 1e6), ("kb/s", 1e3)):
        if v >= div:
            return f"{v / div:.1f} {unit}"
    return f"{v:.0f} b/s"


def _snmp_err(ei):
    t = str(ei)
    if "digest" in t.lower() or "unknown user" in t.lower() or "StatusInformation" in t:
        return "SNMPv3 authentication failed (check user / auth key / protocols)"
    if "decrypt" in t.lower() or "ciphering" in t.lower():
        return "SNMPv3 privacy (encryption) failed - check priv key / protocol (needs the 'cryptography' package)"
    if "timeout" in t.lower():
        return "no SNMP response (timeout) - check IP, port, community / v3 user and that SNMP is enabled on the device"
    return t


def _snmp_val(v):
    """pysnmp value -> python (int / str / None for noSuchObject etc.)"""
    cls = v.__class__.__name__
    if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return None
    if cls in ("ObjectIdentifier", "ObjectName"):
        return str(v)
    if cls in ("OctetString", "DisplayString", "Opaque", "IpAddress"):
        if cls == "IpAddress":
            return ".".join(str(b) for b in bytes(v.asOctets()))
        b = bytes(v.asOctets())
        try:
            return b.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return b.hex(":")
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


class SnmpService:
    """Background asyncio loop: polls hosts with SNMP enabled and runs the trap listener."""

    def __init__(self):
        self.loop = None
        self.thread = None
        self.engine = None
        self.trap_transport = None
        self.trap_status = "disabled"
        self.counters = {}       # host_id -> {ifname: (ts, in, out, inerr, outerr, hc)}
        self.last_poll = {}      # host_id -> ts
        self.cpu_high = {}       # host_id -> consecutive high polls
        self.available = True
        try:
            import pysnmp  # noqa: F401
        except ImportError:
            self.available = False

    # --- lifecycle
    def start(self):
        if not self.available:
            log.warning("pysnmp not installed - SNMP disabled (pip install pysnmp)")
            return
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True, name="snmp")
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
        self.engine = SnmpEngine()
        self.loop.create_task(self._scheduler())
        self.loop.run_until_complete(self._trap_restart())
        self.loop.run_forever()

    def call(self, coro, timeout=30):
        """Run a coroutine on the SNMP loop from another thread (web requests)."""
        if not self.loop:
            raise RuntimeError("SNMP not available (pysnmp missing)")
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def restart_traps(self):
        if self.loop:
            self.call(self._trap_restart(), 10)

    # --- polling
    async def _scheduler(self):
        await asyncio.sleep(3)
        while True:
            try:
                s = get_settings()
                if s["snmp_enabled"]:
                    with db() as c:
                        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts WHERE enabled=1 AND snmp LIKE '%\"enabled\": 1%'")]
                    now = time.time()
                    due = [h for h in hosts if now - self.last_poll.get(h["id"], 0) >= max(30, s["snmp_interval"]) - 2]
                    for h in due:
                        self.last_poll[h["id"]] = now
                    if due:
                        await asyncio.gather(*(self.poll_host(h, s) for h in due), return_exceptions=True)
            except Exception:
                log.exception("SNMP scheduler error")
            await asyncio.sleep(10)

    async def _auth(self, cfg):
        from pysnmp.hlapi.v3arch import asyncio as h
        if cfg["version"] == "3":
            ap = {"none": h.usmNoAuthProtocol, "MD5": h.usmHMACMD5AuthProtocol, "SHA": h.usmHMACSHAAuthProtocol,
                  "SHA256": h.usmHMAC192SHA256AuthProtocol}.get(cfg["auth_proto"], h.usmHMACSHAAuthProtocol)
            pp = {"none": h.usmNoPrivProtocol, "DES": h.usmDESPrivProtocol, "AES": h.usmAesCfb128Protocol,
                  "AES256": h.usmAesCfb256Protocol}.get(cfg["priv_proto"], h.usmAesCfb128Protocol)
            if cfg["auth_proto"] == "none" or not cfg["auth_key"]:
                return h.UsmUserData(cfg["user"])
            if cfg["priv_proto"] == "none" or not cfg["priv_key"]:
                return h.UsmUserData(cfg["user"], cfg["auth_key"], authProtocol=ap)
            return h.UsmUserData(cfg["user"], cfg["auth_key"], cfg["priv_key"], authProtocol=ap, privProtocol=pp)
        return h.CommunityData(cfg["community"] or "public", mpModel=0 if cfg["version"] == "1" else 1)

    async def _get(self, auth, target, oids):
        from pysnmp.hlapi.v3arch import asyncio as h
        ei, es, _, vbs = await h.get_cmd(self.engine, auth, target, h.ContextData(),
                                         *[h.ObjectType(h.ObjectIdentity(o)) for o in oids], lookupMib=False)
        if ei:
            raise RuntimeError(_snmp_err(ei))
        if es:
            # v1 agents fail the whole GET on one missing OID: fall back to one by one
            out = {}
            for o in oids:
                ei2, es2, _, vb2 = await h.get_cmd(self.engine, auth, target, h.ContextData(),
                                                   h.ObjectType(h.ObjectIdentity(o)), lookupMib=False)
                if not ei2 and not es2:
                    out[o] = _snmp_val(vb2[0][1])
            return out
        return {str(n): _snmp_val(v) for n, v in vbs}

    async def _walk(self, auth, target, base, limit=512):
        from pysnmp.hlapi.v3arch import asyncio as h
        out = {}
        async for ei, es, _, vbs in h.bulk_walk_cmd(self.engine, auth, target, h.ContextData(), 0, 25,
                                                   h.ObjectType(h.ObjectIdentity(base)), lexicographicMode=False,
                                                   lookupMib=False):
            if ei:
                raise RuntimeError(str(ei))
            if es:
                break
            for n, v in vbs:
                n = str(n)
                if not n.startswith(base + "."):
                    return out
                out[n[len(base) + 1:]] = _snmp_val(v)
            if len(out) >= limit:
                break
        return out

    async def query(self, h, cfg, s=None):
        """One full SNMP read of a device. Returns dict (raises on timeout/auth error)."""
        from pysnmp.hlapi.v3arch import asyncio as hl
        s = s or get_settings()
        auth = await self._auth(cfg)
        target = await hl.UdpTransportTarget.create((h["host"], int(cfg["port"] or 161)),
                                                    timeout=max(1, s["snmp_timeout"]), retries=1)
        sysv = await self._get(auth, target, list(O_SYS.values()))
        if all(v is None for v in sysv.values()):
            raise RuntimeError("no answer to system MIB")
        d = {k: sysv.get(o) for k, o in O_SYS.items()}
        d["ts"] = time.time()
        # interfaces
        cols = {}
        for k, o in O_IF.items():
            try:
                cols[k] = await self._walk(auth, target, o)
            except Exception:
                cols[k] = {}
        ifs = []
        for idx in sorted(cols["descr"] or cols["name"], key=lambda x: int(x) if x.isdigit() else 0):
            g = lambda k: cols.get(k, {}).get(idx)
            hc = g("hcin") is not None and g("hcout") is not None
            ifs.append({"index": int(idx) if idx.isdigit() else idx, "name": g("name") or g("descr") or f"if{idx}",
                        "descr": g("descr"), "alias": g("alias") or "", "type": g("type"),
                        "speed": (g("highspeed") * 1_000_000) if g("highspeed") else g("speed"),
                        "admin": {1: "up", 2: "down", 3: "testing"}.get(g("admin"), g("admin")),
                        "oper": {1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}.get(g("oper"), g("oper")),
                        "in": g("hcin") if hc else g("in"), "out": g("hcout") if hc else g("out"), "hc": hc,
                        "inerr": g("inerr") or 0, "outerr": g("outerr") or 0})
        d["ifaces"] = ifs
        # CPU / memory (HOST-RESOURCES, then UCD-SNMP)
        try:
            loads = [v for v in (await self._walk(auth, target, O_HR_CPU)).values() if isinstance(v, int)]
        except Exception:
            loads = []
        d["cpu"] = round(sum(loads) / len(loads), 1) if loads else None
        d["cpu_cores"] = len(loads) or None
        d["mem_pct"], d["storage"] = None, []
        try:
            st = {k: await self._walk(auth, target, o) for k, o in O_HR_STORE.items()}
            for i, typ in st["type"].items():
                size, used, units = st["size"].get(i), st["used"].get(i), st["units"].get(i) or 1
                if not size:
                    continue
                pct = round(100.0 * (used or 0) / size, 1)
                if typ == HR_RAM and d["mem_pct"] is None:
                    d["mem_pct"] = pct
                elif typ == HR_DISK:
                    d["storage"].append({"name": st["descr"].get(i), "pct": pct, "size_mb": round(size * units / 1048576)})
        except Exception:
            pass
        if d["cpu"] is None or d["mem_pct"] is None:
            try:
                u = await self._get(auth, target, list(O_UCD.values()))
                uv = {k: u.get(o) for k, o in O_UCD.items()}
                if d["cpu"] is None and isinstance(uv["cpuIdle"], int):
                    d["cpu"] = float(100 - uv["cpuIdle"])
                if d["mem_pct"] is None and uv["memTotal"]:
                    free = (uv["memAvail"] or 0) + (uv["memBuf"] or 0) + (uv["memCached"] or 0)
                    d["mem_pct"] = round(100.0 * (uv["memTotal"] - min(free, uv["memTotal"])) / uv["memTotal"], 1)
            except Exception:
                pass
        # brand extras
        oid = d.get("sysObjectID") or ""
        descr = (d.get("sysDescr") or "").lower()
        brand = h.get("device_type") or "generic"
        d["extra"] = {}
        try:
            if brand == "mikrotik" or oid.startswith("1.3.6.1.4.1.14988") or "routeros" in descr:
                mt = await self._get(auth, target, list(O_MT.values()))
                for k, o in O_MT.items():
                    if isinstance(mt.get(o), int) and mt[o] > 0:
                        d["extra"][k] = mt[o] / 10.0
                gn = await self._walk(auth, target, O_MT_GAUGE["name"], 64)
                if gn:
                    gv = await self._walk(auth, target, O_MT_GAUGE["value"], 64)
                    for i, name in gn.items():
                        v = gv.get(i)
                        if isinstance(v, int):
                            key = {"temperature": "temp", "cpu-temperature": "cpu_temp", "voltage": "voltage"}.get(str(name), str(name))
                            d["extra"][key] = v / 10.0 if key == "voltage" else v
                wl = await self._walk(auth, target, O_MT_WLCLIENTS, 64)
                caps = (await self._get(auth, target, [O_MT_CAPS])).get(O_MT_CAPS)
                n = sum(v for v in wl.values() if isinstance(v, int)) + (caps if isinstance(caps, int) else 0)
                if wl or isinstance(caps, int):
                    d["extra"]["wireless_clients"] = n
            elif brand in ("unifi", "airmax") or oid.startswith("1.3.6.1.4.1.41112") or "ubnt" in descr or "unifi" in descr:
                for base in (O_UBNT_VAP_STA, O_UBNT_AIRMAX_STA):
                    w = await self._walk(auth, target, base, 64)
                    if w:
                        d["extra"]["wireless_clients"] = sum(v for v in w.values() if isinstance(v, int))
                        break
            elif brand == "hikvision" or oid.startswith("1.3.6.1.4.1.39165"):
                w = await self._walk(auth, target, O_HIK_DISK, 64)
                if w:
                    d["extra"]["hik_vendor_values"] = len(w)   # vendor MIB answers; details vary by firmware
        except Exception as e:
            log.debug("SNMP extras for %s: %s", h["host"], e)
        return d

    async def poll_host(self, h, s):
        cfg = host_snmp_cfg(h)
        with db() as c:
            row = c.execute("SELECT data FROM snmp_state WHERE host_id=?", (h["id"],)).fetchone()
        prev = json.loads(row["data"]) if row else {}
        try:
            d = await self.query(h, cfg, s)
        except Exception as e:
            prev.update(error=str(e)[:200], error_ts=time.time())
            with _db_lock, db() as c:
                c.execute("INSERT OR REPLACE INTO snmp_state(host_id, ts, data) VALUES(?,?,?)",
                          (h["id"], prev.get("ts") or 0, json.dumps(prev)))
            log.info("SNMP %s (%s): %s", h["name"], h["host"], e)
            return
        now = d["ts"]
        # rates
        cnt = self.counters.setdefault(h["id"], {})
        for i in d["ifaces"]:
            p = cnt.get(i["name"])
            i["in_bps"] = i["out_bps"] = None
            if p and isinstance(i["in"], int) and isinstance(i["out"], int) and now > p[0]:
                dt = now - p[0]
                wrap = 2 ** 64 if i["hc"] else 2 ** 32
                din, dout = (i["in"] - p[1]) % wrap, (i["out"] - p[2]) % wrap
                if din < wrap / 4 and dout < wrap / 4:
                    i["in_bps"], i["out_bps"] = round(din * 8 / dt), round(dout * 8 / dt)
                i["err_delta"] = max(0, i["inerr"] - p[3]) + max(0, i["outerr"] - p[4])
            cnt[i["name"]] = (now, i["in"], i["out"], i["inerr"], i["outerr"])
        # default selection: physical interfaces that are up (max 8)
        if cfg["ifaces"] is None:
            cfg["ifaces"] = [i["name"] for i in d["ifaces"] if i["type"] in IFTYPE_PHYS and i["oper"] == "up"][:8]
            cfg["alert_ifaces"] = list(cfg["ifaces"])
            with _db_lock, db() as c:
                c.execute("UPDATE hosts SET snmp=? WHERE id=?", (json.dumps(cfg), h["id"]))
        d.pop("error", None)
        self._alerts(h, s, cfg, prev, d)
        with _db_lock, db() as c:
            c.execute("INSERT OR REPLACE INTO snmp_state(host_id, ts, data) VALUES(?,?,?)", (h["id"], now, json.dumps(d)))
            graphed = {i["name"]: [i["in_bps"], i["out_bps"]] for i in d["ifaces"] if i["name"] in (cfg["ifaces"] or [])}
            c.execute("INSERT INTO snmp_samples(host_id, ts, cpu, mem, ifs) VALUES(?,?,?,?,?)",
                      (h["id"], now, d["cpu"], d["mem_pct"], json.dumps(graphed)))

    def _alerts(self, h, s, cfg, prev, d):
        if not prev.get("ts"):
            return
        found = []
        # reboot: sysUpTime went backwards (ignore the 497-day 32-bit wrap)
        pu, nu = prev.get("sysUpTime"), d.get("sysUpTime")
        if s["snmp_alert_reboot"] and isinstance(pu, int) and isinstance(nu, int) and nu + 100 < pu and pu < 4_200_000_000:
            found.append(("snmp_reboot", "warning", "Device rebooted",
                          f"uptime is now {fmt_dur(nu / 100)} (was {fmt_dur(pu / 100)})", {}))
        # interface oper status changes on watched interfaces
        if s["snmp_alert_ifdown"]:
            old = {i["name"]: i.get("oper") for i in prev.get("ifaces", [])}
            for i in d["ifaces"]:
                if i["name"] not in (cfg.get("alert_ifaces") or []) or i["name"] not in old:
                    continue
                label = i["name"] + (f" ({i['alias']})" if i["alias"] else "")
                if old[i["name"]] == "up" and i["oper"] != "up":
                    found.append(("snmp_if_down", "critical", f"Interface {i['name']} down", f"{label} is {i['oper']}",
                                  {"interface": i["name"], "ifIndex": i["index"], "oper": i["oper"]}))
                elif old[i["name"]] != "up" and i["oper"] == "up":
                    found.append(("snmp_if_up", "info", f"Interface {i['name']} up", f"{label} is up again",
                                  {"interface": i["name"], "ifIndex": i["index"], "oper": "up"}))
        # CPU high (2 polls in a row), recovered below threshold-10
        thr = s["snmp_cpu_threshold"]
        if thr and isinstance(d.get("cpu"), (int, float)):
            n = self.cpu_high.get(h["id"], 0)
            if d["cpu"] >= thr:
                n += 1
                if n == 2:
                    found.append(("snmp_cpu_high", "warning", f"High CPU {d['cpu']:.0f}%",
                                  f"CPU load {d['cpu']:.0f}% (threshold {thr}%)", {"cpu": d["cpu"], "threshold": thr}))
            elif d["cpu"] < thr - 10:
                if n >= 2:
                    found.append(("snmp_cpu_ok", "info", f"CPU back to {d['cpu']:.0f}%", "CPU load normal again", {"cpu": d["cpu"]}))
                n = 0
            self.cpu_high[h["id"]] = n
        for kind, sev, title, msg, extra in found:
            snmp_event(h, s, kind, sev, title, msg, extra, source_ip=h["host"])

    # --- traps
    async def _trap_restart(self):
        if self.trap_transport:
            self.trap_transport.close()
            self.trap_transport = None
        s = get_settings()
        if not s["trap_enabled"]:
            self.trap_status = "disabled"
            return
        svc = self

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    svc.handle_trap(data, addr[0])
                except Exception:
                    log.exception("SNMP trap decode failed from %s", addr[0])

        try:
            self.trap_transport, _ = await self.loop.create_datagram_endpoint(
                Proto, local_addr=(s["trap_host"], int(s["trap_port"])))
            self.trap_status = f"listening on udp {s['trap_host']}:{s['trap_port']}"
            log.info("SNMP trap receiver %s", self.trap_status)
        except OSError as e:
            self.trap_status = f"error: {e}"
            log.error("SNMP trap receiver could not start: %s", e)

    def handle_trap(self, data, peer_ip):
        from pyasn1.codec.ber import decoder
        from pysnmp.proto import api
        s = get_settings()
        peer_ip = peer_ip.removeprefix("::ffff:")
        if not ip_allowed(peer_ip, s["rx_allowed_nets"]):
            log.warning("SNMP trap from %s ignored (not in allowed networks)", peer_ip)
            return
        ver = int(api.decodeMessageVersion(data))
        if ver not in api.PROTOCOL_MODULES:
            log.info("SNMP trap version %s from %s not supported (v1/v2c only)", ver, peer_ip)
            return
        pm = api.PROTOCOL_MODULES[ver]
        msg, _ = decoder.decode(data, asn1Spec=pm.Message())
        community = str(pm.apiMessage.get_community(msg))
        allowed = [x.strip() for x in s["trap_community"].split(",") if x.strip()]
        if allowed and community not in allowed:
            log.warning("SNMP trap from %s: wrong community", peer_ip)
            return
        pdu = pm.apiMessage.get_pdu(msg)
        vbs, trap = [], None
        if ver == api.SNMP_VERSION_1:
            if not pdu.isSameTypeWith(pm.TrapPDU()):
                return
            gen = int(pm.apiTrapPDU.get_generic_trap(pdu))
            ent = str(pm.apiTrapPDU.get_enterprise(pdu))
            trap = V1_GENERIC[gen] if 0 <= gen < 6 else f"{ent}.0.{int(pm.apiTrapPDU.get_specific_trap(pdu))}"
            vbs = [(str(o), _snmp_val(v)) for o, v in pm.apiTrapPDU.get_varbinds(pdu)]
        else:
            if not (pdu.isSameTypeWith(pm.SNMPv2TrapPDU()) or pdu.isSameTypeWith(pm.InformRequestPDU())):
                return
            vbs = [(str(o), _snmp_val(v)) for o, v in pm.apiPDU.get_varbinds(pdu)]
            toid = dict(vbs).get(O_SNMPTRAPOID) or "unknown"
            trap = TRAP_NAMES.get(toid, toid)
        process_trap(peer_ip, ver, community, trap, vbs, s)


def process_trap(peer_ip, ver, community, trap, vbs, s=None):
    s = s or get_settings()
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE host=? ORDER BY id LIMIT 1", (peer_ip,)).fetchone()
    host = dict(row) if row else None
    sev, title = TRAP_INFO.get(trap, ("warning", f"SNMP trap {trap}"))
    iface = None
    for o, v in vbs:
        if o.startswith(O_IFNAME_PFX) or o.startswith(O_IFDESCR_PFX):
            iface = v
        elif o.startswith(O_IFINDEX) and iface is None:
            iface = f"ifIndex {v}"
    if iface and trap in ("linkDown", "linkUp"):
        title = f"Interface {iface} {'down' if trap == 'linkDown' else 'up'} (trap)"
    shown = [(o, v) for o, v in vbs if not o.startswith("1.3.6.1.2.1.1.3.0") and o != O_SNMPTRAPOID][:12]
    msg = f"{trap} from {peer_ip}" + ("; " + "; ".join(f"{o}={v}" for o, v in shown) if shown else "")
    extra = {"trap": trap, "snmp_version": "1" if ver == 0 else "2c", "interface": iface,
             "varbinds": [{"oid": o, "value": v} for o, v in vbs[:30]]}
    log.info("SNMP trap %s from %s", trap, peer_ip)
    snmp_event(host or {"id": None, "name": None, "host": peer_ip}, s, "snmp_trap", sev, title, msg[:500], extra,
               source_ip=peer_ip, forward_min=s["trap_forward_min"])


def snmp_event(h, s, kind, sev, title, msg, extra, source_ip=None, forward_min=None):
    """Store + forward an SNMP poll alert or trap (event type snmp_*)."""
    host = h if h.get("id") else None
    now = time.time()
    details = dict(extra, type=kind, source_ip=source_ip)
    eid = add_event("snmp", kind, sev, host, title, msg, details, ts=now)
    if host is None:
        with _db_lock, db() as c:
            c.execute("UPDATE events SET host_ip=? WHERE id=?", (source_ip, eid))
    fm = forward_min or s["snmp_forward_min"]
    if SEVERITY_RANK.get(sev, 1) < SEVERITY_RANK.get(fm, 2):
        return eid
    key = ("snmp", source_ip, kind, extra.get("interface"), extra.get("trap"))
    if now - _rx_rate.get(key, 0) < min(60, s["rx_rate_limit"]) and kind not in ("snmp_if_up", "snmp_cpu_ok"):
        return eid
    _rx_rate[key] = now
    icon = {"critical": "🔴", "warning": "🟠", "info": "🔵"}.get(sev, "🔵")
    label = f"{h['name']} ({source_ip})" if h.get("name") else source_ip
    text = f"{icon} {title} [{s['site_name']}]\nDevice: {label}\n{msg}\n{fmt_ts(now)}"
    alert = {"type": kind, "title": title, "brand": (host or {}).get("device_type"), "source_ip": source_ip,
             "from": None, "subject": None, "fields": {k: v for k, v in extra.items() if k != "varbinds"},
             "attachments": 0}
    if kind == "snmp_trap":
        alert["varbinds"] = extra.get("varbinds")
    payload = build_payload(s, "snmp_trap" if kind == "snmp_trap" else "snmp_alert", eid, host, None,
                            severity=sev, message=text, alert=alert, ts=now)
    notify(f"[{s['site_name']}] {title}" + (f": {h['name']}" if h.get("name") else ""), text, payload)
    return eid


SNMP = SnmpService()


# ----------------------------------------------------------------------------- web app
app = Flask(__name__)
app.json.sort_keys = False  # keep API fields in a readable order
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_NAME="pingmon_session", PERMANENT_SESSION_LIFETIME=7 * 86400,
                  MAX_CONTENT_LENGTH=1024 * 1024)
_login_fail = {}


def client_ip():
    # Trust Cloudflare's header only when the request comes from the local cloudflared
    if request.remote_addr in ("127.0.0.1", "::1") and request.headers.get("CF-Connecting-IP"):
        return request.headers["CF-Connecting-IP"]
    return request.remote_addr


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def _csrf_protect():
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "") or "x"):
            abort(400, "Bad or missing CSRF token - reload the page and try again")


def role():
    return session.get("role")


def viewer_required(f):
    @wraps(f)
    def w(*a, **kw):
        if role() in ("admin", "viewer") or get_settings()["dashboard_access"] == "public":
            return f(*a, **kw)
        return redirect(url_for("login", next=request.path))
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if role() != "admin":
            if role() == "viewer":
                flash("The settings page needs the admin password.")
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return w


def api_auth(f):
    @wraps(f)
    def w(*a, **kw):
        tok = ""
        h = request.headers.get("Authorization", "")
        if h.lower().startswith("bearer "):
            tok = h[7:].strip()
        tok = tok or request.args.get("token", "")
        if not (tok and hmac.compare_digest(tok, get_settings()["api_token"])) and role() not in ("admin", "viewer"):
            return jsonify(error="unauthorized", hint="send Authorization: Bearer <API token> or ?token=<API token>"), 401
        return f(*a, **kw)
    return w


def mask(v):
    if not v:
        return ""
    return "•" * 8 + (v[-4:] if len(v) > 8 else "")


app.jinja_env.globals.update(csrf_token=csrf_token, DEVICE_TYPES=DEVICE_TYPES, mask=mask, role=role, fmt_bps=lambda v: fmt_bps(v))

CSS = """
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f1f4f9;color:#1c2b4a}
header{background:#0b2a55;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
header h1{font-size:19px;margin:0}header small{opacity:.75;font-weight:400}header a{color:#cfe1ff;text-decoration:none;margin-left:16px}
main{max-width:1240px;margin:0 auto;padding:20px}
.summary{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.pill{padding:9px 16px;border-radius:10px;color:#fff;font-weight:700;font-size:17px}
.g{background:#16a34a}.r{background:#dc2626}.a{background:#f59e0b}.p{background:#94a3b8}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:16px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:16px}
.dev{display:flex;align-items:center;gap:12px}
.dot{width:52px;height:52px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:12px}
.dev h3{margin:0;font-size:16px}.muted{color:#64748b;font-size:13px}
.badge{display:inline-block;padding:2px 7px;border-radius:6px;color:#fff;font-size:11px;font-weight:700;vertical-align:middle}
.sev-critical{background:#dc2626}.sev-warning{background:#f59e0b}.sev-info{background:#2563eb}
.stats{display:flex;gap:16px;margin:10px 0 6px;font-size:13px}.stats b{display:block;font-size:16px}
.chartbox{height:120px}h2{font-size:17px;margin:4px 0 12px}
.grp{font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:#475569;margin:18px 0 8px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle}
input,select,button{font-size:14px;padding:7px 9px;border-radius:8px;border:1px solid #cbd5e1;font-family:inherit}
button{background:#1d5fbf;color:#fff;border:none;cursor:pointer}button.sec{background:#e2e8f0;color:#1c2b4a}button.del{background:#fff;color:#dc2626;border:1px solid #fca5a5}
.flash{background:#e0ecff;padding:10px;border-radius:8px;margin-bottom:12px}
.form-grid{display:grid;grid-template-columns:220px 1fr;gap:8px 14px;align-items:center;max-width:820px}
.form-grid input[type=text],.form-grid input[type=password],.form-grid input[type=number],.form-grid input[type=url],.form-grid select{width:100%}
.nav a{display:inline-block;margin:0 6px 8px 0;padding:6px 10px;background:#fff;border-radius:8px;text-decoration:none;color:#1d5fbf;font-size:13px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.thumb{height:44px;border-radius:4px}a{color:#1d5fbf}.hint{font-size:12px;color:#64748b}
.snmpline{font-size:12.5px;color:#334155;margin:2px 0 8px}.lnk{display:inline-block;color:#fff;border-radius:6px;padding:1px 6px;margin:0 4px 3px 0;font-size:11.5px;font-weight:600}
.lnk small{font-weight:400;opacity:.9}.kv td:first-child{color:#64748b;width:160px}
code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:12px}
"""

LAYOUT = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
{% if refresh %}<meta http-equiv="refresh" content="{{ refresh }}">{% endif %}
<title>{{ s.site_name }} - Ping Monitor</title><style>""" + CSS + """</style>
{% if charts %}<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>{% endif %}</head><body>
<header><h1>Wirewave Ping Monitor <small>· {{ s.site_name }}</small></h1><div>
<a href="{{ url_for('index') }}">Dashboard</a>
{% if role() == 'admin' %}<a href="{{ url_for('settings') }}">Settings</a>{% endif %}
{% if role() %}<a href="{{ url_for('logout') }}">Logout ({{ role() }})</a>{% else %}<a href="{{ url_for('login') }}">Login</a>{% endif %}
</div></header><main>
{% with m = get_flashed_messages() %}{% for x in m %}<div class="flash">{{ x }}</div>{% endfor %}{% endwith %}
{{ body|safe }}</main></body></html>"""

CHART_JS = """<script>
const TZ = {{ s.timezone|tojson }};
function hhmm(v){return new Date(v).toLocaleTimeString('en-GB',{timeZone:TZ,hour:'2-digit',minute:'2-digit'});}
function drawChart(id, pts, big){
  const up=pts.filter(p=>p[1]).map(p=>({x:p[0]*1000,y:p[2]})), down=pts.filter(p=>!p[1]).map(p=>({x:p[0]*1000,y:0}));
  const now=Date.now(), from=now-24*3600e3;
  new Chart(document.getElementById(id),{data:{datasets:[
    {type:'line',label:'Latency (ms)',data:up,borderColor:'#1d5fbf',backgroundColor:'rgba(29,95,191,.12)',fill:true,pointRadius:0,borderWidth:1.4,tension:.2},
    {type:'scatter',label:'Failed ping',data:down,pointBackgroundColor:'#dc2626',pointBorderColor:'#dc2626',pointRadius:3}]},
   options:{animation:false,responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:!!big},tooltip:{callbacks:{title:(i)=>new Date(i[0].parsed.x).toLocaleString('en-GB',{timeZone:TZ})}}},
    scales:{x:{type:'linear',min:from,max:now,afterBuildTicks:(ax)=>{const t=[],h=3600e3,st=Math.ceil(from/(4*h))*4*h;for(let v=st;v<=now;v+=4*h)t.push({value:v});ax.ticks=t;},
      ticks:{callback:(v)=>hhmm(v)}},y:{beginAtZero:true,title:{display:!!big,text:'ms'}}}}});
}
function fmtBps(v){if(v==null)return '';const u=[['G',1e9],['M',1e6],['k',1e3]];for(const [n,d] of u){if(v>=d)return (v/d).toFixed(1)+' '+n+'b/s';}return Math.round(v)+' b/s';}
function drawSeries(id, series, opts){
  const now=Date.now(), from=now-24*3600e3;
  new Chart(document.getElementById(id),{type:'line',data:{datasets:series.map(x=>({label:x.label,data:x.data.map(p=>({x:p[0]*1000,y:p[1]})),
    borderColor:x.color,backgroundColor:x.fill||'transparent',fill:!!x.fill,pointRadius:0,borderWidth:1.4,tension:.2,spanGaps:false}))},
   options:{animation:false,responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:true,labels:{boxWidth:10}},tooltip:{callbacks:{title:(i)=>new Date(i[0].parsed.x).toLocaleString('en-GB',{timeZone:TZ}),
      label:(i)=>i.dataset.label+': '+(opts.bps?fmtBps(i.parsed.y):i.parsed.y+'%')}}},
    scales:{x:{type:'linear',min:from,max:now,afterBuildTicks:(ax)=>{const t=[],h=3600e3,st=Math.ceil(from/(4*h))*4*h;for(let v=st;v<=now;v+=4*h)t.push({value:v});ax.ticks=t;},
      ticks:{callback:(v)=>hhmm(v)}},y:{beginAtZero:true,max:opts.bps?undefined:100,ticks:{callback:(v)=>opts.bps?fmtBps(v):v+'%'}}}}});
}</script>"""

STATE_CLS = {"up": "g", "down": "r", "warn": "a"}
STATE_TXT = {"up": "UP", "down": "DOWN", "warn": "?", "disabled": "OFF"}
app.jinja_env.globals.update(STATE_CLS=STATE_CLS, STATE_TXT=STATE_TXT)

LOGIN_BODY = """<div class="card" style="max-width:360px;margin:60px auto"><h2>Login</h2>
<form method="post"><input type="password" name="password" placeholder="Password" autofocus style="width:100%" required>
<input type="hidden" name="csrf" value="{{ csrf_token() }}"><br><br><button style="width:100%">Login</button></form>
<p class="hint">Admin password = dashboard + settings. Viewer password (if set) = dashboard only.</p></div>"""

EVENTS_TABLE = """<table><tr><th>Time</th><th>Source</th><th>Event</th><th>Details</th><th></th></tr>
{% for e in events %}<tr>
<td style="white-space:nowrap">{{ e.time }}</td>
<td>{% if e.host_name %}{{ e.host_name }} <span class="muted">{{ e.host_ip }}</span>{% else %}{{ e.d.get('source_label') or e.d.get('source_ip','') }}{% endif %}</td>
<td><span class="badge sev-{{ e.severity }}">{{ e.severity }}</span> {{ '📧' if e.source=='mail' else ('📡' if e.source=='snmp' else ('🔴' if e.kind=='host_down' else '✅')) }} {{ e.title }}</td>
<td class="muted">{{ e.message[:140] }}</td>
<td>{% for a in e.att %}<a href="{{ url_for('snapshot', name=a) }}" target="_blank"><img class="thumb" src="{{ url_for('snapshot', name=a) }}"></a>{% endfor %}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No events yet.</td></tr>{% endfor %}</table>"""

INDEX_BODY = CHART_JS + """
<div class="summary">
 <div class="pill g">UP {{ c.up }}</div><div class="pill r">DOWN {{ c.down }}</div>
 {% if c.warn %}<div class="pill a">UNSTABLE {{ c.warn }}</div>{% endif %}
 {% if c.pending %}<div class="pill p">PENDING {{ c.pending }}</div>{% endif %}
 <span class="muted">Ping every {{ s.ping_interval }}s · alert after {{ s.fail_threshold }} failed pings · refresh 60s · {{ now }} ({{ s.timezone }})</span>
</div>
{% for g, hs in groups %}<div class="grp">{{ g or 'Devices' }}</div><div class="grid">
{% for h in hs %}<div class="card"><div class="dev">
 <div class="dot {{ STATE_CLS.get(h.state,'p') }}">{{ STATE_TXT.get(h.state,'…') }}</div>
 <div style="flex:1"><a href="{{ url_for('host_page', hid=h.id) }}" style="color:inherit;text-decoration:none"><h3>{{ h.name }}</h3></a>
 <div class="muted"><span class="badge" style="background:{{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[2] }}">{{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[1] }}</span> {{ h.host }}</div></div></div>
 <div class="stats"><div>Last ping<b>{{ '%.1f ms'|format(h.last_ms) if h.last_ms is not none else '—' }}</b></div>
 <div>Uptime 24h<b>{{ '%.1f%%'|format(h.uptime) if h.uptime is not none else '—' }}</b></div>
 <div>{% if h.state=='down' %}Down for<b style="color:#dc2626">{{ h.down_for }}</b>{% else %}Last seen<b style="font-size:13px">{{ h.last_seen_txt }}</b>{% endif %}</div></div>
 {% if h.sn %}<div class="snmpline">📡 {% if h.sn.error and h.sn.stale %}<span style="color:#dc2626">SNMP: {{ h.sn.error[:60] }}</span>{% else %}
 up <b>{{ h.sn.uptime_txt }}</b>{% if h.sn.cpu is not none %} · CPU <b>{{ '%.0f'|format(h.sn.cpu) }}%</b>{% endif %}{% if h.sn.mem_pct is not none %} · RAM <b>{{ '%.0f'|format(h.sn.mem_pct) }}%</b>{% endif %}
 {% if h.sn.extra.temp %} · <b>{{ h.sn.extra.temp }}°C</b>{% endif %}{% if h.sn.extra.voltage %} · <b>{{ h.sn.extra.voltage }} V</b>{% endif %}{% if h.sn.extra.wireless_clients is defined %} · <b>{{ h.sn.extra.wireless_clients }}</b> Wi-Fi clients{% endif %}
 <div style="margin-top:4px">{% for i in h.sn.watched %}<span class="lnk {{ 'g' if i.oper=='up' else 'r' }}" title="{{ i.alias }} {{ i.oper }}">{{ i.name }} {{ '▲' if i.oper=='up' else '▼' }}{% if i.in_bps is not none %} <small>{{ fmt_bps(i.in_bps) }}↓ {{ fmt_bps(i.out_bps) }}↑</small>{% endif %}</span>{% endfor %}</div>{% endif %}</div>{% endif %}
 <div class="chartbox"><canvas id="c{{ h.id }}"></canvas></div><script>drawChart('c{{ h.id }}', {{ h.points|tojson }});</script>
</div>{% endfor %}</div>{% else %}<div class="card">No hosts yet. {% if role()=='admin' %}<a href="{{ url_for('settings') }}#hosts">Add hosts in Settings</a>.{% endif %}</div>{% endfor %}
<div class="card" style="margin-top:16px"><h2>Recent events (ping + device e-mails)</h2>""" + EVENTS_TABLE + """</div>"""

HOST_BODY = CHART_JS + """<div class="card"><div class="dev">
<div class="dot {{ STATE_CLS.get(h.state,'p') }}">{{ STATE_TXT.get(h.state,'…') }}</div>
<div><h3>{{ h.name }}</h3><div class="muted">{{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[0] }} · {{ h.host }} · {{ h.grp }} ·
last seen {{ h.last_seen_txt }} · uptime 24h {{ '%.1f%%'|format(h.uptime) if h.uptime is not none else '—' }}</div></div></div>
<div style="height:320px;margin-top:16px"><canvas id="big"></canvas></div><script>drawChart('big', {{ h.points|tojson }}, true);</script></div>
{% if h.sn %}<div class="card"><h2>📡 SNMP {% if h.sn.error %}<span class="badge sev-{{ 'critical' if h.sn.stale else 'warning' }}">last poll failed: {{ h.sn.error }}</span>{% endif %}</h2>
<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr))"><div><table class="kv">
<tr><td>sysName</td><td>{{ h.sn.sysName or '—' }}</td></tr><tr><td>Description</td><td>{{ (h.sn.sysDescr or '—')[:160] }}</td></tr>
<tr><td>Location</td><td>{{ h.sn.sysLocation or '—' }}</td></tr><tr><td>Device uptime</td><td>{{ h.sn.uptime_txt }}</td></tr>
<tr><td>CPU</td><td>{{ '%.0f%%'|format(h.sn.cpu) if h.sn.cpu is not none else 'n/a' }}{% if h.sn.cpu_cores %} ({{ h.sn.cpu_cores }} cores){% endif %}</td></tr>
<tr><td>Memory used</td><td>{{ '%.0f%%'|format(h.sn.mem_pct) if h.sn.mem_pct is not none else 'n/a' }}</td></tr>
{% for d in h.sn.storage %}<tr><td>Disk {{ d.name }}</td><td>{{ d.pct }}% of {{ d.size_mb }} MB</td></tr>{% endfor %}
{% for k, v in h.sn.extra.items() %}<tr><td>{{ {'temp':'Temperature','cpu_temp':'CPU temperature','voltage':'Voltage','wireless_clients':'Wi-Fi clients'}.get(k, k) }}</td><td>{{ v }}{{ '°C' if 'temp' in k else (' V' if k=='voltage' else '') }}</td></tr>{% endfor %}
<tr><td>Last poll</td><td>{{ h.sn.last_txt }}</td></tr></table></div>
<div style="height:220px"><canvas id="res"></canvas></div></div>
<script>drawSeries('res',[{label:'CPU',color:'#1d5fbf',data:{{ h.sn.cpu_pts|tojson }}},{label:'RAM',color:'#a855f7',data:{{ h.sn.mem_pts|tojson }}}],{});</script>
<h2 style="margin-top:14px">Interfaces</h2><table><tr><th>Interface</th><th>Status</th><th>Speed</th><th>In</th><th>Out</th><th>Errors (total)</th><th>Graph</th><th>Alert</th></tr>
{% for i in h.sn.ifaces %}<tr><td><b>{{ i.name }}</b> <span class="muted">{{ i.alias }}</span></td>
<td><span class="lnk {{ 'g' if i.oper=='up' else ('p' if i.admin=='down' else 'r') }}">{{ i.oper }}</span>{% if i.admin=='down' %} <span class="muted">admin down</span>{% endif %}</td>
<td>{{ fmt_bps(i.speed) if i.speed else '—' }}</td><td>{{ fmt_bps(i.in_bps) }}</td><td>{{ fmt_bps(i.out_bps) }}</td><td>{{ i.inerr + i.outerr }}</td>
<td>{{ '✔' if i.name in h.sn.cfg.ifaces else '' }}</td><td>{{ '✔' if i.name in h.sn.cfg.alert_ifaces else '' }}</td></tr>{% endfor %}</table>
<div class="grid" style="margin-top:14px">{% for n, pts in h.sn.traffic %}<div class="card" style="box-shadow:none;border:1px solid #e2e8f0"><b>{{ n }}</b>
<div style="height:170px"><canvas id="t{{ loop.index }}"></canvas></div>
<script>drawSeries('t{{ loop.index }}',[{label:'In',color:'#16a34a',fill:'rgba(22,163,74,.12)',data:{{ pts[0]|tojson }}},{label:'Out',color:'#1d5fbf',data:{{ pts[1]|tojson }}}],{bps:true});</script></div>{% endfor %}</div>
</div>{% endif %}
<div class="card"><h2>Events</h2>""" + EVENTS_TABLE + """</div>"""


def snmp_view(h, tz, full=False):
    cfg = host_snmp_cfg(h)
    if not cfg["enabled"]:
        return None
    with db() as c:
        row = c.execute("SELECT data FROM snmp_state WHERE host_id=?", (h["id"],)).fetchone()
        d = json.loads(row["data"]) if row else {}
        if full:
            samples = c.execute("SELECT ts, cpu, mem, ifs FROM snmp_samples WHERE host_id=? AND ts>=? ORDER BY ts",
                                (h["id"], time.time() - 86400)).fetchall()
    s = get_settings()
    d.setdefault("ifaces", [])
    d.setdefault("extra", {})
    d.setdefault("storage", [])
    for k in ("cpu", "mem_pct", "cpu_cores", "sysName", "sysDescr", "sysLocation", "error"):
        d.setdefault(k, None)
    d["cfg"] = {"ifaces": cfg["ifaces"] or [], "alert_ifaces": cfg["alert_ifaces"] or []}
    d["uptime_txt"] = fmt_dur(d["sysUpTime"] / 100) if isinstance(d.get("sysUpTime"), int) else "—"
    d["last_txt"] = fmt_ts(d.get("ts"), tz) if d.get("ts") else "never"
    d["stale"] = not d.get("ts") or time.time() - d["ts"] > 3 * max(60, s["snmp_interval"])
    names = set(d["cfg"]["ifaces"]) | set(d["cfg"]["alert_ifaces"])
    d["watched"] = [i for i in d["ifaces"] if i["name"] in names][:8]
    if full:
        d["cpu_pts"] = [[r["ts"], r["cpu"]] for r in samples if r["cpu"] is not None]
        d["mem_pts"] = [[r["ts"], r["mem"]] for r in samples if r["mem"] is not None]
        tr = {n: ([], []) for n in d["cfg"]["ifaces"]}
        for r in samples:
            for n, (bi, bo) in json.loads(r["ifs"] or "{}").items():
                if n in tr and bi is not None:
                    tr[n][0].append([r["ts"], bi])
                    tr[n][1].append([r["ts"], bo])
        d["traffic"] = list(tr.items())
    return d


def page(body_tpl, refresh=None, charts=False, **ctx):
    s = get_settings()
    body = render_template_string(body_tpl, s=s, **ctx)
    return render_template_string(LAYOUT, body=body, s=s, refresh=refresh, charts=charts)


def host_view(row, since, tz, full=False):
    h = dict(row)
    with db() as c:
        pts = [(r["ts"], r["ok"], r["ms"]) for r in
               c.execute("SELECT ts, ok, ms FROM results WHERE host_id=? AND ts>=? ORDER BY ts", (h["id"], since))]
    h["points"] = pts
    h["uptime"] = (100.0 * sum(p[1] for p in pts) / len(pts)) if pts else None
    h["last_seen_txt"] = fmt_ts(h["last_seen"], tz)
    h["down_for"] = fmt_dur(time.time() - h["down_since"]) if h["down_since"] else ""
    h["sn"] = snmp_view(h, tz, full)
    if not h["enabled"]:
        h["state"] = "disabled"
    return h


def event_rows(where="1=1", args=(), limit=30, tz=None):
    with db() as c:
        rows = c.execute(f"SELECT * FROM events WHERE {where} ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
    out = []
    for r in rows:
        e = dict(r)
        e["time"] = fmt_ts(e["ts"], tz)
        e["d"] = json.loads(e["details"] or "{}")
        e["att"] = json.loads(e["attachments"] or "[]")
        e["message"] = e["message"] or ""
        out.append(e)
    return out


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = client_ip()
        fails = [t for t in _login_fail.get(ip, []) if t > time.time() - 900]
        if len(fails) >= 10:
            abort(429, "Too many failed logins - try again in 15 minutes")
        pw = request.form.get("password", "")
        s = get_settings()
        r = "admin" if verify_password(pw, s["admin_hash"]) else \
            ("viewer" if s["viewer_hash"] and verify_password(pw, s["viewer_hash"]) else None)
        if r:
            session.clear()
            session.permanent = True
            session["role"] = r
            _login_fail.pop(ip, None)
            nxt = request.args.get("next", "/")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
        _login_fail[ip] = fails + [time.time()]
        log.warning("Failed login from %s", ip)
        time.sleep(1)
        flash("Wrong password")
    return page(LOGIN_BODY)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@viewer_required
def index():
    tz = tzinfo()
    since = time.time() - 86400
    with db() as c:
        rows = c.execute("SELECT * FROM hosts ORDER BY grp, CASE state WHEN 'down' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, name").fetchall()
    hosts = [host_view(r, since, tz) for r in rows]
    groups, idx = [], {}
    for h in hosts:
        if h["grp"] not in idx:
            idx[h["grp"]] = len(groups)
            groups.append((h["grp"], []))
        groups[idx[h["grp"]]][1].append(h)
    c = {k: sum(1 for h in hosts if h["state"] == k) for k in ("up", "down", "warn", "pending")}
    return page(INDEX_BODY, refresh=60, charts=True, groups=groups, c=c, events=event_rows(limit=25, tz=tz),
                now=fmt_ts(time.time(), tz))


@app.route("/host/<int:hid>")
@viewer_required
def host_page(hid):
    tz = tzinfo()
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
    if not row:
        abort(404)
    return page(HOST_BODY, refresh=60, charts=True, h=host_view(row, time.time() - 86400, tz, full=True),
                events=event_rows("host_id=?", (hid,), 50, tz))


@app.route("/snapshot/<name>")
@viewer_required
def snapshot(name):
    if not re.fullmatch(r"ev\d+_\d\.(jpg|png)", name):
        abort(404)
    return send_from_directory(SNAP_DIR, name, max_age=86400)


@app.route("/healthz")
def healthz():
    return "ok"


# ----------------------------------------------------------------------------- settings page
CSRF = '<input type="hidden" name="csrf" value="{{ csrf_token() }}">'


def _secret_input(name):
    return ('<input type="password" name="' + name + '" autocomplete="new-password" placeholder="'
            '{{ (\'saved \' + mask(s.' + name + ') + \' - leave empty to keep\') if s.' + name + ' else \'not set\' }}">')


SETTINGS_BODY = """
<div class="nav"><a href="#general">General</a><a href="#hosts">Hosts</a><a href="#telegram">Telegram</a><a href="#email">Outgoing e-mail</a>
<a href="#receiver">Incoming e-mail (devices)</a><a href="#snmp">SNMP + traps</a><a href="#webhook">Webhook</a><a href="#api">API</a><a href="#password">Passwords</a></div>

<div class="card" id="hosts"><h2>Hosts</h2>
<table><tr><th>Name</th><th>IP / hostname</th><th>Group / location</th><th>Device type</th><th>On</th><th>Status</th><th>SNMP</th><th></th></tr>
{% for h in hosts %}<tr>
<td><input type="text" form="hf{{ h.id }}" name="name" value="{{ h.name }}" required maxlength="60" style="width:150px"></td>
<td><input type="text" form="hf{{ h.id }}" name="host" value="{{ h.host }}" required maxlength="253" style="width:140px"></td>
<td><input type="text" form="hf{{ h.id }}" name="grp" value="{{ h.grp }}" maxlength="60" style="width:120px"></td>
<td><select form="hf{{ h.id }}" name="device_type">{% for k, v in DEVICE_TYPES.items() %}<option value="{{ k }}" {{ 'selected' if k==h.device_type }}>{{ v[0] }}</option>{% endfor %}</select></td>
<td><input type="checkbox" form="hf{{ h.id }}" name="enabled" value="1" {{ 'checked' if h.enabled }}></td>
<td><span class="badge {{ STATE_CLS.get(h.state,'p') if h.enabled else 'p' }}">{{ STATE_TXT.get(h.state, h.state) if h.enabled else 'OFF' }}</span></td>
<td><a href="{{ url_for('host_snmp', hid=h.id) }}">{{ ('v' + h.scfg.version) if h.scfg.enabled else 'off' }} ⚙</a></td>
<td style="white-space:nowrap"><form id="hf{{ h.id }}" method="post" action="{{ url_for('host_save', hid=h.id) }}" style="display:inline">""" + CSRF + """<button>Save</button></form>
<form method="post" action="{{ url_for('host_delete', hid=h.id) }}" style="display:inline" onsubmit="return confirm('Delete {{ h.name }} and its history?')">""" + CSRF + """<button class="del">Delete</button></form></td></tr>
{% endfor %}
<tr>
<td><input type="text" form="hadd" name="name" placeholder="e.g. Reception NVR" required maxlength="60" style="width:150px"></td>
<td><input type="text" form="hadd" name="host" placeholder="192.168.1.10" required maxlength="253" style="width:140px"></td>
<td><input type="text" form="hadd" name="grp" placeholder="e.g. Cameras" maxlength="60" style="width:120px"></td>
<td><select form="hadd" name="device_type">{% for k, v in DEVICE_TYPES.items() %}<option value="{{ k }}">{{ v[0] }}</option>{% endfor %}</select></td>
<td><input type="checkbox" form="hadd" name="enabled" value="1" checked></td><td></td><td class="hint">after adding</td>
<td><form id="hadd" method="post" action="{{ url_for('host_add') }}">""" + CSRF + """<button>+ Add</button></form></td></tr></table></div>

<div class="card" id="general"><h2>General</h2><form method="post" action="{{ url_for('save_section', section='general') }}">""" + CSRF + """
<div class="form-grid">
<label>Site / client name</label><input type="text" name="site_name" value="{{ s.site_name }}" required maxlength="80">
<label>Timezone</label><input type="text" name="timezone" value="{{ s.timezone }}" list="tzs"><datalist id="tzs">{% for z in tzs %}<option>{{ z }}</option>{% endfor %}</datalist>
<label>Ping interval (seconds)</label><input type="number" name="ping_interval" min="10" max="3600" value="{{ s.ping_interval }}">
<label>Ping timeout (seconds)</label><input type="number" name="ping_timeout" min="1" max="10" value="{{ s.ping_timeout }}">
<label>Failed pings before alert</label><input type="number" name="fail_threshold" min="1" max="20" value="{{ s.fail_threshold }}">
<label>Keep history (days)</label><input type="number" name="retention_days" min="1" max="365" value="{{ s.retention_days }}">
<label>Ping method</label><select name="ping_method">{% for m in ['auto','icmplib','system'] %}<option {{ 'selected' if s.ping_method==m }}>{{ m }}</option>{% endfor %}</select>
<label>Public URL (optional)</label><input type="url" name="public_url" value="{{ s.public_url }}" placeholder="https://hotel.monitor.example.com">
<label>Dashboard access</label><select name="dashboard_access"><option value="login" {{ 'selected' if s.dashboard_access=='login' }}>Login required (admin or viewer password)</option>
<option value="public" {{ 'selected' if s.dashboard_access=='public' }}>Public read-only (no login)</option></select>
<label>Viewer password (dashboard only)</label><div><input type="password" name="viewer_password" autocomplete="new-password" placeholder="{{ 'set - leave empty to keep' if s.viewer_hash else 'not set' }}" style="width:60%">
<label class="hint"><input type="checkbox" name="viewer_clear" value="1"> remove viewer password</label></div>
<span></span><div><button>Save general settings</button> <span class="hint">Ping method in use: {{ ping_name }}</span></div></div></form></div>

<div class="card" id="telegram"><h2>Telegram</h2><form method="post" action="{{ url_for('save_section', section='telegram') }}">""" + CSRF + """
<div class="form-grid">
<label>Enabled</label><input type="checkbox" name="telegram_enabled" value="1" {{ 'checked' if s.telegram_enabled }}>
<label>Bot token</label>""" + _secret_input("telegram_token") + """
<label>Chat ID</label><input type="text" name="telegram_chat_id" value="{{ s.telegram_chat_id }}" placeholder="123456789 or -100...">
<label>Send camera snapshots</label><input type="checkbox" name="telegram_photos" value="1" {{ 'checked' if s.telegram_photos }}>
<span></span><div><button>Save</button> <button formaction="{{ url_for('test_channel', ch='telegram') }}" class="sec">Save + send test</button></div></div></form></div>

<div class="card" id="email"><h2>Outgoing e-mail (alerts to you, via SMTP)</h2><form method="post" action="{{ url_for('save_section', section='email') }}">""" + CSRF + """
<div class="form-grid">
<label>Enabled</label><input type="checkbox" name="email_enabled" value="1" {{ 'checked' if s.email_enabled }}>
<label>SMTP server</label><input type="text" name="smtp_host" value="{{ s.smtp_host }}" placeholder="smtp.gmail.com">
<label>Port</label><input type="number" name="smtp_port" value="{{ s.smtp_port }}" min="1" max="65535">
<label>Security</label><select name="smtp_security">{% for k, v in [('none','None (plain, port 25)'),('starttls','STARTTLS (port 587)'),('ssl','SSL/TLS (port 465)')] %}<option value="{{ k }}" {{ 'selected' if s.smtp_security==k }}>{{ v }}</option>{% endfor %}</select>
<label>Username</label><input type="text" name="smtp_user" value="{{ s.smtp_user }}" autocomplete="off" placeholder="empty = no login">
<label>Password</label>""" + _secret_input("smtp_password") + """
<label>From</label><input type="text" name="smtp_from" value="{{ s.smtp_from }}" placeholder="monitor@yourdomain">
<label>To (comma separated)</label><input type="text" name="smtp_to" value="{{ s.smtp_to }}" placeholder="you@x.gr, tech@x.gr">
<span></span><div><button>Save</button> <button formaction="{{ url_for('test_channel', ch='email') }}" class="sec">Save + send test e-mail</button></div></div></form></div>

<div class="card" id="receiver"><h2>Incoming e-mail receiver (alerts FROM cameras, NVRs, controllers)</h2>
<p class="hint">Point Hikvision / Dahua / UniFi / Omada / MikroTik e-mail settings at this box (its LAN IP) and this port.
Mails are parsed (motion, HDD error, video loss, device offline, ...), shown on the dashboard and forwarded to your channels.
Status: <b>{{ rx_status }}</b></p>
<form method="post" action="{{ url_for('save_section', section='receiver') }}">""" + CSRF + """
<div class="form-grid">
<label>Enabled</label><input type="checkbox" name="rx_enabled" value="1" {{ 'checked' if s.rx_enabled }}>
<label>Listen address</label><input type="text" name="rx_host" value="{{ s.rx_host }}" placeholder="0.0.0.0 = all LAN interfaces">
<label>Port</label><input type="number" name="rx_port" value="{{ s.rx_port }}" min="1" max="65535">
<label>Security</label><select name="rx_security">{% for k, v in [('none','None - plain SMTP (old devices)'),('starttls','STARTTLS offered (plain still allowed)'),('ssl','SSL/TLS (implicit, like port 465)')] %}<option value="{{ k }}" {{ 'selected' if s.rx_security==k }}>{{ v }}</option>{% endfor %}</select>
<label>Require login (AUTH)</label><input type="checkbox" name="rx_require_auth" value="1" {{ 'checked' if s.rx_require_auth }}>
<label>Username</label><input type="text" name="rx_user" value="{{ s.rx_user }}">
<label>Password</label>""" + _secret_input("rx_password") + """
<label>Allowed sender networks</label><input type="text" name="rx_allowed_nets" value="{{ s.rx_allowed_nets }}">
<label>Forward to Telegram/e-mail/webhook</label><select name="rx_forward_min">{% for k, v in [('info','Everything (incl. motion)'),('warning','Warnings + critical (no motion)'),('critical','Critical only'),('none','Nothing (dashboard only)')] %}<option value="{{ k }}" {{ 'selected' if s.rx_forward_min==k }}>{{ v }}</option>{% endfor %}</select>
<label>Max 1 forward per device+type every (s)</label><input type="number" name="rx_rate_limit" value="{{ s.rx_rate_limit }}" min="0" max="86400">
<span></span><div><button>Save + restart receiver</button></div></div></form></div>

<div class="card" id="snmp"><h2>SNMP polling + trap receiver</h2>
<p class="hint">SNMP is set per host (click <b>⚙</b> in the hosts table: community or v3 user, interfaces to graph). These are the global options.
Trap receiver status: <b>{{ trap_status }}</b>{% if not snmp_ok %} · <b style="color:#dc2626">pysnmp not installed</b>{% endif %}</p>
<form method="post" action="{{ url_for('save_section', section='snmp') }}">""" + CSRF + """
<div class="form-grid">
<label>SNMP polling enabled</label><input type="checkbox" name="snmp_enabled" value="1" {{ 'checked' if s.snmp_enabled }}>
<label>Poll interval (seconds)</label><input type="number" name="snmp_interval" value="{{ s.snmp_interval }}" min="30" max="3600">
<label>Timeout (seconds)</label><input type="number" name="snmp_timeout" value="{{ s.snmp_timeout }}" min="1" max="10">
<label>High CPU alert at (%)</label><input type="number" name="snmp_cpu_threshold" value="{{ s.snmp_cpu_threshold }}" min="0" max="100"><span></span><span class="hint">0 = off. Alert after 2 polls in a row above it.</span>
<label>Alert on interface down</label><input type="checkbox" name="snmp_alert_ifdown" value="1" {{ 'checked' if s.snmp_alert_ifdown }}>
<label>Alert on device reboot</label><input type="checkbox" name="snmp_alert_reboot" value="1" {{ 'checked' if s.snmp_alert_reboot }}>
<label>Forward SNMP poll alerts</label><select name="snmp_forward_min">{% for k, v in [('info','Everything (incl. link up / CPU ok)'),('warning','Warnings + critical'),('critical','Critical only'),('none','Nothing (dashboard only)')] %}<option value="{{ k }}" {{ 'selected' if s.snmp_forward_min==k }}>{{ v }}</option>{% endfor %}</select>
<label><b>Trap receiver enabled</b></label><input type="checkbox" name="trap_enabled" value="1" {{ 'checked' if s.trap_enabled }}>
<label>Listen address</label><input type="text" name="trap_host" value="{{ s.trap_host }}" placeholder="0.0.0.0">
<label>UDP port</label><input type="number" name="trap_port" value="{{ s.trap_port }}" min="1" max="65535"><span></span><span class="hint">162 = standard (service has CAP_NET_BIND_SERVICE). 1162 avoids needing it - set the same port on the devices.</span>
<label>Accepted communities</label><input type="text" name="trap_community" value="{{ s.trap_community }}" placeholder="empty = any; e.g. public,wirewave"><span></span><span class="hint">Traps v1/v2c. Sender must also be in the "Allowed sender networks" of the e-mail receiver.</span>
<label>Forward traps</label><select name="trap_forward_min">{% for k, v in [('info','Everything (incl. linkUp)'),('warning','Warnings + critical'),('critical','Critical only (linkDown, coldStart)'),('none','Nothing (dashboard only)')] %}<option value="{{ k }}" {{ 'selected' if s.trap_forward_min==k }}>{{ v }}</option>{% endfor %}</select>
<span></span><div><button>Save + restart trap receiver</button></div></div></form></div>

<div class="card" id="webhook"><h2>Outgoing webhook (Grok Bot / automations)</h2><form method="post" action="{{ url_for('save_section', section='webhook') }}">""" + CSRF + """
<p class="hint">POSTs JSON on host_down, host_recovered, forwarded device_alert, snmp_alert and snmp_trap events. See README for the payload.</p>
<div class="form-grid">
<label>Enabled</label><input type="checkbox" name="webhook_enabled" value="1" {{ 'checked' if s.webhook_enabled }}>
<label>URL</label><input type="url" name="webhook_url" value="{{ s.webhook_url }}" placeholder="https://...">
<label>Secret header name</label><input type="text" name="webhook_header_name" value="{{ s.webhook_header_name }}" placeholder="Authorization or X-Webhook-Secret">
<label>Secret header value</label>""" + _secret_input("webhook_header_value") + """
<span></span><div><button>Save</button> <button formaction="{{ url_for('test_channel', ch='webhook') }}" class="sec">Save + send test</button></div></div></form></div>

<div class="card" id="api"><h2>JSON API token</h2>
<p class="hint">Use as <code>Authorization: Bearer &lt;token&gt;</code> or <code>?token=&lt;token&gt;</code> on <code>/api/status</code> and <code>/api/events</code>.</p>
<input type="password" id="apitok" value="{{ s.api_token }}" readonly style="width:420px;font-family:monospace">
<button type="button" class="sec" onclick="const t=document.getElementById('apitok');t.type=t.type=='password'?'text':'password'">Show</button>
<button type="button" class="sec" onclick="navigator.clipboard.writeText(document.getElementById('apitok').value).then(()=>this.textContent='Copied')">Copy</button>
<form method="post" action="{{ url_for('regen_token') }}" style="display:inline" onsubmit="return confirm('Old token stops working. Continue?')">""" + CSRF + """<button class="del">Regenerate</button></form></div>

<div class="card" id="password"><h2>Change admin password</h2><form method="post" action="{{ url_for('change_password') }}">""" + CSRF + """
<div class="form-grid"><label>Current password</label><input type="password" name="current" required>
<label>New password (min 8)</label><input type="password" name="new" required minlength="8">
<label>Repeat new password</label><input type="password" name="new2" required minlength="8">
<span></span><div><button>Change password</button></div></div></form></div>
"""

BOOL_FIELDS = {"telegram_enabled", "telegram_photos", "email_enabled", "webhook_enabled", "rx_enabled", "rx_require_auth",
               "snmp_enabled", "snmp_alert_ifdown", "snmp_alert_reboot", "trap_enabled"}
SECTIONS = {
    "general": ["site_name", "timezone", "ping_interval", "ping_timeout", "fail_threshold", "retention_days",
                "ping_method", "public_url", "dashboard_access"],
    "telegram": ["telegram_enabled", "telegram_token", "telegram_chat_id", "telegram_photos"],
    "email": ["email_enabled", "smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password", "smtp_from", "smtp_to"],
    "webhook": ["webhook_enabled", "webhook_url", "webhook_header_name", "webhook_header_value"],
    "receiver": ["rx_enabled", "rx_host", "rx_port", "rx_security", "rx_require_auth", "rx_user", "rx_password",
                 "rx_allowed_nets", "rx_forward_min", "rx_rate_limit"],
    "snmp": ["snmp_enabled", "snmp_interval", "snmp_timeout", "snmp_cpu_threshold", "snmp_alert_ifdown", "snmp_alert_reboot",
             "snmp_forward_min", "trap_enabled", "trap_host", "trap_port", "trap_community", "trap_forward_min"],
}
CHOICES = {"ping_method": {"auto", "icmplib", "system"}, "dashboard_access": {"login", "public"},
           "smtp_security": {"none", "starttls", "ssl"}, "rx_security": {"none", "starttls", "ssl"},
           "rx_forward_min": {"info", "warning", "critical", "none"}, "snmp_forward_min": {"info", "warning", "critical", "none"},
           "trap_forward_min": {"info", "warning", "critical", "none"}}
RANGES = {"ping_interval": (10, 3600), "ping_timeout": (1, 10), "fail_threshold": (1, 20), "retention_days": (1, 365),
          "smtp_port": (1, 65535), "rx_port": (1, 65535), "rx_rate_limit": (0, 86400),
          "snmp_interval": (30, 3600), "snmp_timeout": (1, 10), "snmp_cpu_threshold": (0, 100), "trap_port": (1, 65535)}


def _apply_section(section):
    upd = {}
    for k in SECTIONS[section]:
        if k in BOOL_FIELDS:
            upd[k] = 1 if request.form.get(k) else 0
            continue
        v = request.form.get(k, "").strip()
        if k in SECRET_KEYS and not v:
            continue  # keep saved secret
        if k in INT_KEYS:
            try:
                v = int(v)
            except ValueError:
                raise ValueError(f"{k} must be a number")
            lo, hi = RANGES.get(k, (0, 10 ** 9))
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
        if k in CHOICES and v not in CHOICES[k]:
            raise ValueError(f"invalid {k}")
        if k == "timezone":
            ZoneInfo(v)
        if k in ("trap_host", "rx_host") and v:
            ipaddress.ip_address(v)
        if k == "rx_allowed_nets":
            for n in [x.strip() for x in v.split(",") if x.strip()]:
                ipaddress.ip_network(n, strict=False)
        upd[k] = v
    if section == "general":
        if request.form.get("viewer_clear"):
            upd["viewer_hash"] = ""
        elif request.form.get("viewer_password"):
            if len(request.form["viewer_password"]) < 6:
                raise ValueError("viewer password must be at least 6 characters")
            upd["viewer_hash"] = hash_password(request.form["viewer_password"])
    set_settings(**upd)


@app.route("/settings")
@admin_required
def settings():
    with db() as c:
        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts ORDER BY grp, name")]
    for h in hosts:
        h["scfg"] = host_snmp_cfg(h)
    try:
        tzs = sorted(z for z in available_timezones() if z.startswith("Europe/"))
    except Exception:
        tzs = ["Europe/Athens"]
    return page(SETTINGS_BODY, hosts=hosts, tzs=tzs, rx_status=RECEIVER.status(), trap_status=SNMP.trap_status,
                snmp_ok=SNMP.available,
                ping_name=_ping_impl["name"] or "not started")


@app.route("/settings/<section>", methods=["POST"])
@admin_required
def save_section(section):
    if section not in SECTIONS:
        abort(404)
    try:
        _apply_section(section)
        flash(f"{section.capitalize()} settings saved.")
    except Exception as e:
        flash(f"Not saved: {e}")
        return redirect(url_for("settings") + "#" + section)
    if section == "receiver":
        RECEIVER.restart()
        flash(f"SMTP receiver: {RECEIVER.status()}")
    if section == "snmp":
        try:
            SNMP.restart_traps()
        except Exception as e:
            log.error("trap restart: %s", e)
        flash(f"SNMP trap receiver: {SNMP.trap_status}")
    if section == "general":
        app.secret_key = get_settings()["secret_key"]
    return redirect(url_for("settings") + "#" + section)


@app.route("/settings/test/<ch>", methods=["POST"])
@admin_required
def test_channel(ch):
    section = {"telegram": "telegram", "email": "email", "webhook": "webhook"}.get(ch)
    if not section:
        abort(404)
    try:
        _apply_section(section)
    except Exception as e:
        flash(f"Not saved: {e}")
        return redirect(url_for("settings") + "#" + section)
    s = get_settings()
    text = f"🔔 Test from Wirewave Ping Monitor [{s['site_name']}] - {fmt_ts(time.time())}"
    try:
        if ch == "telegram":
            send_telegram(s, text)
        elif ch == "email":
            send_email(s, f"[{s['site_name']}] Ping Monitor test", text + "\n\nIf you can read this, e-mail alerts work.")
        else:
            send_webhook(s, build_payload(s, "test", None, None, None, severity="info", message=text))
        flash(f"✅ Test {ch} sent successfully.")
    except Exception as e:
        flash(f"❌ Test {ch} failed: {e}")
    return redirect(url_for("settings") + "#" + section)


def _host_form():
    name = request.form.get("name", "").strip()[:60]
    host = request.form.get("host", "").strip()
    grp = request.form.get("grp", "").strip()[:60]
    dt = request.form.get("device_type", "generic")
    if not name or not HOST_RE.match(host) or host.startswith("-"):
        raise ValueError("invalid name or IP/hostname")
    if dt not in DEVICE_TYPES:
        dt = "generic"
    return name, host, grp, dt, 1 if request.form.get("enabled") else 0


@app.route("/settings/hosts/add", methods=["POST"])
@admin_required
def host_add():
    try:
        name, host, grp, dt, en = _host_form()
    except ValueError as e:
        flash(f"Not added: {e}")
        return redirect(url_for("settings") + "#hosts")
    with _db_lock, db() as c:
        c.execute("INSERT INTO hosts(name, host, grp, device_type, enabled, created_at, state) VALUES(?,?,?,?,?,?,?)",
                  (name, host, grp, dt, en, time.time(), "pending" if en else "disabled"))
    flash(f"Added {name} ({host}).")
    return redirect(url_for("settings") + "#hosts")


@app.route("/settings/hosts/<int:hid>/save", methods=["POST"])
@admin_required
def host_save(hid):
    try:
        name, host, grp, dt, en = _host_form()
    except ValueError as e:
        flash(f"Not saved: {e}")
        return redirect(url_for("settings") + "#hosts")
    with _db_lock, db() as c:
        old = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
        if not old:
            abort(404)
        reset = old["host"] != host or old["enabled"] != en
        if old["host"] != host:
            c.execute("DELETE FROM snmp_state WHERE host_id=?", (hid,))
            SNMP.counters.pop(hid, None)
        c.execute("UPDATE hosts SET name=?, host=?, grp=?, device_type=?, enabled=? WHERE id=?", (name, host, grp, dt, en, hid))
        if reset:  # new address or re-enabled: start fresh, no stale alerts
            c.execute("UPDATE hosts SET state=?, consec_fail=0, down_since=NULL, last_ms=NULL WHERE id=?",
                      ("pending" if en else "disabled", hid))
    flash(f"Saved {name}.")
    return redirect(url_for("settings") + "#hosts")


@app.route("/settings/hosts/<int:hid>/delete", methods=["POST"])
@admin_required
def host_delete(hid):
    with _db_lock, db() as c:
        c.execute("DELETE FROM results WHERE host_id=?", (hid,))
        c.execute("DELETE FROM snmp_state WHERE host_id=?", (hid,))
        c.execute("DELETE FROM snmp_samples WHERE host_id=?", (hid,))
        c.execute("DELETE FROM hosts WHERE id=?", (hid,))
    flash("Host deleted.")
    return redirect(url_for("settings") + "#hosts")


SNMP_HOST_BODY = """<p><a href="{{ url_for('settings') }}#hosts">← Settings / hosts</a></p>
<div class="card"><h2>SNMP for {{ h.name }} <span class="muted">{{ h.host }} · {{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[0] }}</span></h2>
<form method="post" action="{{ url_for('host_snmp', hid=h.id) }}">""" + CSRF + """<input type="hidden" name="has_ifaces" value="{{ 1 if ifaces else 0 }}">
<div class="form-grid">
<label>SNMP enabled</label><input type="checkbox" name="enabled" value="1" {{ 'checked' if c.enabled }}>
<label>Version</label><select name="version" onchange="document.querySelectorAll('.v3').forEach(e=>e.style.display=this.value=='3'?'':'none');document.querySelectorAll('.v2').forEach(e=>e.style.display=this.value=='3'?'none':'')">
{% for v in ['2c','1','3'] %}<option value="{{ v }}" {{ 'selected' if c.version==v }}>v{{ v }}</option>{% endfor %}</select>
<label>UDP port</label><input type="number" name="port" value="{{ c.port }}" min="1" max="65535">
<label class="v2">Community</label><input class="v2" type="password" name="community" autocomplete="new-password" placeholder="{{ ('saved ' + mask(c.community) + ' - leave empty to keep') if c.community else 'e.g. public (read-only)' }}">
<label class="v3">v3 user</label><input class="v3" type="text" name="user" value="{{ c.user }}" autocomplete="off">
<label class="v3">Auth protocol</label><select class="v3" name="auth_proto">{% for v in ['SHA','MD5','SHA256','none'] %}<option {{ 'selected' if c.auth_proto==v }}>{{ v }}</option>{% endfor %}</select>
<label class="v3">Auth password</label><input class="v3" type="password" name="auth_key" autocomplete="new-password" placeholder="{{ ('saved ' + mask(c.auth_key) + ' - leave empty to keep') if c.auth_key else 'min 8 characters' }}">
<label class="v3">Privacy protocol</label><select class="v3" name="priv_proto">{% for v in ['AES','DES','AES256','none'] %}<option {{ 'selected' if c.priv_proto==v }}>{{ v }}</option>{% endfor %}</select>
<label class="v3">Privacy password</label><input class="v3" type="password" name="priv_key" autocomplete="new-password" placeholder="{{ ('saved ' + mask(c.priv_key) + ' - leave empty to keep') if c.priv_key else 'min 8 characters' }}">
</div>
{% if ifaces %}<h2 style="margin-top:16px">Interfaces</h2><p class="hint">Graph = traffic chart on the host page. Alert = message when it goes from up to down (and back).</p>
<table><tr><th>Interface</th><th>Status</th><th>Speed</th><th>Graph</th><th>Alert</th></tr>
{% for i in ifaces %}<tr><td><b>{{ i.name }}</b> <span class="muted">{{ i.alias }} {{ i.descr if i.descr != i.name else '' }}</span></td>
<td><span class="lnk {{ 'g' if i.oper=='up' else 'r' }}">{{ i.oper }}</span></td><td>{{ fmt_bps(i.speed) if i.speed else '—' }}</td>
<td><input type="checkbox" name="g_{{ i.name }}" value="1" {{ 'checked' if i.name in (c.ifaces or []) }}></td>
<td><input type="checkbox" name="a_{{ i.name }}" value="1" {{ 'checked' if i.name in (c.alert_ifaces or []) }}></td></tr>{% endfor %}</table>
{% else %}<p class="hint">Interfaces appear here after the first successful poll or a test (physical interfaces that are up get selected automatically).</p>{% endif %}
<p><button>Save</button> <button name="test" value="1" class="sec">Save + test now</button></p></form>
{% if test %}<div class="card" style="border:1px solid #e2e8f0;box-shadow:none">{% if test.error %}❌ <b>SNMP test failed:</b> {{ test.error }}{% else %}
✅ <b>{{ test.sysName }}</b> answered in {{ test.took }} s - {{ test.sysDescr[:150] if test.sysDescr }}<br>uptime {{ test.uptime_txt }} · CPU {{ test.cpu if test.cpu is not none else 'n/a' }} · RAM {{ test.mem_pct if test.mem_pct is not none else 'n/a' }}% · {{ test.ifaces|length }} interfaces{% for k, v in test.extra.items() %} · {{ k }} {{ v }}{% endfor %}{% endif %}</div>{% endif %}
</div><script>document.querySelector('select[name=version]').dispatchEvent(new Event('change'))</script>"""


@app.route("/settings/hosts/<int:hid>/snmp", methods=["GET", "POST"])
@admin_required
def host_snmp(hid):
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
        st = c.execute("SELECT data FROM snmp_state WHERE host_id=?", (hid,)).fetchone()
    if not row:
        abort(404)
    h = dict(row)
    cfg = host_snmp_cfg(h)
    ifaces = (json.loads(st["data"]).get("ifaces") if st else None) or []
    test = None
    if request.method == "POST":
        f = request.form
        try:
            cfg["enabled"] = 1 if f.get("enabled") else 0
            cfg["version"] = f.get("version") if f.get("version") in ("1", "2c", "3") else "2c"
            cfg["port"] = int(f.get("port") or 161)
            if not 1 <= cfg["port"] <= 65535:
                raise ValueError("port must be 1-65535")
            cfg["user"] = f.get("user", "").strip()[:64]
            cfg["auth_proto"] = f.get("auth_proto") if f.get("auth_proto") in ("SHA", "MD5", "SHA256", "none") else "SHA"
            cfg["priv_proto"] = f.get("priv_proto") if f.get("priv_proto") in ("AES", "DES", "AES256", "none") else "AES"
            for k in ("community", "auth_key", "priv_key"):
                if f.get(k):
                    cfg[k] = f[k].strip()[:128]
            if cfg["version"] == "3":
                if not cfg["user"]:
                    raise ValueError("SNMPv3 needs a user name")
                for k, p in (("auth_key", "auth_proto"), ("priv_key", "priv_proto")):
                    if cfg[p] != "none" and cfg[k] and len(cfg[k]) < 8:
                        raise ValueError("SNMPv3 passwords must be at least 8 characters")
            if f.get("has_ifaces") == "1":
                cfg["ifaces"] = [i["name"] for i in ifaces if f.get("g_" + i["name"])]
                cfg["alert_ifaces"] = [i["name"] for i in ifaces if f.get("a_" + i["name"])]
        except ValueError as e:
            flash(f"Not saved: {e}")
            return redirect(url_for("host_snmp", hid=hid))
        with _db_lock, db() as c:
            c.execute("UPDATE hosts SET snmp=? WHERE id=?", (json.dumps(cfg), hid))
        h["snmp"] = json.dumps(cfg)
        SNMP.last_poll.pop(hid, None)  # poll soon
        flash("SNMP settings saved.")
        if not f.get("test"):
            return redirect(url_for("host_snmp", hid=hid))
        t0 = time.time()
        try:
            test = SNMP.call(SNMP.query(h, cfg), 60)
            test["took"] = round(time.time() - t0, 2)
            test["uptime_txt"] = fmt_dur(test["sysUpTime"] / 100) if isinstance(test.get("sysUpTime"), int) else "?"
            ifaces = test["ifaces"]
            if cfg["ifaces"] is None:
                cfg["ifaces"] = [i["name"] for i in ifaces if i["type"] in IFTYPE_PHYS and i["oper"] == "up"][:8]
                cfg["alert_ifaces"] = list(cfg["ifaces"])
                with _db_lock, db() as c:
                    c.execute("UPDATE hosts SET snmp=? WHERE id=?", (json.dumps(cfg), hid))
        except Exception as e:
            test = {"error": _snmp_err(e) if not isinstance(e, RuntimeError) else str(e)}
    return page(SNMP_HOST_BODY, h=h, c=cfg, ifaces=ifaces, test=test)


@app.route("/settings/api/regenerate", methods=["POST"])
@admin_required
def regen_token():
    set_settings(api_token=secrets.token_urlsafe(32))
    flash("New API token generated - update it wherever you use it.")
    return redirect(url_for("settings") + "#api")


@app.route("/settings/password", methods=["POST"])
@admin_required
def change_password():
    s = get_settings()
    if not verify_password(request.form.get("current", ""), s["admin_hash"]):
        flash("Current password is wrong.")
    elif len(request.form.get("new", "")) < 8 or request.form.get("new") != request.form.get("new2"):
        flash("New passwords must match and be at least 8 characters.")
    else:
        set_settings(admin_hash=hash_password(request.form["new"]))
        flash("Admin password changed.")
    return redirect(url_for("settings") + "#password")


# ----------------------------------------------------------------------------- JSON API
def event_json(e, tz):
    d = json.loads(e["details"] or "{}")
    out = {"id": e["id"], "time": iso(e["ts"], tz), "source": e["source"], "type": e["kind"], "severity": e["severity"],
           "host": e["host_name"], "ip": e["host_ip"], "title": e["title"], "message": e["message"]}
    if e["source"] == "mail":
        out.update(brand=d.get("brand"), source_ip=d.get("source_ip"), subject=d.get("subject"),
                   fields=d.get("fields"), attachments=len(json.loads(e["attachments"] or "[]")))
        out["host"] = out["host"] or d.get("source_label")
    if e["source"] == "snmp":
        out.update(source_ip=d.get("source_ip"), trap=d.get("trap"), interface=d.get("interface"),
                   fields={k: v for k, v in d.items() if k not in ("type", "source_ip", "trap", "interface", "varbinds")} or None)
        if d.get("varbinds"):
            out["varbinds"] = d["varbinds"]
    return out


def snmp_json(h, tz):
    d = snmp_view(h, tz)
    if d is None:
        return None
    return {"last_poll": iso(d.get("ts"), tz) if d.get("ts") else None, "ok": not d["error"] and not d["stale"],
            "error": d["error"], "sys_name": d["sysName"], "sys_descr": d["sysDescr"],
            "uptime_seconds": int(d["sysUpTime"] / 100) if isinstance(d.get("sysUpTime"), int) else None,
            "cpu_pct": d["cpu"], "mem_pct": d["mem_pct"], "extra": d["extra"],
            "interfaces": [{"name": i["name"], "alias": i.get("alias") or None, "oper": i.get("oper"), "admin": i.get("admin"),
                            "speed_bps": i.get("speed"), "in_bps": i.get("in_bps"), "out_bps": i.get("out_bps"),
                            "errors": (i.get("inerr") or 0) + (i.get("outerr") or 0),
                            "graphed": i["name"] in d["cfg"]["ifaces"], "alerting": i["name"] in d["cfg"]["alert_ifaces"]}
                           for i in d["ifaces"] if i.get("type") != 24]}   # skip loopback


@app.route("/api/status")
@api_auth
def api_status():
    s = get_settings()
    tz = tzinfo()
    now = time.time()
    since = now - 86400
    hosts = []
    with db() as c:
        for r in c.execute("SELECT * FROM hosts ORDER BY grp, name").fetchall():
            st = c.execute("SELECT COUNT(*) n, SUM(ok) up FROM results WHERE host_id=? AND ts>=?", (r["id"], since)).fetchone()
            state = r["state"] if r["enabled"] else "disabled"
            hosts.append({
                "id": r["id"], "name": r["name"], "ip": r["host"], "group": r["grp"] or None,
                "device_type": r["device_type"], "enabled": bool(r["enabled"]), "state": state,
                "latency_ms": r["last_ms"],
                "uptime_24h": round(100.0 * (st["up"] or 0) / st["n"], 2) if st["n"] else None,
                "last_check": iso(r["last_check"], tz), "last_seen": iso(r["last_seen"], tz),
                "down_since": iso(r["down_since"], tz),
                "down_for_seconds": int(now - r["down_since"]) if r["down_since"] else None,
                "consecutive_failures": r["consec_fail"],
                "snmp": snmp_json(dict(r), tz)})
        evs = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 20").fetchall()
    summ = {k: sum(1 for h in hosts if h["state"] == k) for k in ("up", "down", "warn", "pending", "disabled")}
    summ["total"] = len(hosts)
    summ["all_ok"] = summ["down"] == 0 and summ["warn"] == 0
    summ["down_hosts"] = [h["name"] for h in hosts if h["state"] == "down"]
    summ["snmp_links_down"] = [f"{h['name']}:{i['name']}" for h in hosts if h["snmp"] for i in h["snmp"]["interfaces"]
                               if i["alerting"] and i["oper"] != "up"]
    return jsonify(site=s["site_name"], generated_at=iso(now, tz), timezone=s["timezone"], version=VERSION,
                   summary=summ, hosts=hosts, recent_events=[event_json(e, tz) for e in evs])


@app.route("/api/events")
@api_auth
def api_events():
    tz = tzinfo()
    since = parse_since(request.args.get("since"))
    since_id = int(request.args.get("since_id", 0) or 0)
    limit = max(1, min(500, int(request.args.get("limit", 100) or 100)))
    q, args = "ts > ? AND id > ?", [since, since_id]
    if request.args.get("source") in ("ping", "mail", "snmp"):
        q += " AND source=?"
        args.append(request.args["source"])
    if request.args.get("min_severity") in SEVERITY_RANK:
        allowed = [k for k, v in SEVERITY_RANK.items() if k != "none" and v >= SEVERITY_RANK[request.args["min_severity"]]]
        q += f" AND severity IN ({','.join('?' * len(allowed))})"
        args += allowed
    with db() as c:
        rows = c.execute(f"SELECT * FROM events WHERE {q} ORDER BY id ASC LIMIT ?", (*args, limit)).fetchall()
    evs = [event_json(e, tz) for e in rows]
    return jsonify(site=get_settings()["site_name"], count=len(evs), events=evs,
                   next_since_id=evs[-1]["id"] if evs else since_id)


@app.errorhandler(400)
@app.errorhandler(404)
def _api_errors(e):
    if request.path.startswith("/api/"):
        return jsonify(error=e.description if hasattr(e, "description") else str(e)), e.code
    return e


# ----------------------------------------------------------------------------- main
def main():
    global DB_PATH, DATA_DIR, SNAP_DIR
    ap = argparse.ArgumentParser(description="Wirewave Ping Monitor v" + VERSION)
    ap.add_argument("--host", default=os.environ.get("PINGMON_HOST", "127.0.0.1"), help="web bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PINGMON_PORT", 8080)), help="web port (default 8080)")
    ap.add_argument("--db", default=os.environ.get("PINGMON_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "pingmonitor.db")),
                    help="SQLite database file (snapshots are stored next to it)")
    ap.add_argument("--set-password", "--reset-password", dest="set_password", action="store_true",
                    help="set or reset the admin password, then exit")
    ap.add_argument("--password-stdin", action="store_true", help="with --set-password: read the password from stdin")
    ap.add_argument("--check-setup", action="store_true", help="exit 0 if an admin password is set, 3 if not")
    ap.add_argument("--show-token", action="store_true", help="print the API token and exit")
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("mail.log").setLevel(logging.ERROR)  # aiosmtpd is chatty (deprecation notes)

    DB_PATH = os.path.abspath(a.db)
    DATA_DIR = os.path.dirname(DB_PATH)
    SNAP_DIR = os.path.join(DATA_DIR, "snapshots")
    os.makedirs(SNAP_DIR, exist_ok=True)
    init_db()
    s = get_settings()

    if a.check_setup:
        sys.exit(0 if s["admin_hash"] else 3)
    if a.show_token:
        print(s["api_token"])
        return
    if a.set_password or not s["admin_hash"]:
        if not a.set_password and not sys.stdin.isatty():
            log.error("No admin password set. Run once in a terminal:  %s %s --set-password --db %s",
                      sys.executable, os.path.abspath(__file__), DB_PATH)
            sys.exit(2)
        set_settings(admin_hash=hash_password(prompt_new_password(a.password_stdin)))
        print("Admin password saved.")
        if a.set_password:
            return

    app.secret_key = get_settings()["secret_key"]
    get_pinger(s["ping_method"])
    stop = threading.Event()
    threading.Thread(target=monitor_loop, args=(stop,), daemon=True, name="monitor").start()
    RECEIVER.restart()
    SNMP.start()
    log.info("Wirewave Ping Monitor %s - site '%s' - web UI http://%s:%d", VERSION, s["site_name"], a.host, a.port)
    try:
        from waitress import serve
        serve(app, host=a.host, port=a.port, threads=4, ident="pingmonitor")
    except ImportError:
        app.run(host=a.host, port=a.port, threaded=True)
    finally:
        stop.set()
        RECEIVER.stop()


if __name__ == "__main__":
    main()
